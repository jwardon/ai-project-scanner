import pickle
import subprocess
import sys
from pathlib import Path

from ai_project_scanner import scan_pickle_file
from ai_project_scanner.__main__ import main

SRC = str(Path(__file__).resolve().parents[1] / "src")


def test_valid_pickle_reports_ordered_opcodes_with_offsets(tmp_path):
    p = tmp_path / "ok.pkl"
    p.write_bytes(pickle.dumps([1, "a"], protocol=2))
    result = scan_pickle_file(p)
    assert result.ok
    names = [e.attributes["opcode"] for e in result.evidence]
    assert names[0] == "PROTO" and names[-1] == "STOP"
    assert "BINUNICODE" in names
    offsets = [e.attributes["offset"] for e in result.evidence]
    assert offsets == sorted(offsets) and offsets[0] == 0
    first = result.evidence[0]
    assert first.description == "Pickle opcode PROTO"
    assert first.location == "byte offset 0"
    assert first.value == 2


def test_all_protocols(tmp_path):
    for proto in range(pickle.HIGHEST_PROTOCOL + 1):
        p = tmp_path / f"p{proto}.pkl"
        p.write_bytes(pickle.dumps({"k": [1, 2]}, protocol=proto))
        assert scan_pickle_file(p).ok


def test_truncated_pickle_is_controlled_error(tmp_path):
    p = tmp_path / "t.pkl"
    p.write_bytes(pickle.dumps(list(range(50)), protocol=2)[:-5])
    result = scan_pickle_file(p)
    assert not result.ok and result.errors


def test_malformed_and_empty(tmp_path):
    for i, data in enumerate([b"", b"\xff\xff garbage", b"\x80\x02X\xff\xff\xff\x7f"]):
        p = tmp_path / f"m{i}.pkl"
        p.write_bytes(data)
        assert not scan_pickle_file(p).ok


def test_missing_file(tmp_path):
    assert not scan_pickle_file(tmp_path / "nope.pkl").ok


class _Payload:
    def __reduce__(self):
        import os
        return (os.system, ("touch " + str(MARKER),))


MARKER = None


def test_payload_not_executed(tmp_path):
    global MARKER
    MARKER = tmp_path / "pwned"
    p = tmp_path / "evil.pkl"
    p.write_bytes(pickle.dumps(_Payload()))
    result = scan_pickle_file(p)
    assert result.ok
    assert "REDUCE" in [e.attributes["opcode"] for e in result.evidence]
    assert not MARKER.exists()


def test_scan_does_not_call_pickle_loaders(tmp_path, monkeypatch):
    p = tmp_path / "a.pkl"
    p.write_bytes(pickle.dumps([1]))

    def boom(*a, **k):
        raise AssertionError("deserialization attempted")

    for name in ("load", "loads", "Unpickler"):
        monkeypatch.setattr(pickle, name, boom)
    assert scan_pickle_file(p).ok


def test_cli(tmp_path, capsys):
    p = tmp_path / "a.pkl"
    p.write_bytes(pickle.dumps([1]))
    assert main([str(p)]) == 0
    assert "STOP" in capsys.readouterr().out
    p.write_bytes(b"\x80\x04")
    assert main([str(p)]) == 1
    assert "error" in capsys.readouterr().err


def test_module_invocation(tmp_path):
    p = tmp_path / "a.pkl"
    p.write_bytes(b"\x80\x04N.")
    r = subprocess.run(
        [sys.executable, "-m", "ai_project_scanner", str(p)],
        capture_output=True, text=True, env={"PYTHONPATH": SRC},
    )
    assert r.returncode == 0 and "NONE" in r.stdout and "Traceback" not in r.stderr


# --- symbolic invocation tracing ---------------------------------------

def _scan(tmp_path, data):
    p = tmp_path / "x.pkl"
    p.write_bytes(data)
    return scan_pickle_file(p)


def test_global_reduce_traced_with_arguments(tmp_path):
    r = _scan(tmp_path, b"cbuiltins\neval\n(S'1+1'\ntR.")
    assert r.ok and not r.limitations
    [inv] = r.invocations
    assert inv.callable == "builtins.eval" and inv.arguments == ("1+1",)
    assert inv.operation == "REDUCE"


def test_stack_global_reduce_traced(tmp_path):
    data = (b"\x80\x04\x8c\x08builtins\x94\x8c\x04eval\x94\x93\x94"
            b"\x8c\x031+1\x94\x85\x94R\x94.")
    r = _scan(tmp_path, data)
    [inv] = r.invocations
    assert inv.callable == "builtins.eval" and inv.arguments == ("1+1",)


def test_real_pickle_of_os_system_traced(tmp_path, monkeypatch):
    global MARKER
    MARKER = tmp_path / "pwned"
    for proto in range(pickle.HIGHEST_PROTOCOL + 1):
        r = _scan(tmp_path, pickle.dumps(_Payload(), protocol=proto))
        [inv] = r.invocations
        assert inv.callable in ("posix.system", "nt.system", "os.system")
        assert inv.arguments == ("touch " + str(MARKER),)
    assert not MARKER.exists()


def test_memoized_callable_traced(tmp_path):
    # callable stored in memo, popped, retrieved, and then invoked
    r = _scan(tmp_path, b"cos\nsystem\np0\n0(S'id'\ntg0\n.")
    assert not r.invocations  # g0 pushed after tuple: no REDUCE yet
    r = _scan(tmp_path, b"cos\nsystem\np0\n0g0\n(S'id'\ntR.")
    [inv] = r.invocations
    assert inv.callable == "os.system" and inv.arguments == ("id",)


def test_memoized_callable_binary_and_memoize(tmp_path):
    data = (b"\x80\x04\x8c\x02os\x94\x8c\x06system\x94\x93\x94" b"0h\x02"
            b"\x8c\x02id\x94\x85\x94R.")
    r = _scan(tmp_path, data)
    [inv] = r.invocations
    assert inv.callable == "os.system" and inv.arguments == ("id",)


def test_stack_manipulation_dup_pop_mark(tmp_path):
    # junk under a mark is discarded; DUP duplicates the callable
    data = b"(I1\nI2\n1cos\nsystem\n2(S'id'\ntR."
    r = _scan(tmp_path, data)
    assert [i.callable for i in r.invocations] == ["os.system"]
    assert r.invocations[0].arguments == ("id",)
    r = _scan(tmp_path, b"cos\nsystem\n2(S'a'\ntR0(S'b'\ntR.")
    assert [i.arguments for i in r.invocations] == [("a",), ("b",)]


def test_arguments_through_containers_and_memo(tmp_path):
    data = (b"cbuiltins\ngetattr\n(]p0\nS'x'\na(dS'k'\nI5\nsg0\nS'y'\ntR.")
    r = _scan(tmp_path, data)
    [inv] = r.invocations
    assert inv.callable == "builtins.getattr"
    lst, dct, again, s = inv.arguments
    assert lst.items == ["x"] and dct.items == [("k", 5)]
    assert again is lst and s == "y"


def test_nested_invocation_both_traced(tmp_path):
    data = (b"cbuiltins\neval\n(cbuiltins\nstr\n(S'a'\ntRtR.")
    r = _scan(tmp_path, data)
    assert [i.callable for i in r.invocations] == ["builtins.str", "builtins.eval"]


def test_global_without_reduce_not_an_invocation(tmp_path):
    r = _scan(tmp_path, b"cos\nsystem\n.")
    assert r.ok and not r.invocations


def test_unresolvable_callable_is_limitation(tmp_path):
    r = _scan(tmp_path, b"NS'system'\n\x93(S'id'\ntR.")
    assert not r.invocations and r.limitations
    r = _scan(tmp_path, b"N(S'id'\ntR.")
    assert not r.invocations and r.limitations


def test_unsupported_opcode_halts_with_limitation(tmp_path):
    r = _scan(tmp_path, b"cos\nsystem\n(S'id'\ntios\nsystem\n.")
    assert r.limitations and not r.invocations


def test_stack_underflow_and_missing_memo_are_limitations(tmp_path):
    assert _scan(tmp_path, b"R.").limitations
    r = _scan(tmp_path, b"g5\n.")
    assert r.limitations


def test_cli_prints_invocation(tmp_path, capsys):
    p = tmp_path / "a.pkl"
    p.write_bytes(b"cbuiltins\neval\n(S'1+1'\ntR.")
    assert main([str(p)]) == 0
    assert "builtins.eval('1+1',)" in capsys.readouterr().out


def test_build_and_newobj_record_limitations(tmp_path):
    r = _scan(tmp_path, b"cos\nsystem\n)\x81.")
    assert any("NEWOBJ" in lim.description for lim in r.limitations)
    r = _scan(tmp_path, b"cos\nsystem\n)\x81}b.")
    assert any("BUILD" in lim.description for lim in r.limitations)


def test_events_preserve_ordering(tmp_path):
    r = _scan(tmp_path, b"cos\nsystem\n(S'id'\ntRN\x81.")
    kinds = [type(e).__name__ for e in r.events if type(e).__name__ != "Evidence"]
    assert kinds == ["Invocation", "Limitation"]
    pos = [i for i, e in enumerate(r.events) if type(e).__name__ == "Invocation"][0]
    assert r.events[pos - 1].attributes["opcode"] == "REDUCE"
