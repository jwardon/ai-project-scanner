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
    names = [e.name for e in result.evidence]
    assert names[0] == "PROTO" and names[-1] == "STOP"
    assert "BINUNICODE" in names
    offsets = [e.offset for e in result.evidence]
    assert offsets == sorted(offsets) and offsets[0] == 0


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
    assert "REDUCE" in [e.name for e in result.evidence]
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
