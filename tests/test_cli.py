import pickle
import subprocess
import sys

from ai_project_scanner.cli import main


class _Evil:
    def __reduce__(self):
        return (eval, ("1+1",))


def test_help(capsys):
    assert main(["--help"]) == 0
    out = capsys.readouterr().out
    assert "usage: scan" in out and "PATH" in out and "safe" in out


def test_clean_result_is_qualified(tmp_path, capsys):
    (tmp_path / "a.pkl").write_bytes(pickle.dumps({"a": 1}))
    assert main([str(tmp_path)]) == 0
    out = capsys.readouterr().out
    assert "does not establish that the file is safe" in out
    assert "finding:" not in out


def test_finding_shows_evidence(tmp_path, capsys):
    p = tmp_path / "evil.pkl"
    p.write_bytes(pickle.dumps(_Evil()))
    assert main([str(p)]) == 0
    out = capsys.readouterr().out
    assert "finding:" in out and f"artifact: {p}" in out
    assert "evidence:" in out and "byte offset" in out


def test_limitation_distinct_from_finding(tmp_path, capsys):
    (tmp_path / "a.pkl").write_bytes(b"Pabc\n.")
    assert main([str(tmp_path)]) == 0
    out = capsys.readouterr().out
    assert "limitation: PERSID" in out
    assert "finding:" not in out
    assert "analysis was incomplete" in out


def test_malformed_input_no_traceback(tmp_path, capsys):
    (tmp_path / "bad.pkl").write_bytes(b"\x80\x04")
    assert main([str(tmp_path)]) == 1
    cap = capsys.readouterr()
    assert "error:" in cap.err and "Traceback" not in cap.err


def test_missing_target(tmp_path, capsys):
    assert main([str(tmp_path / "nope")]) == 2
    assert "does not exist" in capsys.readouterr().err


def test_no_supported_files(tmp_path, capsys):
    assert main([str(tmp_path)]) == 0
    assert capsys.readouterr().out.strip() == "No supported files found."


def test_bad_config_no_traceback(tmp_path, monkeypatch, capsys):
    (tmp_path / "ai-project-scanner.toml").write_text("[scan\n")
    monkeypatch.chdir(tmp_path)
    assert main([]) == 2
    assert "configuration error" in capsys.readouterr().err


def test_module_entry_point(tmp_path):
    (tmp_path / "a.pkl").write_bytes(pickle.dumps(1))
    r = subprocess.run(
        [sys.executable, "-m", "ai_project_scanner", str(tmp_path)],
        capture_output=True,
        text=True,
        check=False,
        env={"PYTHONPATH": "src", "PATH": ""},
    )
    assert r.returncode == 0 and "Target:" in r.stdout
