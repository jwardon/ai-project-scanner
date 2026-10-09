import pickle

from ai_project_scanner.__main__ import main
from ai_project_scanner.discovery import discover_files


def _pkl(path, obj=1):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(pickle.dumps(obj))
    return path


def test_single_file(tmp_path, capsys):
    p = _pkl(tmp_path / "a.pkl")
    assert discover_files(p) == [p]
    assert main([str(p)]) == 0
    assert f"Target: {p}" in capsys.readouterr().out


def test_directory_recursive_nested_and_multiple(tmp_path, capsys):
    a = _pkl(tmp_path / "a.pkl")
    b = _pkl(tmp_path / "x" / "y" / "b.pickle")
    c = _pkl(tmp_path / "x" / "c.PKL")
    (tmp_path / "x" / "note.txt").write_text("hi")
    assert discover_files(tmp_path) == sorted([a, b, c])
    assert main([str(tmp_path)]) == 0
    out = capsys.readouterr().out
    for p in (a, b, c):
        assert f"Target: {p}" in out


def test_dot_target(tmp_path, monkeypatch, capsys):
    _pkl(tmp_path / "sub" / "a.pkl")
    monkeypatch.chdir(tmp_path)
    assert main(["."]) == 0
    assert "a.pkl" in capsys.readouterr().out


def test_no_supported_files(tmp_path, capsys):
    (tmp_path / "a.txt").write_text("x")
    assert main([str(tmp_path)]) == 0
    assert capsys.readouterr().out.strip() == "No supported files found."
    assert main([str(tmp_path / "a.txt")]) == 0
    assert capsys.readouterr().out.strip() == "No supported files found."


def test_bad_file_in_directory_does_not_stop_others(tmp_path, capsys):
    (tmp_path / "bad.pkl").write_bytes(b"\x80\x04")
    _pkl(tmp_path / "good.pkl")
    assert main([str(tmp_path)]) == 1
    cap = capsys.readouterr()
    assert "good.pkl" in cap.out and "bad.pkl" in cap.err


def test_directory_symlink_not_followed(tmp_path):
    outside = tmp_path / "outside"
    _pkl(outside / "o.pkl")
    scan = tmp_path / "scan"
    scan.mkdir()
    (scan / "link").symlink_to(outside, target_is_directory=True)
    assert discover_files(scan) == []
