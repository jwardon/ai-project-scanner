from ai_project_scanner.python_scanner import scan_python_file


def test_scan_python_file_parses_valid_python(tmp_path):
    path = tmp_path / "source.py"
    path.write_text("value = 1\nprint(value)\n")

    result = scan_python_file(path)

    assert result.ok
    assert result.results == []
    assert result.errors == []


def test_invalid_python_is_an_analysis_error(tmp_path):
    path = tmp_path / "invalid.py"
    path.write_text("def unfinished(\n")

    result = scan_python_file(path)

    assert not result.ok
    assert not result.findings
    assert result.errors[0].startswith("Cannot parse Python source:")


def test_unreadable_python_file_is_an_analysis_error(tmp_path):
    result = scan_python_file(tmp_path / "missing.py")

    assert not result.ok
    assert result.errors[0].startswith("Cannot read file:")


def test_unknown_source_encoding_is_an_analysis_error(tmp_path):
    path = tmp_path / "invalid_encoding.py"
    path.write_text("# coding: unknown-encoding\nvalue = 1\n")

    result = scan_python_file(path)

    assert not result.ok
    assert result.errors[0].startswith("Cannot parse Python source:")


def test_scan_python_file_does_not_execute_source(tmp_path):
    marker = tmp_path / "executed"
    path = tmp_path / "source.py"
    path.write_text(f"open({str(marker)!r}, 'w')\n")

    result = scan_python_file(path)

    assert result.ok
    assert result.results == []
    assert not marker.exists()
