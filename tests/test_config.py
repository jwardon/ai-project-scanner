import pickle

import pytest

from ai_project_scanner.__main__ import main
from ai_project_scanner.config import (
    ConfigError,
    ScannerConfig,
    load_config,
    resolve_scan_target,
)

DEDICATED = '[scan]\npath = "./models"\n'
PYPROJECT = '[tool.ai-project-scanner.scan]\npath = "./models"\n'


def test_both_sources_same_shape(tmp_path):
    a, b = tmp_path / "a", tmp_path / "b"
    a.mkdir()
    b.mkdir()
    (a / "ai-project-scanner.toml").write_text(DEDICATED)
    (b / "pyproject.toml").write_text(PYPROJECT)
    assert load_config(a) == ScannerConfig(scan_path=str(a / "models"))
    assert load_config(b) == ScannerConfig(scan_path=str(b / "models"))


def test_default_when_nothing_configured(tmp_path):
    assert resolve_scan_target(None, tmp_path) == "."


def test_pyproject_without_tool_section_uses_default(tmp_path):
    (tmp_path / "pyproject.toml").write_text("[project]\nname = 'x'\n")
    assert resolve_scan_target(None, tmp_path) == "."


def test_config_file_used(tmp_path):
    (tmp_path / "ai-project-scanner.toml").write_text(DEDICATED)
    assert resolve_scan_target(None, tmp_path) == str(tmp_path / "models")


def test_pyproject_used(tmp_path):
    (tmp_path / "pyproject.toml").write_text(PYPROJECT)
    assert resolve_scan_target(None, tmp_path) == str(tmp_path / "models")


def test_explicit_overrides_and_config_not_read(tmp_path):
    (tmp_path / "ai-project-scanner.toml").write_text("not = [valid")
    assert resolve_scan_target("x", tmp_path) == "x"


def test_config_file_precedes_pyproject_without_merge(tmp_path):
    (tmp_path / "ai-project-scanner.toml").write_text('[scan]\npath = "one"\n')
    (tmp_path / "pyproject.toml").write_text(
        '[tool.ai-project-scanner.scan]\npath = "two"\n'
    )
    assert resolve_scan_target(None, tmp_path) == str(tmp_path / "one")


def test_empty_config_file_does_not_fall_through(tmp_path):
    (tmp_path / "ai-project-scanner.toml").write_text("")
    (tmp_path / "pyproject.toml").write_text(PYPROJECT)
    assert resolve_scan_target(None, tmp_path) == "."


@pytest.mark.parametrize(
    "content",
    [
        "[scan",
        "[scan]\npath = 3\n",
        '[scan]\npath = ""\n',
        'scan = "x"\n',
        '[scan]\npath = "a"\nother = 1\n',
        "[other]\n",
    ],
)
def test_invalid_config_file_errors(tmp_path, content):
    (tmp_path / "ai-project-scanner.toml").write_text(content)
    (tmp_path / "pyproject.toml").write_text(PYPROJECT)
    with pytest.raises(ConfigError):
        resolve_scan_target(None, tmp_path)


def test_invalid_pyproject_errors(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        "[tool.ai-project-scanner.scan]\npath = 1\n"
    )
    with pytest.raises(ConfigError):
        load_config(tmp_path)
    (tmp_path / "pyproject.toml").write_text('[tool]\nai-project-scanner = "x"\n')
    with pytest.raises(ConfigError):
        load_config(tmp_path)


def test_cli_uses_configured_target_and_reports_errors(tmp_path, monkeypatch, capsys):
    (tmp_path / "models").mkdir()
    (tmp_path / "models" / "a.pkl").write_bytes(pickle.dumps(1))
    (tmp_path / "ai-project-scanner.toml").write_text(DEDICATED)
    monkeypatch.chdir(tmp_path)
    assert main([]) == 0
    assert "a.pkl" in capsys.readouterr().out
    (tmp_path / "ai-project-scanner.toml").write_text("[scan")
    assert main([]) == 2
    assert "configuration error" in capsys.readouterr().err
    assert main(["a", "b"]) == 2
