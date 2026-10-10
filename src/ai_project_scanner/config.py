"""Scanner configuration loading and scan target resolution."""

from __future__ import annotations

import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

CONFIG_FILE_NAME = "ai-project-scanner.toml"
PYPROJECT_FILE_NAME = "pyproject.toml"
DEFAULT_SCAN_PATH = "."


class ConfigError(Exception):
    """Raised when relevant scanner configuration is invalid."""


@dataclass(frozen=True)
class ScannerConfig:
    scan_path: str | None = None


def _read_toml(file: Path) -> dict[str, Any]:
    try:
        with file.open("rb") as f:
            return tomllib.load(f)
    except (OSError, tomllib.TOMLDecodeError, UnicodeDecodeError) as err:
        raise ConfigError(f"{file}: cannot read configuration: {err}") from err


def _parse(table: Any, file: Path, location: str) -> ScannerConfig:
    if not isinstance(table, dict):
        raise ConfigError(f"{file}: {location} must be a table")
    unknown = sorted(set(table) - {"scan"})
    if unknown:
        raise ConfigError(
            f"{file}: unknown setting(s) in {location}: {', '.join(unknown)}"
        )
    scan = table.get("scan", {})
    if not isinstance(scan, dict):
        raise ConfigError(f"{file}: {location}.scan must be a table")
    unknown = sorted(set(scan) - {"path"})
    if unknown:
        raise ConfigError(
            f"{file}: unknown setting(s) in {location}.scan: {', '.join(unknown)}"
        )
    path = scan.get("path")
    if path is None:
        return ScannerConfig()
    if not isinstance(path, str) or not path.strip():
        raise ConfigError(f"{file}: {location}.scan.path must be a non-empty string")
    return ScannerConfig(scan_path=path)


def load_config(directory: str | Path = ".") -> ScannerConfig:
    """Load configuration from ``ai-project-scanner.toml`` or ``pyproject.toml``.

    The dedicated config file, when present, is used exclusively; the two
    sources are never merged. Relative configured paths are resolved against
    ``directory``.
    """
    base = Path(directory)
    config_file = base / CONFIG_FILE_NAME
    pyproject_file = base / PYPROJECT_FILE_NAME
    if config_file.is_file():
        config = _parse(_read_toml(config_file), config_file, "the file")
        source = config_file
    elif pyproject_file.is_file():
        tool = _read_toml(pyproject_file).get("tool", {})
        if not isinstance(tool, dict) or "ai-project-scanner" not in tool:
            return ScannerConfig()
        table = tool["ai-project-scanner"]
        config = _parse(table, pyproject_file, "[tool.ai-project-scanner]")
        source = pyproject_file
    else:
        return ScannerConfig()
    if config.scan_path is None:
        return config
    return ScannerConfig(scan_path=str(source.parent / config.scan_path))


def resolve_scan_target(explicit: str | None, directory: str | Path = ".") -> str:
    """Resolve the scan target: explicit, config file, pyproject file, then ``.``."""
    if explicit is not None:
        return explicit
    return load_config(directory).scan_path or DEFAULT_SCAN_PATH
