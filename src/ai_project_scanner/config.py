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


def _read_toml(config_file: Path) -> dict[str, Any]:
    try:
        with config_file.open("rb") as config_stream:
            return tomllib.load(config_stream)
    except (OSError, tomllib.TOMLDecodeError, UnicodeDecodeError) as err:
        raise ConfigError(f"{config_file}: cannot read configuration: {err}") from err


def _parse_config_table(config_table: Any, config_file: Path) -> ScannerConfig:
    if not isinstance(config_table, dict):
        raise ConfigError(f"{config_file}: scanner configuration must be a table")
    unknown_config_keys = sorted(set(config_table) - {"scan"})
    if unknown_config_keys:
        raise ConfigError(
            f"{config_file}: unknown scanner setting(s): "
            f"{', '.join(unknown_config_keys)}"
        )
    scan_table = config_table.get("scan", {})
    if not isinstance(scan_table, dict):
        raise ConfigError(f"{config_file}: scan must be a table")
    unknown_scan_keys = sorted(set(scan_table) - {"path"})
    if unknown_scan_keys:
        raise ConfigError(
            f"{config_file}: unknown scan setting(s): {', '.join(unknown_scan_keys)}"
        )
    scan_path = scan_table.get("path")
    if scan_path is None:
        return ScannerConfig()
    if not isinstance(scan_path, str) or not scan_path.strip():
        raise ConfigError(f"{config_file}: scan.path must be a non-empty string")
    return ScannerConfig(scan_path=scan_path)


def load_config(directory: str | Path = ".") -> ScannerConfig:
    """Load configuration from ``ai-project-scanner.toml`` or ``pyproject.toml``.

    The dedicated config file, when present, is used exclusively; the two
    sources are never merged. Relative configured paths are resolved against
    ``directory``.
    """
    config_directory = Path(directory)
    config_file = config_directory / CONFIG_FILE_NAME
    pyproject_file = config_directory / PYPROJECT_FILE_NAME
    if config_file.is_file():
        config = _parse_config_table(_read_toml(config_file), config_file)
        config_source_file = config_file
    elif pyproject_file.is_file():
        tool_table = _read_toml(pyproject_file).get("tool", {})
        if not isinstance(tool_table, dict) or "ai-project-scanner" not in tool_table:
            return ScannerConfig()
        scanner_table = tool_table["ai-project-scanner"]
        config = _parse_config_table(scanner_table, pyproject_file)
        config_source_file = pyproject_file
    else:
        return ScannerConfig()
    if config.scan_path is None:
        return config
    return ScannerConfig(
        scan_path=str(config_source_file.parent / config.scan_path)
    )


def resolve_scan_target(explicit: str | None, directory: str | Path = ".") -> str:
    """Resolve the scan target: explicit, config file, pyproject file, then ``.``."""
    if explicit is not None:
        return explicit
    return load_config(directory).scan_path or DEFAULT_SCAN_PATH
