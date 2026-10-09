"""Discovery of supported files beneath a scan target."""

from __future__ import annotations

import os
from pathlib import Path

PICKLE_SUFFIXES = frozenset({".pkl", ".pickle"})


def is_supported(path: str | os.PathLike) -> bool:
    """Return True if the path has a supported file type (currently pickle)."""
    return Path(path).suffix.lower() in PICKLE_SUFFIXES


def discover_files(target: str | os.PathLike) -> list[Path]:
    """Return supported files for a file or directory target, sorted by path.

    Directories are searched recursively without following directory symlinks.
    """
    root = Path(target)
    if root.is_dir():
        found = [
            Path(dirpath) / name
            for dirpath, _dirs, names in os.walk(root)
            for name in names
            if is_supported(name)
        ]
        return sorted(found)
    return [root] if is_supported(root) else []
