"""Static inspection of Python source using the standard-library AST."""

from __future__ import annotations

import ast
import os
import tokenize

from .results import ScanResult


def scan_python_file(path: str | os.PathLike) -> ScanResult:
    """Parse Python source without executing it."""
    result = ScanResult(target=os.fspath(path))
    try:
        with tokenize.open(path) as source_file:
            source = source_file.read()
    except OSError as exc:
        result.errors.append(f"Cannot read file: {exc}")
        return result
    except (SyntaxError, UnicodeDecodeError) as exc:
        result.errors.append(f"Cannot parse Python source: {exc}")
        return result

    try:
        ast.parse(source, filename=os.fspath(path))
    except SyntaxError as exc:
        result.errors.append(f"Cannot parse Python source: {exc}")
    return result
