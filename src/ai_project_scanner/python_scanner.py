"""Static inspection of Python source using the standard-library AST."""

from __future__ import annotations

import ast
import os
import tokenize

from .results import Evidence, ScanResult


def scan_python_file(path: str | os.PathLike) -> ScanResult:
    """Parse Python source and record call-expression locations without execution."""
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
        tree = ast.parse(source, filename=os.fspath(path))
    except SyntaxError as exc:
        result.errors.append(f"Cannot parse Python source: {exc}")
        return result

    calls = sorted(
        (node for node in ast.walk(tree) if isinstance(node, ast.Call)),
        key=lambda node: (node.lineno, node.col_offset),
    )
    for call in calls:
        result.results.append(
            Evidence(
                description="Python call expression",
                location=f"line {call.lineno}, column {call.col_offset}",
                attributes={
                    "node": "Call",
                    "line": call.lineno,
                    "column": call.col_offset,
                },
            )
        )
    return result
