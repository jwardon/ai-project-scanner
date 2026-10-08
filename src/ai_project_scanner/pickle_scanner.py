"""Static inspection of pickle instruction streams.

The target is only tokenized with ``pickletools.genops``; it is never
deserialized or executed.
"""

from __future__ import annotations

import io
import os
import pickletools

from .results import Evidence, ScanResult

_MAX_DETAIL = 200


def _format_arg(arg: object) -> str | None:
    if arg is None:
        return None
    text = repr(arg)
    if len(text) > _MAX_DETAIL:
        text = text[:_MAX_DETAIL] + "..."
    return text


def scan_pickle_file(path: str | os.PathLike) -> ScanResult:
    """Inspect the opcodes of a pickle file without deserializing it."""
    result = ScanResult(target=os.fspath(path))
    try:
        with open(path, "rb") as f:
            data = f.read()
    except OSError as exc:
        result.errors.append(f"Cannot read file: {exc}")
        return result

    try:
        for opcode, arg, pos in pickletools.genops(io.BytesIO(data)):
            result.evidence.append(
                Evidence("pickle-opcode", opcode.name, pos, _format_arg(arg))
            )
    except Exception as exc:  # malformed input must yield a controlled error
        result.errors.append(f"Malformed or truncated pickle: {exc}")
    return result
