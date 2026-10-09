"""Static inspection of pickle instruction streams.

The target is only tokenized with ``pickletools.genops``; it is never
deserialized or executed.
"""

from __future__ import annotations

import io
import os
import pickletools

from .pickle_interpreter import PickleInterpreter
from .results import Evidence, ScanResult


def scan_pickle_file(path: str | os.PathLike) -> ScanResult:
    """Inspect the opcodes of a pickle file without deserializing it."""
    result = ScanResult(target=os.fspath(path))
    try:
        with open(path, "rb") as f:
            data = f.read()
    except OSError as exc:
        result.errors.append(f"Cannot read file: {exc}")
        return result

    interpreter = PickleInterpreter()
    try:
        for opcode, arg, pos in pickletools.genops(io.BytesIO(data)):
            result.results.append(
                Evidence(
                    description=f"Pickle opcode {opcode.name}",
                    location=f"byte offset {pos}",
                    value=arg,
                    attributes={"opcode": opcode.name, "offset": pos},
                )
            )
            result.results.extend(interpreter.step(opcode.name, arg, pos))
    except Exception as exc:  # malformed input must yield a controlled error
        result.errors.append(f"Malformed or truncated pickle: {exc}")
    return result
