"""Static inspection of pickle instruction streams.

The target is only tokenized with ``pickletools.genops``; it is never
deserialized or executed.
"""

from __future__ import annotations

import io
import os
import pickletools

from .pickle_interpreter import PickleInterpreter
from .pickle_rules import PICKLE_CAPABILITY_RULES
from .results import Evidence, Finding, Invocation, ScanResult


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
            for analysis_result in interpreter.step(opcode.name, arg, pos):
                result.results.append(analysis_result)
                if isinstance(analysis_result, Invocation):
                    rule = PICKLE_CAPABILITY_RULES.get(analysis_result.callable)
                    if rule is not None:
                        evidence = Evidence(
                            description=(
                                f"Resolved invocation of {analysis_result.callable}"
                            ),
                            location=f"byte offset {analysis_result.offset}",
                            value=analysis_result.arguments,
                            attributes={
                                "callable": analysis_result.callable,
                                "arguments": analysis_result.arguments,
                                "opcode": analysis_result.operation,
                                "offset": analysis_result.offset,
                            },
                        )
                        result.results.append(
                            Finding(
                                rule_id=rule.rule_id,
                                artifact_path=result.target,
                                message=(
                                    f"Pickle invokes {analysis_result.callable}, "
                                    f"establishing {rule.capability} "
                                    "during deserialization."
                                ),
                                evidence=[evidence],
                            )
                        )
    except Exception as exc:  # malformed input must yield a controlled error
        result.errors.append(f"Malformed or truncated pickle: {exc}")
    return result
