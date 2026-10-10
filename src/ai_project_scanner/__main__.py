"""Usage: python -m ai_project_scanner PATH"""

from __future__ import annotations

import sys

from .discovery import discover_files
from .pickle_scanner import scan_pickle_file
from .results import Evidence, Finding, Invocation

_MAX_VALUE = 200


def _truncate(text: str) -> str:
    return text if len(text) <= _MAX_VALUE else text[:_MAX_VALUE] + "..."


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 1:
        print("usage: python -m ai_project_scanner PATH", file=sys.stderr)
        return 2
    files = discover_files(args[0])
    if not files:
        print("No supported files found.")
        return 0
    ok = True
    for path in files:
        result = scan_pickle_file(path)
        ok = ok and result.ok
        print(f"Target: {result.target}")
        for analysis_result in result.results:
            if isinstance(analysis_result, Evidence):
                offset = analysis_result.attributes["offset"]
                opcode = analysis_result.attributes["opcode"]
                line = f"{offset:>8}  {opcode}"
                if analysis_result.value is not None:
                    line += f"  {_truncate(repr(analysis_result.value))}"
                print(line)
            elif isinstance(analysis_result, Invocation):
                arguments = analysis_result.arguments
                args = "<unresolved>" if arguments is None else repr(arguments)
                print(
                    f"{analysis_result.offset:>8}  {analysis_result.operation} -> "
                    f"{analysis_result.callable}{_truncate(args)}"
                )
            elif isinstance(analysis_result, Finding):
                print(f"finding: {analysis_result.rule_id}: {analysis_result.message}")
            else:
                print(
                    f"limitation: {analysis_result.operation}: "
                    f"{analysis_result.description} "
                    f"(byte offset {analysis_result.offset})"
                )
        if result.limitations:
            print(
                f"analysis incomplete: {len(result.limitations)} limitation(s); "
                "this result does not establish that the file is safe"
            )
        for err in result.errors:
            print(f"error: {result.target}: {err}", file=sys.stderr)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
