"""Usage: python -m ai_project_scanner PATH"""

from __future__ import annotations

import sys

from .discovery import discover_files
from .pickle_scanner import scan_pickle_file

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
        for ev in result.evidence:
            line = f"{ev.attributes['offset']:>8}  {ev.attributes['opcode']}"
            if ev.value is not None:
                line += f"  {_truncate(repr(ev.value))}"
            print(line)
        for inv in result.invocations:
            args = "<unresolved>" if inv.arguments is None else repr(inv.arguments)
            print(
                f"{inv.offset:>8}  {inv.operation} -> "
                f"{inv.callable}{_truncate(args)}"
            )
        for lim in result.limitations:
            print(f"limitation: {lim}")
        for err in result.errors:
            print(f"error: {result.target}: {err}", file=sys.stderr)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
