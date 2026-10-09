"""Usage: python -m ai_project_scanner PATH"""

from __future__ import annotations

import sys

from .pickle_scanner import scan_pickle_file

_MAX_VALUE = 200


def _truncate(text: str) -> str:
    return text if len(text) <= _MAX_VALUE else text[:_MAX_VALUE] + "..."


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 1:
        print("usage: python -m ai_project_scanner PATH", file=sys.stderr)
        return 2
    result = scan_pickle_file(args[0])
    print(f"Target: {result.target}")
    for ev in result.evidence:
        line = f"{ev.attributes['offset']:>8}  {ev.attributes['opcode']}"
        if ev.value is not None:
            line += f"  {_truncate(repr(ev.value))}"
        print(line)
    for err in result.errors:
        print(f"error: {err}", file=sys.stderr)
    return 0 if result.ok else 1


if __name__ == "__main__":
    sys.exit(main())
