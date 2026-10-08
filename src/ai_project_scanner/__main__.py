"""Usage: python -m ai_project_scanner PATH"""

from __future__ import annotations

import sys

from .pickle_scanner import scan_pickle_file


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 1:
        print("usage: python -m ai_project_scanner PATH", file=sys.stderr)
        return 2
    result = scan_pickle_file(args[0])
    print(f"Target: {result.target}")
    for ev in result.evidence:
        line = f"{ev.offset:>8}  {ev.name}"
        if ev.detail is not None:
            line += f"  {ev.detail}"
        print(line)
    for err in result.errors:
        print(f"error: {err}", file=sys.stderr)
    return 0 if result.ok else 1


if __name__ == "__main__":
    sys.exit(main())
