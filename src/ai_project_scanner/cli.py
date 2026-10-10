"""Command-line interface: ``scan [path]``."""

from __future__ import annotations

import argparse
import os
import sys

from .config import ConfigError, resolve_scan_target
from .discovery import discover_files
from .pickle_scanner import scan_pickle_file
from .results import Evidence, Finding, Invocation, ScanResult

_MAX_VALUE = 200

_DESCRIPTION = """\
Statically scan AI/ML project artifacts for security-relevant behavior.
Scanned files are never deserialized or executed. Currently supported:
pickle files (.pkl, .pickle)."""

_EPILOG = """\
If PATH is omitted, the target comes from ai-project-scanner.toml, then
[tool.ai-project-scanner] in pyproject.toml, then the current directory.

Exit status: 0 = every file was scanned, 1 = a scan error occurred,
2 = usage or configuration error.
A scan with no findings does not establish that a target is safe."""


def _truncate(text: str) -> str:
    return text if len(text) <= _MAX_VALUE else text[:_MAX_VALUE] + "..."


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="scan",
        description=_DESCRIPTION,
        epilog=_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "path",
        nargs="?",
        metavar="PATH",
        help="file or directory to scan (directories are searched recursively)",
    )
    return parser


def _print_finding(finding: Finding) -> None:
    print(f"finding: {finding.rule_id}: {finding.message}")
    print(f"  artifact: {finding.artifact_path}")
    for evidence in finding.evidence:
        line = f"  evidence: {evidence.description}"
        if evidence.location:
            line += f" ({evidence.location})"
        print(line)
        if evidence.value is not None:
            print(f"    value: {_truncate(repr(evidence.value))}")


def _report(result: ScanResult) -> None:
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
            shown = "<unresolved>" if arguments is None else repr(arguments)
            print(
                f"{analysis_result.offset:>8}  {analysis_result.operation} -> "
                f"{analysis_result.callable}{_truncate(shown)}"
            )
        elif isinstance(analysis_result, Finding):
            _print_finding(analysis_result)
        else:
            print(
                f"limitation: {analysis_result.operation}: "
                f"{analysis_result.description} "
                f"(byte offset {analysis_result.offset})"
            )
    for err in result.errors:
        print(f"error: {result.target}: {err}", file=sys.stderr)
    if result.errors:
        print("Result: scan failed; this file was not fully analyzed.")
    elif result.findings:
        print(f"Result: {len(result.findings)} finding(s) identified.")
    elif result.limitations:
        print(
            f"Result: no findings identified, but analysis was incomplete "
            f"({len(result.limitations)} limitation(s)); this result does not "
            "establish that the file is safe."
        )
    else:
        print(
            "Result: no security-relevant behavior identified by the supported "
            "analysis; this does not establish that the file is safe."
        )


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    try:
        args = parser.parse_args(sys.argv[1:] if argv is None else argv)
    except SystemExit as exit_request:
        return exit_request.code if isinstance(exit_request.code, int) else 2
    try:
        target = resolve_scan_target(args.path)
    except ConfigError as err:
        print(f"configuration error: {err}", file=sys.stderr)
        return 2
    if not os.path.exists(target):
        print(f"error: target does not exist: {target}", file=sys.stderr)
        return 2
    files = discover_files(target)
    if not files:
        print("No supported files found.")
        return 0
    all_ok = True
    for path in files:
        try:
            result = scan_pickle_file(path)
        except Exception as err:  # noqa: BLE001
            result = ScanResult(target=os.fspath(path))
            result.errors.append(f"Unexpected scan failure: {err!r}")
        all_ok = all_ok and result.ok
        _report(result)
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
