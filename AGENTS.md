# AGENTS.md

## Project

AI Project Scanner is a security scanner for AI/ML projects, including source code, dependencies, models, configuration, and provenance.

The project favors a small number of well-supported analyses over superficial coverage.

## Engineering Guidelines

- Keep implementations focused on the requirements and acceptance criteria of the current issue.
- Prefer simple, maintainable designs over premature abstraction.
- Reuse existing project structures and conventions where practical.
- Avoid unrelated refactoring or feature expansion.
- Add dependencies only when they provide clear value and prefer the standard library when it is a reasonable fit.
- Keep analyzer-specific implementation details separate from generic scanner concepts where practical.

## Security

- Treat scanned files and their contents as untrusted input.
- Analysis must not execute untrusted content unless a future feature explicitly provides an approved isolated execution environment.
- Never deserialize an untrusted pickle during static analysis.
- Prefer evidence-based results over assumptions about intent.
- Do not describe an artifact as safe, clean, benign, or malicious unless the implemented analysis can establish that claim.
- Surface meaningful analysis limitations rather than silently treating unsupported behavior as safe.
- Preserve least privilege and avoid introducing unnecessary network, filesystem, subprocess, or credential access.

## Testing

- Add or update automated tests for behavior introduced or changed by the issue.
- Include relevant error and security-boundary cases, not only successful paths.
- Security tests should verify that prohibited behavior does not occur, not merely that expected output is produced.
- Keep tests deterministic and independent of external services unless the issue explicitly requires otherwise.

## Architecture and Scope

- Follow accepted ADRs in `docs/adr/`.
- Do not silently override an accepted architectural decision. If an issue appears to conflict with an ADR, surface the conflict for human review.
- Do not expand the scope of an issue merely to anticipate possible future requirements.
- Do not build generalized frameworks or extension systems until a concrete requirement justifies them.

## Pull Requests

- Keep each pull request scoped to its issue.
- Explain significant implementation choices and tradeoffs in the pull request description.
- Call out assumptions, known limitations, or unresolved questions.
- Include the tests necessary to demonstrate that the acceptance criteria are satisfied.
- Do not include unrelated cleanup or refactoring.
