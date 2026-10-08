# Architecture Decision Records

This directory contains Architecture Decision Records (ADRs) for AI Project Scanner.

ADRs document significant technical decisions whose context and reasoning are useful to preserve over time. They complement the project charter, which records the project's initial direction, and the README and other documentation, which describe the project's current state.

## When to Write an ADR

Use an ADR when a decision:

- materially affects the architecture, security model, or long-term maintainability of the project;
- involves meaningful tradeoffs or alternatives;
- establishes a constraint that future development should understand; or
- would otherwise leave a future contributor asking why the project works this way.

Routine implementation choices do not require ADRs.

## Format

ADRs use the following sections:

- **Status**
- **Context**
- **Decision**
- **Alternatives Considered**
- **Consequences**

Use `template.md` as the starting point for new records.

## Naming

ADRs are numbered sequentially using four digits followed by a short descriptive name:

`NNNN-short-decision-name.md`

For example:

`0001-example-decision.md`

Numbers are never reused, even if an ADR is later superseded.

## Status

An ADR may have one of the following statuses:

- **Proposed** — Under consideration.
- **Accepted** — The decision has been adopted.
- **Superseded** — Replaced by a later ADR.

Accepted ADRs are not rewritten when the architecture changes. A new ADR should document the new decision and identify the ADR it supersedes.