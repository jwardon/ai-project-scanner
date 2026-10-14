# 0002: Use Bounded Python AST Analysis for AI/ML-Specific Source Analysis

## Status

Accepted

## Context

AI Project Scanner needs to analyze Python source files for security-relevant behavior in AI/ML projects.

General-purpose Python SAST is already provided by established tools. Reimplementing broad source-code security analysis would expand the scanner's scope without substantially advancing its AI/ML-specific security goals.

A technical spike evaluated three approaches:

- Python's standard-library `ast` module.
- Bandit as an established Python SAST tool.
- Semgrep CE as a general-purpose static-analysis engine with custom rules.

Bandit demonstrated useful conventional Python security coverage and structured findings suitable for later integration.

Semgrep CE demonstrated strong structural matching. A small custom rule recognized multiple forms of pickle deserialization, including module aliases and directly imported functions. However, the evaluated OSS JSON output did not expose the matched metavariables needed to directly establish artifact relationships. Additional scanner-owned analysis would still be required to resolve those relationships.

A prototype using Python's `ast` module safely parsed source without executing it and identified pickle deserialization through common import forms. A small amount of bounded value resolution was also sufficient to resolve artifact paths represented as string literals, variables, and simple string expressions. More complex cases, such as values returned through function calls, remained unresolved.

This distinction is important to the scanner's purpose. General-purpose SAST can identify that potentially unsafe deserialization occurs. AI Project Scanner may additionally need to establish relationships such as a particular source component loading a particular model artifact so that later cross-component analysis can correlate source behavior with analysis of that artifact.

The project should preserve the option to integrate with existing general-purpose security tooling rather than attempting to replace it.

## Decision

AI Project Scanner will use Python's standard-library AST as the foundation for its AI/ML-specific Python source analysis.

Source analysis will use bounded static interpretation. It will model only the Python semantics necessary to establish supported security-relevant behavior, evidence, and relationships.

Initial analysis may include:

- Recognizing security-relevant calls through supported import and alias forms.
- Preserving source locations as evidence.
- Resolving simple values and artifact references when they can be established through bounded local static analysis.
- Reporting established source behavior even when an associated artifact reference cannot be resolved.
- Reporting meaningful analysis limitations when unsupported semantics prevent the scanner from establishing a supported security-relevant conclusion.

The source analyzer will not attempt to become a general-purpose Python SAST engine.

General-purpose SAST remains a separate concern. AI Project Scanner may later integrate results from tools such as user-configured SAST scanners, but those tools are not foundational dependencies of Python source analysis.

External security-tool integration should favor composition with existing tooling rather than requiring users to replace established security workflows.

As with pickle analysis, failure to identify security-relevant behavior does not establish that source code is safe.

## Alternatives Considered

### Use Bandit as the Python source-analysis foundation

Bandit provides mature Python security checks, structured output, source locations, and commercially permissive licensing.

It was not selected as the foundation because the scanner's differentiated source-analysis requirements include AI/ML-specific semantics and relationships that general-purpose SAST does not necessarily represent. Making Bandit foundational would also couple AI Project Scanner's source-analysis architecture to an external SAST framework.

Bandit remains a candidate for optional general-purpose SAST integration.

### Use Semgrep CE with scanner-owned rules

Semgrep CE provides powerful structural matching, import-aware analysis, custom rules, and structured findings.

The spike demonstrated that Semgrep could recognize supported pickle-loading patterns across several import forms with very little rule configuration.

It was not selected as the foundation because AI Project Scanner would still require scanner-owned semantic processing for important AI/ML-specific relationships such as resolving referenced artifacts. This would introduce a substantial external dependency while retaining a separate scanner-owned analysis layer.

Semgrep engine and rule licensing also require care when considering redistribution and future commercial or hosted use. AI Project Scanner should not make its core source-analysis capability dependent on externally maintained rule content whose licensing may constrain those uses.

Semgrep remains a possible external integration using user-provided or otherwise appropriately licensed configuration.

### Implement comprehensive Python program analysis

A more complete symbolic interpreter, data-flow engine, or other general-purpose Python analysis framework could provide deeper resolution.

This was rejected because it would substantially increase complexity and duplicate mature static-analysis capabilities. The scanner should expand its interpretation only when doing so materially improves supported AI/ML-specific security analysis.

## Consequences

AI Project Scanner retains direct control over the semantics, evidence, limitations, and relationships produced by its differentiated Python analysis.

The initial implementation can remain small and dependency-free while still supporting useful AI/ML-specific analysis.

Some source relationships will remain unresolved when they require semantics outside the analyzer's supported bounds. The scanner must represent that uncertainty rather than guessing or silently treating unresolved behavior as safe.

As source analysis grows, there is a risk of gradually recreating a general-purpose static-analysis engine. New interpretation capabilities should therefore be added only when they materially improve AI/ML-specific security analysis.

General-purpose SAST coverage will not initially be provided by the Python source analyzer. Users may continue using their existing SAST tooling independently, with optional integration left for later work.

This architecture supports future cross-component analysis: source analysis can establish relationships to artifacts when possible, artifact analyzers can independently analyze those artifacts, and later correlation can combine the results without duplicating artifact scanning.
