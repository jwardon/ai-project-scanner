# AI Project Scanner

[![Code Quality](https://github.com/jwardon/ai-project-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/jwardon/ai-project-scanner/actions/workflows/ci.yml)

AI Project Scanner is an open-source security scanner for AI/ML projects, including source code, dependencies, models, configuration, and provenance.

The project explores how security tooling can assess the components of an AI/ML project and provide useful evidence about risks in its software and model supply chains.

## Motivation

AI/ML projects introduce security-relevant components and trust relationships beyond traditional application code, including model artifacts, training and retrieval data, dependencies, and provenance.

AI Project Scanner applies security principles described in [AI Security 101](https://github.com/jwardon/ai-security-101), particularly around [AI supply-chain security](https://github.com/jwardon/ai-security-101/blob/main/5_attacks_ai_supply_chain.md) and [security controls for AI systems](https://github.com/jwardon/ai-security-101/blob/main/8_security_controls_for_ai_systems.md).

## Status

This project is in early development.

The initial implementation safely inspects Python pickle files without deserializing untrusted content. The MVP is expanding this into static analysis that can identify security-relevant behavior during deserialization while preserving evidence and explicitly reporting analysis limitations. These are development milestones, not the full project scope described below.

Functionality and interfaces should be considered unstable until the first release.

## Scope

The project is focused on security analysis of the contents of AI/ML projects, including:

- source code and Jupyter notebooks
- software dependencies
- model files and serialized artifacts
- configuration and metadata
- provenance and lineage information

The project favors a small number of well-supported analyses over superficial coverage. Scanned content is treated as untrusted, and analysis should distinguish what can be established from what cannot.

The project is not intended to be a general-purpose network or live AI infrastructure vulnerability scanner.

## Usage

Statically scan pickle files without deserializing them. The target may be a file or a directory, which is searched recursively for `.pkl` and `.pickle` files:

```text
pip install .
scan path/to/file.pkl
scan .
scan --help
```

The scanner also symbolically traces callable invocation (`REDUCE`) for a supported subset of pickle semantics, reporting the callable and statically resolvable arguments, and lists analysis limitations where behavior cannot be determined. Nothing is deserialized.

The target may be omitted. It is then resolved from, in order: `ai-project-scanner.toml` in the current directory, `[tool.ai-project-scanner]` in `pyproject.toml`, then `.`. The first source found is used on its own; the two are never merged. Relative configured paths are resolved against the directory containing the configuration file.

```toml
# ai-project-scanner.toml
[scan]
path = "./models"
```

```toml
# pyproject.toml
[tool.ai-project-scanner.scan]
path = "./models"
```

Invalid configuration is reported as a `configuration error` (exit code 2).

If no supported files are found, `No supported files found.` is reported.

## Design

Significant architectural decisions are documented in [`docs/adr`](docs/adr/). Project planning and the implementation roadmap are tracked in [GitHub Issues](https://github.com/jwardon/ai-project-scanner/issues).

## License

Licensed under the Apache License 2.0. See [LICENSE](LICENSE).
