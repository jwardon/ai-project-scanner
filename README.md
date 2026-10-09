# AI Project Scanner

[![CI](https://github.com/jwardon/ai-project-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/jwardon/ai-project-scanner/actions/workflows/ci.yml)

AI Project Scanner is an open-source security scanner for AI/ML projects, including source code, dependencies, models, configuration, and provenance.

The project explores how security tooling can assess the components of an AI/ML project and provide useful evidence about risks in its software and model supply chains.

## Status

This project is in early development.

The initial scope, architecture, and MVP are currently being defined. Functionality and interfaces should be considered unstable until the first release.

## Scope

The project is focused on security analysis of the contents of AI/ML projects, including areas such as:

- source code and Jupyter notebooks
- software dependencies
- model files and serialized artifacts
- configuration and metadata
- provenance and lineage information

The project is not intended to be a general-purpose network or live AI infrastructure vulnerability scanner.

## Usage

Inspect a pickle file's opcodes without deserializing it:

```
PYTHONPATH=src python -m ai_project_scanner path/to/file.pkl
```

## License

Licensed under the Apache License 2.0. See [LICENSE](LICENSE).
