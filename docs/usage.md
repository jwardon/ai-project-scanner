# Usage

## Installation

Python 3.12 or later is required. From a clone of this repository:

```text
pip install .
```

This installs the `scan` command.

## Scanning

```text
scan [path]
```

- **File:** `scan model.pkl` scans that single file.
- **Directory:** `scan models/` recursively scans supported files beneath the directory. `scan .` scans the current directory.

Currently supported files are pickle files (`.pkl` and `.pickle`). Scanned files are analyzed statically and are never loaded or executed.

If the target contains no supported files, the scan reports `No supported files found.`

## Default target

When `path` is omitted, the target is resolved from the first of these that applies:

1. `ai-project-scanner.toml` in the current directory
2. the `[tool.ai-project-scanner]` table in `pyproject.toml` in the current directory
3. the current directory (`.`)

The first source found is used on its own; the sources are never merged. If `ai-project-scanner.toml` exists, `pyproject.toml` is ignored. A relative configured path is resolved against the directory containing the configuration file. A path given on the command line always takes precedence.

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

Unknown settings or a non-string or empty `scan.path` are configuration errors.

## Help

```text
scan --help
```

## Results

For each scanned file the output reports:

- **Findings** (`finding:`): security-relevant behavior the scanner identified, with the artifact path and supporting evidence such as the location and value.
- **Limitations** (`limitation:`): behavior the scanner could not fully analyze. A limitation is not a finding; it means the result for that file is incomplete.
- **Scan errors** (`error:`, written to standard error): the file could not be read or is malformed, so it was not fully analyzed. Other files are still scanned.

Each file ends with a `Result:` line summarizing the outcome.

**No findings does not establish that a file is safe.** The scanner only reports what its supported analysis can identify. A file with no findings, and especially one with limitations, may still contain behavior the scanner did not detect.

## Exit statuses

| Status | Meaning |
| ------ | ------- |
| 0 | Every file was scanned (including when findings were reported), or no supported files were found. |
| 1 | At least one file could not be scanned because of a scan error. |
| 2 | Usage error, nonexistent target, or configuration error. |
