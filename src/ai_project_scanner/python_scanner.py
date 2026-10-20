"""Static inspection of Python source using the standard-library AST."""

from __future__ import annotations

import ast
import os
import tokenize

from .results import Evidence, Finding, ScanResult

_LOCAL_DESERIALIZERS = {"pickle.load", "pickle.loads", "joblib.load"}
_REMOTE_ACQUISITION_APIS = {
    "datasets.load_dataset": "external dataset acquisition",
    "huggingface_hub.hf_hub_download": "remote artifact acquisition",
    "huggingface_hub.snapshot_download": "remote artifact acquisition",
    "langchain.hub.pull": "external prompt acquisition",
}
_TRANSFORMER_AUTO_CLASSES = {
    "AutoConfig",
    "AutoFeatureExtractor",
    "AutoImageProcessor",
    "AutoModel",
    "AutoProcessor",
    "AutoTokenizer",
}


def _imports(tree: ast.Module) -> dict[str, str]:
    """Map imported local names to their fully qualified names."""
    names: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                local_name = alias.asname or alias.name.split(".")[0]
                imported_name = alias.name if alias.asname else local_name
                names[local_name] = imported_name
        elif isinstance(node, ast.ImportFrom):
            if node.module is None:
                continue
            for alias in node.names:
                if alias.name != "*":
                    names[alias.asname or alias.name] = f"{node.module}.{alias.name}"
    return names


def _qualified_name(node: ast.AST, imports: dict[str, str]) -> str | None:
    if isinstance(node, ast.Name):
        return imports.get(node.id)
    if isinstance(node, ast.Attribute):
        parent = _qualified_name(node.value, imports)
        return f"{parent}.{node.attr}" if parent else None
    return None


def _operation(api: str) -> str | None:
    if api in _LOCAL_DESERIALIZERS:
        return "local artifact deserialization"
    if api in _REMOTE_ACQUISITION_APIS:
        return _REMOTE_ACQUISITION_APIS[api]
    parts = api.split(".")
    if (
        len(parts) == 3
        and parts[0] == "transformers"
        and parts[2] == "from_pretrained"
        and (
            parts[1] in _TRANSFORMER_AUTO_CLASSES
            or parts[1].startswith("AutoModelFor")
        )
    ):
        return "remote model acquisition"
    return None


def _evidence(api: str, operation: str, node: ast.Call) -> Evidence:
    line = node.lineno
    column = node.col_offset + 1
    return Evidence(
        description=f"{operation} via {api}",
        location=f"line {line}, column {column}",
        attributes={
            "api": api,
            "operation": operation,
            "line": line,
            "column": column,
        },
    )


def scan_python_file(path: str | os.PathLike) -> ScanResult:
    """Parse Python source without executing it."""
    result = ScanResult(target=os.fspath(path))
    try:
        with tokenize.open(path) as source_file:
            source = source_file.read()
    except OSError as exc:
        result.errors.append(f"Cannot read file: {exc}")
        return result
    except (SyntaxError, UnicodeDecodeError) as exc:
        result.errors.append(f"Cannot parse Python source: {exc}")
        return result

    try:
        tree = ast.parse(source, filename=os.fspath(path))
    except SyntaxError as exc:
        result.errors.append(f"Cannot parse Python source: {exc}")
        return result

    imports = _imports(tree)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        api = _qualified_name(node.func, imports)
        if api is None:
            continue
        operation = _operation(api)
        if operation is None:
            continue
        evidence = _evidence(api, operation, node)
        if operation == "local artifact deserialization":
            result.results.append(
                Finding(
                    rule_id="python.unsafe_deserialization",
                    artifact_path=result.target,
                    message=(
                        f"Uses pickle-based deserialization through {api}; "
                        "this is security-sensitive when input is untrusted."
                    ),
                    evidence=[evidence],
                )
            )
        else:
            result.results.append(evidence)

        trust_remote_code = any(
            keyword.arg == "trust_remote_code"
            and isinstance(keyword.value, ast.Constant)
            and keyword.value.value is True
            for keyword in node.keywords
        )
        if trust_remote_code and operation in {
            "remote model acquisition",
            "external dataset acquisition",
        }:
            trust_evidence = _evidence(api, "explicit remote-code trust", node)
            trust_evidence.attributes["trust_remote_code"] = True
            result.results.append(
                Finding(
                    rule_id="python.remote_code_trust",
                    artifact_path=result.target,
                    message=(
                        f"Explicitly enables remote code trust for {api}; "
                        "remote code may execute during acquisition or loading."
                    ),
                    evidence=[trust_evidence],
                )
            )
    return result
