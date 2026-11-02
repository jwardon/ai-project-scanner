"""Static inspection of Python source using the standard-library AST."""

from __future__ import annotations

import ast
import os
import tokenize

from .results import Evidence, Finding, ScanResult

_LOCAL_DESERIALIZERS = {"pickle.load", "pickle.loads", "joblib.load"}
_REMOTE_ACQUISITION_APIS = {
    "huggingface_hub.hf_hub_download": "remote artifact acquisition",
    "huggingface_hub.snapshot_download": "remote artifact acquisition",
    "langchain.hub.pull": "remote prompt acquisition",
}
_TRANSFORMER_AUTO_CLASSES = {
    "AutoConfig",
    "AutoFeatureExtractor",
    "AutoImageProcessor",
    "AutoModel",
    "AutoProcessor",
    "AutoTokenizer",
}


def _operation(api: str) -> str | None:
    if api in _LOCAL_DESERIALIZERS:
        return "local artifact deserialization"
    if api in _REMOTE_ACQUISITION_APIS:
        return _REMOTE_ACQUISITION_APIS[api]
    if api == "datasets.load_dataset":
        return "dataset loading"
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
        if parts[1] == "AutoModel" or parts[1].startswith("AutoModelFor"):
            return "model loading"
        return "model artifact loading"
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


def _bound_names(target: ast.AST) -> set[str]:
    if isinstance(target, ast.Name):
        return {target.id}
    if isinstance(target, (ast.Tuple, ast.List)):
        return set().union(*(_bound_names(item) for item in target.elts))
    return set()


class _SourceAnalyzer(ast.NodeVisitor):
    def __init__(self, result: ScanResult):
        self.result = result
        self.scopes: list[tuple[str, dict[str, str | None]]] = [("module", {})]

    def _bind(self, name: str, api: str | None) -> None:
        self.scopes[-1][1][name] = api

    def _resolve(self, node: ast.AST) -> str | None:
        if isinstance(node, ast.Name):
            for _kind, names in reversed(self.scopes):
                if node.id in names:
                    return names[node.id]
            return None
        if isinstance(node, ast.Attribute):
            parent = self._resolve(node.value)
            return f"{parent}.{node.attr}" if parent else None
        return None

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            local_name = alias.asname or alias.name.split(".")[0]
            api = alias.name if alias.asname else local_name
            self._bind(local_name, api)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        for alias in node.names:
            if alias.name == "*":
                continue
            local_name = alias.asname or alias.name
            api = (
                f"{node.module}.{alias.name}"
                if node.level == 0 and node.module
                else None
            )
            self._bind(local_name, api)

    def visit_Call(self, node: ast.Call) -> None:
        api = self._resolve(node.func)
        operation = _operation(api) if api else None
        if operation is not None:
            evidence = _evidence(api, operation, node)
            if operation == "local artifact deserialization":
                self.result.results.append(
                    Finding(
                        rule_id="python.unsafe_deserialization",
                        artifact_path=self.result.target,
                        message=(
                            f"Uses pickle-based deserialization through {api}; "
                            "this is security-sensitive when input is untrusted."
                        ),
                        evidence=[evidence],
                    )
                )
            else:
                self.result.results.append(evidence)

            trust_remote_code = any(
                keyword.arg == "trust_remote_code"
                and isinstance(keyword.value, ast.Constant)
                and keyword.value.value is True
                for keyword in node.keywords
            )
            if trust_remote_code and operation in {
                "model loading",
                "model artifact loading",
                "dataset loading",
            }:
                trust_evidence = _evidence(
                    api, "explicit remote-code trust", node
                )
                trust_evidence.attributes["trust_remote_code"] = True
                self.result.results.append(
                    Finding(
                        rule_id="python.remote_code_trust",
                        artifact_path=self.result.target,
                        message=(
                            f"Explicitly enables remote code trust for {api}; "
                            "remote code may execute during acquisition or loading."
                        ),
                        evidence=[trust_evidence],
                    )
                )
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        self.visit(node.value)
        for target in node.targets:
            for name in _bound_names(target):
                self._bind(name, None)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.value is not None:
            self.visit(node.value)
        for name in _bound_names(node.target):
            self._bind(name, None)

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        self.visit(node.value)
        for name in _bound_names(node.target):
            self._bind(name, None)

    def visit_NamedExpr(self, node: ast.NamedExpr) -> None:
        self.visit(node.value)
        for name in _bound_names(node.target):
            self._bind(name, None)

    def visit_Delete(self, node: ast.Delete) -> None:
        for target in node.targets:
            for name in _bound_names(target):
                self._bind(name, None)

    def visit_For(self, node: ast.For) -> None:
        self.visit(node.iter)
        for name in _bound_names(node.target):
            self._bind(name, None)
        for statement in node.body + node.orelse:
            self.visit(statement)

    visit_AsyncFor = visit_For

    def visit_With(self, node: ast.With) -> None:
        for item in node.items:
            self.visit(item.context_expr)
            if item.optional_vars is not None:
                for name in _bound_names(item.optional_vars):
                    self._bind(name, None)
        for statement in node.body:
            self.visit(statement)

    visit_AsyncWith = visit_With

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        for decorator in node.decorator_list:
            self.visit(decorator)
        for default in node.args.defaults + node.args.kw_defaults:
            if default is not None:
                self.visit(default)
        arguments = (
            node.args.posonlyargs
            + node.args.args
            + node.args.kwonlyargs
        )
        for argument in arguments:
            if argument.annotation is not None:
                self.visit(argument.annotation)
        if node.args.vararg and node.args.vararg.annotation:
            self.visit(node.args.vararg.annotation)
        if node.args.kwarg and node.args.kwarg.annotation:
            self.visit(node.args.kwarg.annotation)
        if node.returns is not None:
            self.visit(node.returns)
        self._bind(node.name, None)
        parent_scopes = (
            self.scopes[:-1]
            if self.scopes[-1][0] == "class"
            else self.scopes
        )
        self.scopes = parent_scopes + [("function", {})]
        for argument in arguments:
            self._bind(argument.arg, None)
        if node.args.vararg:
            self._bind(node.args.vararg.arg, None)
        if node.args.kwarg:
            self._bind(node.args.kwarg.arg, None)
        for statement in node.body:
            self.visit(statement)
        self.scopes = parent_scopes

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        for expression in node.decorator_list + node.bases:
            self.visit(expression)
        for keyword in node.keywords:
            self.visit(keyword.value)
        self._bind(node.name, None)
        self.scopes.append(("class", {}))
        for statement in node.body:
            self.visit(statement)
        self.scopes.pop()


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

    _SourceAnalyzer(result).visit(tree)
    return result
