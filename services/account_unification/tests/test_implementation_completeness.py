"""Repository-owned implementation completeness checks."""
from __future__ import annotations

import ast
import importlib
import inspect
import textwrap
from pathlib import Path


SOURCE_ROOTS = (Path("app"), Path("fuzz"), Path("tools"))
PROTOCOL_IMPLEMENTATIONS = {
    ("app.audit", "AuditSink"): (
        ("app.audit", "InMemoryAuditSink"),
        ("app.audit", "SqliteAuditSink"),
    ),
    ("app.keycloak_client", "AdminApi"): (
        ("app.keycloak_client", "HttpAdminApi"),
        ("tests.mock_keycloak", "MockKeycloakAdminApi"),
    ),
    ("app.kv_store", "KvStore"): (
        ("app.kv_store", "InMemoryKvStore"),
        ("app.kv_store", "SqliteKvStore"),
    ),
}


def _class_bases(class_node: ast.ClassDef | None) -> set[str]:
    if class_node is None:
        return set()
    bases: set[str] = set()
    for base in class_node.bases:
        bases.add(getattr(base, "id", getattr(base, "attr", ast.unparse(base))))
    return bases


def _is_empty_function_body(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    executable = [
        statement
        for statement in node.body
        if not (
            isinstance(statement, ast.Expr)
            and isinstance(getattr(statement, "value", None), ast.Constant)
            and isinstance(statement.value.value, str)
        )
    ]
    if len(executable) != 1:
        return False
    statement = executable[0]
    if isinstance(statement, ast.Pass):
        return True
    if (
        isinstance(statement, ast.Expr)
        and isinstance(statement.value, ast.Constant)
        and statement.value.value is Ellipsis
    ):
        return True
    if isinstance(statement, ast.Raise):
        exc = statement.exc
        name = getattr(exc, "id", getattr(exc, "attr", ""))
        if isinstance(exc, ast.Call):
            name = getattr(exc.func, "id", getattr(exc.func, "attr", ""))
        return name == "NotImplementedError"
    return False


def _load_class(module_name: str, class_name: str):
    return getattr(importlib.import_module(module_name), class_name)


def _public_protocol_methods(protocol_class) -> list[str]:
    return sorted(
        name
        for name, member in protocol_class.__dict__.items()
        if callable(member) and not name.startswith("_")
    )


def _method_has_empty_body(method) -> bool:
    source = textwrap.dedent(inspect.getsource(method))
    tree = ast.parse(source)
    function_node = tree.body[0]
    assert isinstance(function_node, (ast.FunctionDef, ast.AsyncFunctionDef))
    return _is_empty_function_body(function_node)


def _empty_function_bodies() -> list[str]:
    findings: list[str] = []
    for source_root in SOURCE_ROOTS:
        for path in sorted(source_root.rglob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            parents: dict[ast.AST, ast.AST] = {}
            for parent in ast.walk(tree):
                for child in ast.iter_child_nodes(parent):
                    parents[child] = parent
            for node in ast.walk(tree):
                if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                if not _is_empty_function_body(node):
                    continue
                parent = parents.get(node)
                class_node = parent if isinstance(parent, ast.ClassDef) else None
                if "Protocol" in _class_bases(class_node):
                    continue
                findings.append(f"{path}:{node.lineno} {node.name}")
    return findings


def test_empty_function_bodies_are_protocol_contracts_only():
    """Reject accidental stubs while allowing typing.Protocol declarations."""
    assert _empty_function_bodies() == []


def test_protocol_contracts_have_non_empty_concrete_implementations():
    """Reject Protocol contracts whose concrete implementations are only stubs."""
    for protocol_ref, implementation_refs in PROTOCOL_IMPLEMENTATIONS.items():
        protocol_class = _load_class(*protocol_ref)
        method_names = _public_protocol_methods(protocol_class)
        assert method_names, f"{protocol_ref[1]} must declare at least one method"

        for implementation_ref in implementation_refs:
            implementation_class = _load_class(*implementation_ref)
            missing = [
                method_name
                for method_name in method_names
                if not callable(getattr(implementation_class, method_name, None))
            ]
            assert missing == [], (
                f"{implementation_ref[1]} is missing {protocol_ref[1]} "
                f"methods: {missing}"
            )

            empty = [
                method_name
                for method_name in method_names
                if _method_has_empty_body(getattr(implementation_class, method_name))
            ]
            assert empty == [], (
                f"{implementation_ref[1]} has unimplemented {protocol_ref[1]} "
                f"methods: {empty}"
            )
