"""Repository-owned implementation completeness checks."""
from __future__ import annotations

import ast
from pathlib import Path


SOURCE_ROOTS = (Path("app"), Path("fuzz"), Path("tools"))


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
