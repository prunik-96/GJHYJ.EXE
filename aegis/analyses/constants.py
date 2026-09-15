"""Вычисление переменных с заведомо известным значением.

Полноценное распространение констант по CFG здесь избыточно. Достаточно
более простого и надёжного признака: если во всей области видимости имя
присваивается ровно один раз и присваивается литералу, то в любой точке
кода оно равно этому литералу.

Так ловятся конструкции вида::

    USE_SHELL = True
    subprocess.run(cmd, shell=USE_SHELL)

где проверка одного лишь узла вызова ничего бы не увидела.
"""

from __future__ import annotations

import ast
from typing import Any

UNKNOWN = object()

_MAX_STR = 4096


def literal_value(node: ast.AST) -> Any:
    """Значение узла, если оно вычислимо статически, иначе ``UNKNOWN``."""
    if isinstance(node, ast.Constant):
        value = node.value
        if isinstance(value, str) and len(value) > _MAX_STR:
            return UNKNOWN
        return value
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        items = [literal_value(item) for item in node.elts]
        if any(item is UNKNOWN for item in items):
            return UNKNOWN
        if isinstance(node, ast.List):
            return items
        if isinstance(node, ast.Set):
            try:
                return set(items)
            except TypeError:
                return UNKNOWN
        return tuple(items)
    if isinstance(node, ast.Dict):
        result = {}
        for key_node, value_node in zip(node.keys, node.values):
            if key_node is None:
                return UNKNOWN
            key = literal_value(key_node)
            value = literal_value(value_node)
            if key is UNKNOWN or value is UNKNOWN:
                return UNKNOWN
            try:
                result[key] = value
            except TypeError:
                return UNKNOWN
        return result
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.USub, ast.UAdd, ast.Not)):
        operand = literal_value(node.operand)
        if operand is UNKNOWN:
            return UNKNOWN
        try:
            if isinstance(node.op, ast.USub):
                return -operand
            if isinstance(node.op, ast.UAdd):
                return +operand
            return not operand
        except TypeError:
            return UNKNOWN
    return UNKNOWN


class ConstantEnv:
    """Имена, значение которых известно на протяжении всей области видимости."""

    def __init__(self, values: dict[str, Any]) -> None:
        self._values = values

    @classmethod
    def from_scope(cls, body: list[ast.stmt]) -> "ConstantEnv":
        assignments: dict[str, list[Any]] = {}

        def record(name: str, value: Any) -> None:
            assignments.setdefault(name, []).append(value)

        for stmt in _walk_scope(body):
            if isinstance(stmt, ast.Assign):
                value = literal_value(stmt.value)
                for target in stmt.targets:
                    for name in _target_names(target):
                        record(name, value)
            elif isinstance(stmt, ast.AnnAssign) and stmt.value is not None:
                value = literal_value(stmt.value)
                for name in _target_names(stmt.target):
                    record(name, value)
            elif isinstance(stmt, (ast.AugAssign, ast.For, ast.AsyncFor)):
                target = stmt.target
                for name in _target_names(target):
                    record(name, UNKNOWN)
            elif isinstance(stmt, (ast.With, ast.AsyncWith)):
                for item in stmt.items:
                    if item.optional_vars is not None:
                        for name in _target_names(item.optional_vars):
                            record(name, UNKNOWN)

        resolved = {
            name: values[0]
            for name, values in assignments.items()
            if len(values) == 1 and values[0] is not UNKNOWN
        }
        return cls(resolved)

    def get(self, node: ast.AST) -> Any:
        """Значение выражения: литерал на месте либо однозначная переменная."""
        direct = literal_value(node)
        if direct is not UNKNOWN:
            return direct
        if isinstance(node, ast.Name):
            return self._values.get(node.id, UNKNOWN)
        return UNKNOWN

    def is_true(self, node: ast.AST) -> bool:
        return self.get(node) is True

    def as_text(self, node: ast.AST) -> str | None:
        value = self.get(node)
        return value if isinstance(value, str) else None

    def names(self) -> dict[str, Any]:
        return dict(self._values)


def _walk_scope(body: list[ast.stmt]):
    """Обойти операторы области видимости, не заходя во вложенные функции."""
    stack = list(body)
    while stack:
        stmt = stack.pop()
        yield stmt
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        for field_name in ("body", "orelse", "finalbody"):
            stack.extend(getattr(stmt, field_name, []) or [])
        for handler in getattr(stmt, "handlers", []) or []:
            stack.extend(handler.body)
        for case in getattr(stmt, "cases", []) or []:
            stack.extend(case.body)


def _target_names(target: ast.AST) -> list[str]:
    if isinstance(target, ast.Name):
        return [target.id]
    if isinstance(target, (ast.Tuple, ast.List)):
        names: list[str] = []
        for element in target.elts:
            names.extend(_target_names(element))
        return names
    if isinstance(target, ast.Starred):
        return _target_names(target.value)
    return []
