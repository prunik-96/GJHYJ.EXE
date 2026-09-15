"""Движок правил, работающих по образцу в синтаксическом дереве.

Часть проблем видна без анализа потока данных: вызов слабого хеша, пароль
в исходнике, отключённая проверка сертификата. Такие правила описываются
как обработчики узлов определённого типа и применяются за один обход дерева.

Каждое правило объявляет метаданные через :func:`define`, поэтому список
проверок и их описания собираются автоматически — руками ничего дублировать
не нужно.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from typing import Callable

from ..analyses.constants import ConstantEnv
from ..core.findings import Confidence, Finding, Severity, TraceStep
from ..core.symbols import SymbolTable


@dataclass(frozen=True)
class RuleMeta:
    id: str
    title: str
    message: str
    severity: Severity
    cwe: str | None
    category: str
    remediation: str


CATALOG: dict[str, RuleMeta] = {}
_HANDLERS: dict[type, list[Callable]] = {}


def define(
    id: str,
    title: str,
    message: str,
    severity: Severity,
    category: str,
    remediation: str,
    cwe: str | None = None,
) -> RuleMeta:
    """Объявить правило и зарегистрировать его в общем каталоге."""
    if id in CATALOG:
        raise ValueError(f"правило {id} уже объявлено")
    meta = RuleMeta(id, title, message, severity, cwe, category, remediation)
    CATALOG[id] = meta
    return meta


def on(*node_types: type) -> Callable:
    """Зарегистрировать обработчик для узлов указанных типов."""

    def decorator(function: Callable) -> Callable:
        for node_type in node_types:
            _HANDLERS.setdefault(node_type, []).append(function)
        return function

    return decorator


class RuleContext:
    """Всё, что нужно правилу: дерево, имена, константы и способ сообщить."""

    def __init__(
        self,
        path: str,
        tree: ast.Module,
        symbols: SymbolTable,
        env: ConstantEnv,
        source: str,
    ) -> None:
        self.path = path
        self.tree = tree
        self.symbols = symbols
        self.env = env
        self.source = source
        self.lines = source.splitlines()
        self.findings: list[Finding] = []
        self._parents: dict[int, ast.AST] = {}
        self._index_parents(tree)

    def _index_parents(self, tree: ast.AST) -> None:
        for parent in ast.walk(tree):
            for child in ast.iter_child_nodes(parent):
                self._parents[id(child)] = parent

    def parent(self, node: ast.AST) -> ast.AST | None:
        return self._parents.get(id(node))

    def enclosing_function(self, node: ast.AST) -> ast.AST | None:
        current = self.parent(node)
        while current is not None:
            if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef)):
                return current
            current = self.parent(current)
        return None

    def qualified(self, node: ast.AST) -> str | None:
        from ..core.symbols import dotted_name

        resolved = self.symbols.qualify(node)
        if resolved is not None:
            return resolved
        raw = dotted_name(node)
        if raw is not None and self.symbols.matches(node, {raw}) is not None:
            return raw
        return None

    def emit(
        self,
        meta: RuleMeta,
        node: ast.AST,
        message: str | None = None,
        severity: Severity | None = None,
        confidence: Confidence = Confidence.HIGH,
        trace: list[TraceStep] | None = None,
    ) -> None:
        self.findings.append(
            Finding(
                rule_id=meta.id,
                title=meta.title,
                message=message or meta.message,
                severity=severity or meta.severity,
                confidence=confidence,
                path=self.path,
                line=getattr(node, "lineno", 0),
                column=getattr(node, "col_offset", 0),
                end_line=getattr(node, "end_lineno", None),
                cwe=meta.cwe,
                category=meta.category,
                remediation=meta.remediation,
                trace=trace or [],
            )
        )


def run_rules(context: RuleContext) -> list[Finding]:
    """Один обход дерева, диспетчеризация по типу узла."""
    for node in ast.walk(context.tree):
        for handler in _HANDLERS.get(type(node), ()):
            handler(node, context)
    return context.findings


def keyword_of(node: ast.Call, name: str) -> ast.keyword | None:
    for keyword in node.keywords:
        if keyword.arg == name:
            return keyword
    return None
