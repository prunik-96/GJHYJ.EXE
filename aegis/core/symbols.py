"""Разрешение имён: приведение выражений к полному имени.

Правила движка описаны через канонические имена вроде ``subprocess.run``.
Но в реальном коде это может быть ``sp.run``, ``run`` или ``check_output``.
Этот модуль убирает разницу, собирая таблицу псевдонимов из импортов.
"""

from __future__ import annotations

import ast


def dotted_name(node: ast.AST) -> str | None:
    """Собрать ``a.b.c`` из цепочки Attribute/Name. None, если это не цепочка."""
    parts: list[str] = []
    current = node
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if not isinstance(current, ast.Name):
        return None
    parts.append(current.id)
    return ".".join(reversed(parts))


def attribute_tail(node: ast.AST) -> str | None:
    """Последний компонент выражения: для ``cursor.execute`` вернёт ``execute``.

    Нужно для правил, где важен только метод, а объект неизвестен
    (соединение с базой может называться как угодно).
    """
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Name):
        return node.id
    return None


class SymbolTable:
    """Таблица псевдонимов модуля плюс сведения о локальных переменных."""

    def __init__(self) -> None:
        self._aliases: dict[str, str] = {}
        self.imported_modules: set[str] = set()
        self._shadowed: set[str] = set()

    @classmethod
    def from_module(cls, tree: ast.Module) -> "SymbolTable":
        table = cls()
        table.collect(tree)
        return table

    def collect(self, tree: ast.AST) -> None:
        """Обойти дерево и запомнить все импорты."""
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                self._collect_import(node)
            elif isinstance(node, ast.ImportFrom):
                self._collect_import_from(node)

    def _collect_import(self, node: ast.Import) -> None:
        for alias in node.names:
            self.imported_modules.add(alias.name)
            if alias.asname:
                # import subprocess as sp  ->  sp == subprocess
                self._aliases[alias.asname] = alias.name
            else:
                # import os.path делает доступным имя `os`
                root = alias.name.split(".")[0]
                self._aliases[root] = root

    def _collect_import_from(self, node: ast.ImportFrom) -> None:
        if node.level:  # относительный импорт — полное имя нам неизвестно
            return
        module = node.module or ""
        if not module:
            return
        self.imported_modules.add(module)
        for alias in node.names:
            if alias.name == "*":
                continue
            local = alias.asname or alias.name
            self._aliases[local] = f"{module}.{alias.name}"

    def shadow(self, name: str) -> None:
        """Отметить, что имя переопределено в коде.

        Касается и импортов, и встроенных функций: если в модуле есть
        собственная ``def open(...)``, то вызов ``open(path)`` — это уже
        не файловая операция, и правила о ней применять нельзя.
        """
        self._shadowed.add(name)

    def shadow_module_definitions(self, tree: ast.Module) -> None:
        """Перекрыть имена, которые модуль определяет сам."""
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                self.shadow(node.name)
            elif isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        self.shadow(target.id)
            elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
                self.shadow(node.target.id)

    def qualify(self, node: ast.AST) -> str | None:
        """Полное имя выражения либо None, если восстановить его нельзя."""
        raw = dotted_name(node)
        if raw is None:
            return None
        head, _, tail = raw.partition(".")
        if head in self._shadowed:
            return None
        base = self._aliases.get(head)
        if base is None:
            # Имя не импортировалось: это локальный объект, а не известный API.
            return None
        return f"{base}.{tail}" if tail else base

    def matches(self, node: ast.AST, candidates: set[str]) -> str | None:
        """Вернуть совпавшее каноническое имя из набора кандидатов."""
        qualified = self.qualify(node)
        if qualified is not None and qualified in candidates:
            return qualified
        # Встроенные функции (eval, exec, open) не импортируются вовсе.
        raw = dotted_name(node)
        if raw is not None and raw in candidates and raw not in self._shadowed:
            return raw
        return None
