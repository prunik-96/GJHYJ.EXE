"""Поиск обращений к значению, которое может оказаться None.

Это самая частая ошибка времени выполнения в Python: ``re.match`` вернул
None, а код сразу зовёт ``.group()``. Наивная проверка по AST давала бы
шквал ложных срабатываний, поэтому анализ учитывает условия: на ветке
``if m is not None`` переменная считается проверенной, а ``if m is None:
return`` снимает подозрение со всего остального кода.
"""

from __future__ import annotations

import ast

from ..core.cfg import CFG, Eval
from ..core.dataflow import merge_maps, solve_forward
from ..core.findings import Confidence, Finding, Severity, TraceStep
from ..core.symbols import SymbolTable, attribute_tail, dotted_name

NOT_NONE = "not-none"
MAYBE_NONE = "maybe-none"
DEFINITELY_NONE = "none"

RULE_ID = "AEG-BUG-001"

# Функции стандартной библиотеки, штатно возвращающие None.
OPTIONAL_CALLS: frozenset[str] = frozenset({
    "re.match", "re.search", "re.fullmatch",
    "shutil.which", "inspect.getmodule",
    "os.environ.get", "os.getenv",
})

# Методы, возвращающие None, у объекта неизвестного типа.
OPTIONAL_METHODS: frozenset[str] = frozenset({"get", "find", "match", "search", "fullmatch"})

_ORDER = {NOT_NONE: 0, MAYBE_NONE: 1, DEFINITELY_NONE: 2}


def _join_value(left: str, right: str) -> str:
    if left == right:
        return left
    return MAYBE_NONE


def _join_states(states: list[dict[str, str]]) -> dict[str, str]:
    if not states:
        return {}
    # Переменная, известная лишь на части путей, на остальных ничем не
    # ограничена, поэтому её состояние становится неопределённым.
    common = set(states[0])
    for state in states[1:]:
        common &= set(state)
    merged = merge_maps(states, _join_value)
    return {name: value for name, value in merged.items() if name in common}


class NullnessAnalysis:
    def __init__(self, tree: ast.Module, symbols: SymbolTable, path: str) -> None:
        self.tree = tree
        self.symbols = symbols
        self.path = path
        self.findings: list[Finding] = []
        self._seen: set[tuple[int, int]] = set()

    def run_scope(self, cfg: CFG, node: ast.AST) -> None:
        initial = self._initial_state(node)
        solve_forward(
            cfg,
            initial,
            self._transfer,
            _join_states,
            edge_transfer=self._refine,
            empty=dict,
        )

    def _initial_state(self, node: ast.AST) -> dict[str, str]:
        state: dict[str, str] = {}
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return state
        args = node.args
        # Параметр со значением по умолчанию None часто забывают проверить.
        positional = args.posonlyargs + args.args
        defaults = args.defaults
        offset = len(positional) - len(defaults)
        for index, default in enumerate(defaults):
            if isinstance(default, ast.Constant) and default.value is None:
                state[positional[offset + index].arg] = MAYBE_NONE
        for arg, default in zip(args.kwonlyargs, args.kw_defaults):
            if isinstance(default, ast.Constant) and default.value is None:
                state[arg.arg] = MAYBE_NONE
        return state

    # --- перенос -----------------------------------------------------------

    def _transfer(self, block, state: dict[str, str]) -> dict[str, str]:
        current = dict(state)
        for instruction in block.instructions:
            if isinstance(instruction, Eval):
                self._inspect(instruction.expr, current)
            else:
                self._statement(instruction, current)
        return current

    def _statement(self, stmt: ast.stmt, state: dict[str, str]) -> None:
        if isinstance(stmt, ast.Assign):
            self._inspect(stmt.value, state)
            value = self._state_of(stmt.value, state)
            for target in stmt.targets:
                if isinstance(target, ast.Name):
                    state[target.id] = value
                else:
                    self._inspect(target, state)
            return
        if isinstance(stmt, ast.AnnAssign) and stmt.value is not None:
            self._inspect(stmt.value, state)
            if isinstance(stmt.target, ast.Name):
                state[stmt.target.id] = self._state_of(stmt.value, state)
            return
        if isinstance(stmt, ast.Assert):
            self._inspect(stmt.test, state)
            self._apply_condition(stmt.test, True, state)
            return
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            return  # отдельная область видимости
        if isinstance(stmt, (ast.For, ast.AsyncFor)):
            self._inspect(stmt.iter, state)
            if isinstance(stmt.target, ast.Name):
                state[stmt.target.id] = NOT_NONE
            return
        for child in ast.iter_child_nodes(stmt):
            if isinstance(child, ast.expr):
                self._inspect(child, state)

    def _refine(self, edge, state: dict[str, str]) -> dict[str, str]:
        if edge.condition is None or edge.branch is None:
            return state
        refined = dict(state)
        self._apply_condition(edge.condition, edge.branch, refined)
        return refined

    def _apply_condition(self, test: ast.expr, truth: bool, state: dict[str, str]) -> None:
        """Уточнить состояние, зная результат проверки."""
        if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
            self._apply_condition(test.operand, not truth, state)
            return
        if isinstance(test, ast.BoolOp):
            # Для `and` истинность целого гарантирует истинность каждой части.
            if (isinstance(test.op, ast.And) and truth) or (isinstance(test.op, ast.Or) and not truth):
                for value in test.values:
                    self._apply_condition(value, truth, state)
            return
        if isinstance(test, ast.Name):
            # Истинное значение заведомо не None.
            state[test.id] = NOT_NONE if truth else MAYBE_NONE
            return
        if isinstance(test, ast.Compare) and len(test.ops) == 1:
            operator = test.ops[0]
            left, right = test.left, test.comparators[0]
            name = _name_compared_with_none(left, right)
            if name is None:
                return
            if isinstance(operator, (ast.Is, ast.Eq)):
                state[name] = DEFINITELY_NONE if truth else NOT_NONE
            elif isinstance(operator, (ast.IsNot, ast.NotEq)):
                state[name] = NOT_NONE if truth else DEFINITELY_NONE

    # --- вычисление состояния значения ------------------------------------

    def _state_of(self, node: ast.expr, state: dict[str, str]) -> str:
        if isinstance(node, ast.Constant):
            return DEFINITELY_NONE if node.value is None else NOT_NONE
        if isinstance(node, ast.Name):
            return state.get(node.id, NOT_NONE)
        if isinstance(node, ast.Call) and self._returns_optional(node):
            return MAYBE_NONE
        if isinstance(node, ast.BoolOp) and isinstance(node.op, ast.Or):
            # `x or default` — итог определяется последним операндом.
            return self._state_of(node.values[-1], state)
        if isinstance(node, ast.IfExp):
            return _join_value(self._state_of(node.body, state), self._state_of(node.orelse, state))
        if isinstance(node, ast.Await):
            return self._state_of(node.value, state)
        return NOT_NONE

    def _returns_optional(self, node: ast.Call) -> bool:
        qualified = self.symbols.qualify(node.func)
        if qualified is not None and qualified in OPTIONAL_CALLS:
            return True
        raw = dotted_name(node.func)
        if raw is not None and raw in OPTIONAL_CALLS:
            return True
        # `d.get(key)` без второго аргумента может вернуть None.
        if isinstance(node.func, ast.Attribute) and node.func.attr in OPTIONAL_METHODS:
            return len(node.args) < 2 and not node.keywords
        return False

    # --- поиск опасных обращений ------------------------------------------

    def _inspect(self, node: ast.expr, state: dict[str, str]) -> None:
        for child in ast.walk(node):
            if isinstance(child, (ast.Attribute, ast.Subscript)):
                self._check_access(child, child.value, state)

    def _check_access(self, access: ast.expr, base: ast.expr, state: dict[str, str]) -> None:
        if isinstance(base, ast.Name):
            status = state.get(base.id, NOT_NONE)
            if status == NOT_NONE:
                return
            description = f"переменная {base.id} может быть None в этой точке"
            confidence = Confidence.HIGH if status == DEFINITELY_NONE else Confidence.MEDIUM
        elif isinstance(base, ast.Call) and self._returns_optional(base):
            name = dotted_name(base.func) or attribute_tail(base.func) or "вызов"
            description = f"{name}() возвращает None, если совпадения нет"
            confidence = Confidence.HIGH
        else:
            return

        key = (access.lineno, access.col_offset)
        if key in self._seen:
            return
        self._seen.add(key)

        member = access.attr if isinstance(access, ast.Attribute) else "[...]"
        self.findings.append(
            Finding(
                rule_id=RULE_ID,
                title="Возможное обращение к None",
                message=f"обращение к {member} произойдёт с ошибкой, если значение окажется None",
                severity=Severity.MEDIUM,
                confidence=confidence,
                path=self.path,
                line=access.lineno,
                column=access.col_offset,
                cwe="CWE-476",
                category="reliability",
                remediation="Проверьте значение перед использованием: `if value is None: ...` "
                            "или задайте значение по умолчанию.",
                trace=[TraceStep(access.lineno, description)],
            )
        )


def _name_compared_with_none(left: ast.expr, right: ast.expr) -> str | None:
    """Имя переменной из сравнения вида ``x is None`` в любом порядке."""
    if isinstance(left, ast.Name) and _is_none_literal(right):
        return left.id
    if isinstance(right, ast.Name) and _is_none_literal(left):
        return right.id
    return None


def _is_none_literal(node: ast.expr) -> bool:
    return isinstance(node, ast.Constant) and node.value is None
