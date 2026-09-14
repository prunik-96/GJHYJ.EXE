"""Анализ помеченных данных (taint analysis).

Главная идея: пометить всё, что пришло извне, и проследить, куда оно
дотекает. Если помеченное значение достигает опасной операции, минуя
проверку, — это уязвимость, и движок может показать весь путь целиком.

Анализ межпроцедурный, но упрощённо: вызовы разбираются за несколько
раундов. В первом раунде видно, какие функции вызываются с грязными
аргументами; в следующем их параметры тоже считаются грязными. Так поток
прослеживается через слои ``handler -> helper -> execute``.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field

from ..core.cfg import CFGBuilder, Eval, function_scopes
from ..core.dataflow import merge_maps, solve_forward
from ..core.findings import Confidence, Finding, Severity, TraceStep
from ..core.symbols import SymbolTable, attribute_tail, dotted_name
from .constants import ConstantEnv
from .taint_spec import (
    FILE_READ_METHODS,
    HANDLER_DECORATOR_HINTS,
    HTTP_REQUEST_ATTRS,
    NETWORK_READ_METHODS,
    SANITIZERS,
    SINKS,
    SOURCES,
    TRUST,
)

MAX_TRACE = 6
MAX_ROUNDS = 4

# Функции, не возвращающие обработанные данные: пропускать через них метку
# незачем, иначе появляются ложные срабатывания.
NON_PROPAGATING = frozenset({
    "print", "logging.debug", "logging.info", "logging.warning",
    "logging.error", "logging.exception", "isinstance", "issubclass",
})


@dataclass(frozen=True)
class Taint:
    """Пометка значения: откуда пришло и что уже обезврежено."""

    labels: frozenset[str] = frozenset()
    neutralized: frozenset[str] = frozenset()
    trace: tuple[TraceStep, ...] = ()

    def __bool__(self) -> bool:
        return bool(self.labels)

    def with_step(self, line: int, description: str) -> "Taint":
        if not self.labels or len(self.trace) >= MAX_TRACE:
            return self
        if self.trace and self.trace[-1].description == description:
            return self
        return Taint(self.labels, self.neutralized, self.trace + (TraceStep(line, description),))

    def sanitize(self, categories: frozenset[str] | None, line: int, name: str) -> "Taint":
        if categories is None:
            return CLEAN
        return Taint(
            self.labels,
            self.neutralized | categories,
            self.trace + (TraceStep(line, f"обезврежено через {name}()"),)
            if len(self.trace) < MAX_TRACE
            else self.trace,
        )

    def covers(self, category: str) -> bool:
        """Опасна ли метка для стока этой категории."""
        return bool(self.labels) and category not in self.neutralized


CLEAN = Taint()


def join_taint(left: Taint, right: Taint) -> Taint:
    """Слияние двух путей.

    Метки объединяются: значение грязное, если оно грязное хотя бы по
    одному пути. Обезвреженные категории, наоборот, пересекаются —
    проверка засчитывается, только если она есть на всех путях.
    """
    if left == right:
        return left
    # Чистое значение не накладывает ограничений: у него нет ни меток, ни
    # проверок, поэтому оно не должно отменять уже выполненное обезвреживание.
    if not left.labels:
        return right
    if not right.labels:
        return left
    labels = left.labels | right.labels
    neutralized = left.neutralized & right.neutralized
    if not labels:
        return CLEAN
    # Порядок выбора следа детерминирован, иначе анализ не сойдётся.
    candidates = [t for t in (left, right) if t.labels]
    trace = min(
        (t.trace for t in candidates),
        key=lambda tr: (len(tr), tuple((s.line, s.description) for s in tr)),
    )
    return Taint(labels, neutralized, trace)


def join_states(states: list[dict[str, Taint]]) -> dict[str, Taint]:
    return merge_maps(states, join_taint)


@dataclass
class ScopeInfo:
    """Область видимости, подготовленная к анализу."""

    name: str
    node: ast.AST
    body: list[ast.stmt]
    cfg: object
    env: ConstantEnv
    is_handler: bool = False
    params: list[str] = field(default_factory=list)


class TaintAnalysis:
    """Анализ одного модуля."""

    def __init__(self, tree: ast.Module, symbols: SymbolTable, path: str) -> None:
        self.tree = tree
        self.symbols = symbols
        self.path = path
        self.findings: list[Finding] = []
        # Параметры функций, признанные грязными по результатам прошлых раундов.
        self.param_taint: dict[tuple[str, str], frozenset[str]] = {}
        self._functions: dict[str, ast.AST] = {}
        self._collecting = False

    def run(self) -> list[Finding]:
        module_env = ConstantEnv.from_scope(self.tree.body)
        scopes = self._prepare_scopes(module_env)
        for scope in scopes:
            if isinstance(scope.node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self._functions[scope.name] = scope.node

        # Раунды нужны, чтобы метка прошла через цепочку вызовов.
        for round_index in range(MAX_ROUNDS):
            before = dict(self.param_taint)
            self.findings = []
            self._collecting = True
            for scope in scopes:
                self._analyze_scope(scope)
            if self.param_taint == before:
                break
        return self.findings

    def _prepare_scopes(self, module_env: ConstantEnv) -> list[ScopeInfo]:
        scopes: list[ScopeInfo] = []
        for name, node, body in function_scopes(self.tree):
            scope_values = ConstantEnv.from_scope(body).names()
            env = ConstantEnv({**module_env.names(), **scope_values})
            cfg = CFGBuilder.build(name, node, body)
            info = ScopeInfo(name=name, node=node, body=body, cfg=cfg, env=env)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                info.params = _parameter_names(node)
                info.is_handler = _is_request_handler(node)
            scopes.append(info)
        return scopes

    # --- анализ области видимости -----------------------------------------

    def _analyze_scope(self, scope: ScopeInfo) -> None:
        initial = self._initial_state(scope)

        def transfer(block, state):
            evaluator = _Evaluator(self, scope, dict(state))
            for instruction in block.instructions:
                evaluator.execute(instruction)
            return evaluator.state

        solve_forward(
            scope.cfg,
            initial,
            transfer,
            join_states,
            edge_transfer=None,
            empty=dict,
        )

    def _initial_state(self, scope: ScopeInfo) -> dict[str, Taint]:
        state: dict[str, Taint] = {}
        if not scope.params:
            return state
        line = getattr(scope.node, "lineno", 0)
        for param in scope.params:
            if param in ("self", "cls"):
                continue
            if scope.is_handler:
                state[param] = Taint(
                    frozenset({"http"}),
                    frozenset(),
                    (TraceStep(line, f"параметр {param} обработчика приходит из HTTP-запроса"),),
                )
            else:
                labels = self.param_taint.get((scope.name, param))
                if labels:
                    state[param] = Taint(
                        labels,
                        frozenset(),
                        (TraceStep(line, f"параметр {param} получает непроверенные данные от вызывающего кода"),),
                    )
        return state

    def record_param_taint(self, func_name: str, param: str, labels: frozenset[str]) -> None:
        key = (func_name, param)
        existing = self.param_taint.get(key, frozenset())
        merged = existing | labels
        if merged != existing:
            self.param_taint[key] = merged

    def lookup_function(self, name: str) -> ast.AST | None:
        return self._functions.get(name)

    def report(self, finding: Finding) -> None:
        if not self._collecting:
            return
        for existing in self.findings:
            if (existing.rule_id, existing.line, existing.column) == (
                finding.rule_id,
                finding.line,
                finding.column,
            ):
                return
        self.findings.append(finding)


class _Evaluator:
    """Вычисляет пометки выражений и попутно проверяет стоки."""

    def __init__(self, analysis: TaintAnalysis, scope: ScopeInfo, state: dict[str, Taint]) -> None:
        self.analysis = analysis
        self.scope = scope
        self.state = state
        self.symbols = analysis.symbols
        self.env = scope.env

    # --- операторы ---------------------------------------------------------

    def execute(self, instruction) -> None:
        if isinstance(instruction, Eval):
            self.eval(instruction.expr)
            return
        handler = getattr(self, f"_exec_{type(instruction).__name__.lower()}", None)
        if handler is not None:
            handler(instruction)
        elif isinstance(instruction, ast.stmt):
            for child in ast.iter_child_nodes(instruction):
                if isinstance(child, ast.expr):
                    self.eval(child)

    def _exec_assign(self, stmt: ast.Assign) -> None:
        value = self.eval(stmt.value)
        for target in stmt.targets:
            self._bind(target, value, stmt.lineno)

    def _exec_annassign(self, stmt: ast.AnnAssign) -> None:
        if stmt.value is None:
            return
        self._bind(stmt.target, self.eval(stmt.value), stmt.lineno)

    def _exec_augassign(self, stmt: ast.AugAssign) -> None:
        value = self.eval(stmt.value)
        if isinstance(stmt.target, ast.Name):
            current = self.state.get(stmt.target.id, CLEAN)
            self._bind(stmt.target, join_taint(current, value), stmt.lineno)
        else:
            self._bind(stmt.target, value, stmt.lineno)

    def _exec_for(self, stmt: ast.For) -> None:
        value = self.eval(stmt.iter)
        self._bind(stmt.target, value, stmt.lineno)

    _exec_asyncfor = _exec_for

    def _exec_with(self, stmt: ast.With) -> None:
        for item in stmt.items:
            value = self.eval(item.context_expr)
            if item.optional_vars is not None:
                self._bind(item.optional_vars, value, stmt.lineno)

    _exec_asyncwith = _exec_with

    def _exec_functiondef(self, stmt) -> None:
        # Тело разбирается отдельно; здесь важны только декораторы и умолчания.
        for decorator in stmt.decorator_list:
            self.eval(decorator)
        for default in list(stmt.args.defaults) + [d for d in stmt.args.kw_defaults if d]:
            self.eval(default)

    _exec_asyncfunctiondef = _exec_functiondef

    def _exec_classdef(self, stmt: ast.ClassDef) -> None:
        for decorator in stmt.decorator_list:
            self.eval(decorator)

    def _exec_import(self, stmt) -> None:
        return

    _exec_importfrom = _exec_import
    _exec_global = _exec_import
    _exec_nonlocal = _exec_import
    _exec_pass = _exec_import

    def _bind(self, target: ast.AST, value: Taint, line: int) -> None:
        if isinstance(target, ast.Name):
            if value:
                value = value.with_step(line, f"значение сохраняется в переменную {target.id}")
                self.state[target.id] = value
            else:
                self.state.pop(target.id, None)
        elif isinstance(target, (ast.Tuple, ast.List)):
            for element in target.elts:
                self._bind(element, value, line)
        elif isinstance(target, ast.Starred):
            self._bind(target.value, value, line)
        elif isinstance(target, (ast.Attribute, ast.Subscript)):
            # Запись в контейнер делает грязным сам контейнер.
            root = _root_name(target)
            if root is not None and value:
                current = self.state.get(root, CLEAN)
                self.state[root] = join_taint(current, value)

    # --- выражения ---------------------------------------------------------

    def eval(self, node: ast.AST | None) -> Taint:
        if node is None:
            return CLEAN
        method = getattr(self, f"_eval_{type(node).__name__.lower()}", None)
        if method is not None:
            return method(node)
        return self._eval_children(node)

    def _eval_children(self, node: ast.AST) -> Taint:
        result = CLEAN
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.expr):
                result = join_taint(result, self.eval(child))
        return result

    def _eval_constant(self, node: ast.Constant) -> Taint:
        return CLEAN

    def _eval_name(self, node: ast.Name) -> Taint:
        source = self._source_for(node)
        if source is not None:
            return source
        return self.state.get(node.id, CLEAN)

    def _eval_attribute(self, node: ast.Attribute) -> Taint:
        source = self._source_for(node)
        if source is not None:
            return source
        return self.eval(node.value)

    def _eval_subscript(self, node: ast.Subscript) -> Taint:
        source = self._source_for(node)
        if source is not None:
            return source
        return join_taint(self.eval(node.value), self.eval(node.slice))

    def _eval_compare(self, node: ast.Compare) -> Taint:
        # Результат сравнения — булево значение, данных оно не переносит.
        self.eval(node.left)
        for comparator in node.comparators:
            self.eval(comparator)
        return CLEAN

    def _eval_boolop(self, node: ast.BoolOp) -> Taint:
        result = CLEAN
        for value in node.values:
            result = join_taint(result, self.eval(value))
        return result

    def _eval_namedexpr(self, node: ast.NamedExpr) -> Taint:
        value = self.eval(node.value)
        self._bind(node.target, value, node.lineno)
        return value

    def _eval_lambda(self, node: ast.Lambda) -> Taint:
        return CLEAN

    def _eval_call(self, node: ast.Call) -> Taint:
        # Аргументы вычисляются всегда: внутри них тоже могут быть стоки.
        argument_taint = CLEAN
        for argument in node.args:
            argument_taint = join_taint(argument_taint, self.eval(argument))
        for keyword in node.keywords:
            argument_taint = join_taint(argument_taint, self.eval(keyword.value))

        self._check_sinks(node)
        self._propagate_to_callee(node)

        source = self._source_for(node)
        if source is not None:
            return source

        name = self._canonical_name(node.func)
        if name is not None and name in SANITIZERS:
            if argument_taint:
                return argument_taint.sanitize(SANITIZERS[name], node.lineno, name)
            return CLEAN
        if name is not None and name in NON_PROPAGATING:
            return CLEAN

        receiver_taint = self.eval(node.func) if isinstance(node.func, ast.Attribute) else CLEAN
        return join_taint(argument_taint, receiver_taint)

    def _eval_joinedstr(self, node: ast.JoinedStr) -> Taint:
        result = CLEAN
        for value in node.values:
            result = join_taint(result, self.eval(value))
        if result:
            result = result.with_step(node.lineno, "данные подставляются в строку")
        return result

    def _eval_binop(self, node: ast.BinOp) -> Taint:
        result = join_taint(self.eval(node.left), self.eval(node.right))
        if result and isinstance(node.op, (ast.Add, ast.Mod)):
            result = result.with_step(node.lineno, "данные склеиваются в строку")
        return result

    # --- распознавание источников -----------------------------------------

    def _source_for(self, node: ast.AST) -> Taint | None:
        target = node.func if isinstance(node, ast.Call) else node
        raw = dotted_name(target)
        qualified = self.symbols.qualify(target)
        line = getattr(node, "lineno", 0)

        for spec in SOURCES:
            for candidate in (qualified, raw):
                if candidate is None:
                    continue
                if candidate in spec.names:
                    return self._make_source(spec.label, spec.description, line)
                if spec.prefix and any(
                    candidate == name or candidate.startswith(name + ".") for name in spec.names
                ):
                    return self._make_source(spec.label, spec.description, line)

        # `request.args` и подобное — без опоры на импорты, работает и в Django.
        if isinstance(target, ast.Attribute) and raw is not None:
            head, _, _ = raw.partition(".")
            if head == "request" and _mentions_request_attr(raw):
                return self._make_source("http", "HTTP-запрос", line)

        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            method = node.func.attr
            if method in NETWORK_READ_METHODS:
                return self._make_source("network", "данные из сети", line)
            if method in FILE_READ_METHODS and not self.eval(node.func.value):
                return self._make_source("file", "содержимое файла", line)
        return None

    def _make_source(self, label: str, description: str, line: int) -> Taint:
        return Taint(
            frozenset({label}),
            frozenset(),
            (TraceStep(line, f"источник непроверенных данных: {description}"),),
        )

    # --- проверка стоков ---------------------------------------------------

    def _canonical_name(self, func: ast.AST) -> str | None:
        qualified = self.symbols.qualify(func)
        if qualified is not None:
            return qualified
        raw = dotted_name(func)
        if raw is not None and self.symbols.matches(func, {raw}) is not None:
            return raw
        return None

    def _check_sinks(self, node: ast.Call) -> None:
        name = self._canonical_name(node.func)
        tail = attribute_tail(node.func)
        for spec in SINKS:
            if spec.match == "tail":
                if tail not in spec.names or not isinstance(node.func, ast.Attribute):
                    continue
            elif name is None or name not in spec.names:
                continue
            if spec.guard is not None and not spec.guard(node, self.env):
                continue
            self._check_sink_arguments(node, spec)

    def _check_sink_arguments(self, node: ast.Call, spec) -> None:
        for position in spec.positions:
            if position < len(node.args):
                self._report_if_tainted(node, node.args[position], spec)
        for keyword in node.keywords:
            if keyword.arg in spec.keywords:
                self._report_if_tainted(node, keyword.value, spec)

    def _report_if_tainted(self, call: ast.Call, argument: ast.expr, spec) -> None:
        taint = self.eval(argument)
        if not taint.covers(spec.category):
            return
        severity, confidence = _rate(spec.severity, taint.labels)
        trace = list(taint.trace)
        trace.append(TraceStep(call.lineno, f"значение достигает опасной операции {_display(call)}"))
        self.analysis.report(
            Finding(
                rule_id=spec.rule_id,
                title=spec.title,
                message=spec.message,
                severity=severity,
                confidence=confidence,
                path=self.analysis.path,
                line=call.lineno,
                column=call.col_offset,
                end_line=getattr(call, "end_lineno", None),
                cwe=spec.cwe,
                category=spec.category,
                remediation=spec.remediation,
                trace=trace,
            )
        )

    # --- межпроцедурная передача ------------------------------------------

    def _propagate_to_callee(self, node: ast.Call) -> None:
        if not isinstance(node.func, ast.Name):
            return
        callee = self.analysis.lookup_function(node.func.id)
        if callee is None:
            return
        params = _parameter_names(callee)
        for index, argument in enumerate(node.args):
            if index >= len(params):
                break
            taint = self.eval(argument)
            if taint:
                self.analysis.record_param_taint(node.func.id, params[index], taint.labels)
        for keyword in node.keywords:
            if keyword.arg and keyword.arg in params:
                taint = self.eval(keyword.value)
                if taint:
                    self.analysis.record_param_taint(node.func.id, keyword.arg, taint.labels)


# --- вспомогательное -------------------------------------------------------

def _rate(base: Severity, labels: frozenset[str]) -> tuple[Severity, Confidence]:
    """Скорректировать уровень и уверенность по степени доверия к источнику."""
    trust = {TRUST.get(label, "medium") for label in labels}
    if "high" in trust:
        return base, Confidence.HIGH
    if "medium" in trust:
        return base, Confidence.MEDIUM
    # Только окружение: настраивает обычно тот же, кто запускает программу.
    lowered = Severity(max(Severity.LOW, base - 1))
    return lowered, Confidence.LOW


def _display(call: ast.Call) -> str:
    name = dotted_name(call.func) or attribute_tail(call.func) or "<вызов>"
    return f"{name}()"


def _root_name(node: ast.AST) -> str | None:
    current = node
    while isinstance(current, (ast.Attribute, ast.Subscript)):
        current = current.value
    return current.id if isinstance(current, ast.Name) else None


def _mentions_request_attr(raw: str) -> bool:
    return any(part in HTTP_REQUEST_ATTRS for part in raw.split("."))


def _parameter_names(node: ast.AST) -> list[str]:
    args = node.args
    names = [a.arg for a in args.posonlyargs] + [a.arg for a in args.args]
    if args.vararg:
        names.append(args.vararg.arg)
    names += [a.arg for a in args.kwonlyargs]
    if args.kwarg:
        names.append(args.kwarg.arg)
    return names


def _is_request_handler(node: ast.AST) -> bool:
    for decorator in node.decorator_list:
        target = decorator.func if isinstance(decorator, ast.Call) else decorator
        name = dotted_name(target) or ""
        tail = name.rsplit(".", 1)[-1]
        if tail in HANDLER_DECORATOR_HINTS and "." in name:
            return True
    return False
