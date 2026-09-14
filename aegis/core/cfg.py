"""Построение графа потока управления (CFG).

Анализ по «плоскому» AST видит только соседство строк. Чтобы понять,
достижим ли опасный вызов и что попадёт в переменную к этому моменту,
нужен граф: базовые блоки плюс рёбра переходов.

Блок содержит либо обычный оператор, либо ``Eval`` — вычисление выражения
без присваивания (условие ``if``, итератор ``for``). Рёбра ветвлений несут
условие и его знак, что позволяет анализам уточнять состояние на ветках:
внутри ``if x is not None`` переменная заведомо не None.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field

Instruction = "ast.stmt | Eval"


@dataclass
class Eval:
    """Вычисление выражения, не являющееся самостоятельным оператором."""

    expr: ast.expr
    origin: ast.AST
    kind: str = "condition"

    @property
    def lineno(self) -> int:
        return getattr(self.expr, "lineno", getattr(self.origin, "lineno", 0))


@dataclass
class Edge:
    """Переход между блоками. ``condition`` задаёт, при каком исходе теста."""

    target: int
    condition: ast.expr | None = None
    branch: bool | None = None


@dataclass
class BasicBlock:
    id: int
    label: str = ""
    instructions: list = field(default_factory=list)
    succs: list[Edge] = field(default_factory=list)
    preds: list[int] = field(default_factory=list)

    @property
    def lineno(self) -> int:
        for item in self.instructions:
            line = getattr(item, "lineno", 0)
            if line:
                return line
        return 0


class CFG:
    """Граф одной области видимости: модуля, функции или метода."""

    def __init__(self, name: str, node: ast.AST) -> None:
        self.name = name
        self.node = node
        self.blocks: dict[int, BasicBlock] = {}
        self.entry: int = -1
        self.exit: int = -1

    def new_block(self, label: str = "") -> BasicBlock:
        block = BasicBlock(id=len(self.blocks), label=label)
        self.blocks[block.id] = block
        return block

    def connect(
        self,
        src: int,
        dst: int,
        condition: ast.expr | None = None,
        branch: bool | None = None,
    ) -> None:
        if any(e.target == dst and e.branch == branch for e in self.blocks[src].succs):
            return
        self.blocks[src].succs.append(Edge(dst, condition, branch))
        if src not in self.blocks[dst].preds:
            self.blocks[dst].preds.append(src)

    def reachable(self) -> set[int]:
        """Блоки, достижимые от входа. Остальное — мёртвый код."""
        seen: set[int] = set()
        stack = [self.entry]
        while stack:
            current = stack.pop()
            if current in seen:
                continue
            seen.add(current)
            stack.extend(edge.target for edge in self.blocks[current].succs)
        return seen

    def in_order(self) -> list[BasicBlock]:
        return [self.blocks[i] for i in sorted(self.blocks)]


class _LoopContext:
    def __init__(self, continue_target: int) -> None:
        self.continue_target = continue_target
        self.breaks: list[int] = []


class CFGBuilder:
    """Рекурсивно превращает список операторов в граф.

    Каждый метод обработки возвращает «бахрому» — блоки, из которых
    управление уходит к следующему оператору. Пустая бахрома означает,
    что все пути уже завершились (return, raise, break).
    """

    # Определения вложенных функций и классов не разворачиваются: для них
    # строится отдельный граф, иначе поток управления был бы искажён.
    _OPAQUE = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)

    def __init__(self, name: str, node: ast.AST) -> None:
        self.cfg = CFG(name, node)
        self._loops: list[_LoopContext] = []

    @classmethod
    def build(cls, name: str, node: ast.AST, body: list[ast.stmt]) -> CFG:
        builder = cls(name, node)
        cfg = builder.cfg
        entry = cfg.new_block("entry")
        cfg.entry = entry.id
        exit_block = cfg.new_block("exit")
        cfg.exit = exit_block.id
        fringe = builder._body(body, entry.id)
        for block_id in fringe:
            cfg.connect(block_id, cfg.exit)
        return cfg

    # --- обход -------------------------------------------------------------

    def _body(self, statements: list[ast.stmt], current: int) -> list[int]:
        fringe = [current]
        for stmt in statements:
            if not fringe:
                # Код недостижим, но разобрать его всё равно надо: правила
                # работают по AST, а отдельное правило сообщит о мёртвом коде.
                unreachable = self.cfg.new_block("unreachable")
                fringe = [unreachable.id]
            fringe = self._statement(stmt, fringe)
        return fringe

    def _statement(self, stmt: ast.stmt, fringe: list[int]) -> list[int]:
        handler = getattr(self, f"_on_{type(stmt).__name__.lower()}", None)
        if handler is None:
            return self._simple(stmt, fringe)
        return handler(stmt, fringe)

    def _merge(self, fringe: list[int], label: str = "") -> int:
        """Свести несколько путей в один блок."""
        if len(fringe) == 1:
            return fringe[0]
        joined = self.cfg.new_block(label or "join")
        for block_id in fringe:
            self.cfg.connect(block_id, joined.id)
        return joined.id

    def _simple(self, stmt: ast.stmt, fringe: list[int]) -> list[int]:
        target = self._merge(fringe)
        self.cfg.blocks[target].instructions.append(stmt)
        return [target]

    def _on_functiondef(self, stmt, fringe):
        return self._simple(stmt, fringe)

    _on_asyncfunctiondef = _on_functiondef
    _on_classdef = _on_functiondef

    def _on_if(self, stmt: ast.If, fringe: list[int]) -> list[int]:
        head = self._merge(fringe)
        self.cfg.blocks[head].instructions.append(Eval(stmt.test, stmt, "condition"))

        then_block = self.cfg.new_block("if-then")
        self.cfg.connect(head, then_block.id, stmt.test, True)
        then_fringe = self._body(stmt.body, then_block.id)

        else_block = self.cfg.new_block("if-else")
        self.cfg.connect(head, else_block.id, stmt.test, False)
        else_fringe = self._body(stmt.orelse, else_block.id) if stmt.orelse else [else_block.id]

        return then_fringe + else_fringe

    def _on_while(self, stmt: ast.While, fringe: list[int]) -> list[int]:
        head = self._merge(fringe)
        header = self.cfg.new_block("while-head")
        self.cfg.connect(head, header.id)
        header.instructions.append(Eval(stmt.test, stmt, "condition"))

        loop = _LoopContext(header.id)
        self._loops.append(loop)
        body_block = self.cfg.new_block("while-body")
        self.cfg.connect(header.id, body_block.id, stmt.test, True)
        body_fringe = self._body(stmt.body, body_block.id)
        self._loops.pop()

        for block_id in body_fringe:
            self.cfg.connect(block_id, header.id)  # обратное ребро

        exit_block = self.cfg.new_block("while-exit")
        self.cfg.connect(header.id, exit_block.id, stmt.test, False)
        result = [exit_block.id] + loop.breaks
        if stmt.orelse:
            result = self._body(stmt.orelse, exit_block.id) + loop.breaks
        return result

    def _on_for(self, stmt: ast.For, fringe: list[int]) -> list[int]:
        head = self._merge(fringe)
        header = self.cfg.new_block("for-head")
        self.cfg.connect(head, header.id)
        # Заголовок цикла присваивает цель значению из итератора.
        header.instructions.append(stmt)

        loop = _LoopContext(header.id)
        self._loops.append(loop)
        body_block = self.cfg.new_block("for-body")
        self.cfg.connect(header.id, body_block.id, None, True)
        body_fringe = self._body(stmt.body, body_block.id)
        self._loops.pop()

        for block_id in body_fringe:
            self.cfg.connect(block_id, header.id)

        exit_block = self.cfg.new_block("for-exit")
        self.cfg.connect(header.id, exit_block.id, None, False)
        result = [exit_block.id] + loop.breaks
        if stmt.orelse:
            result = self._body(stmt.orelse, exit_block.id) + loop.breaks
        return result

    _on_asyncfor = _on_for

    def _on_with(self, stmt: ast.With, fringe: list[int]) -> list[int]:
        head = self._merge(fringe)
        # Менеджер контекста — обычное присваивание: `with open(p) as f`.
        self.cfg.blocks[head].instructions.append(stmt)
        return self._body(stmt.body, head)

    _on_asyncwith = _on_with

    def _on_try(self, stmt: ast.Try, fringe: list[int]) -> list[int]:
        head = self._merge(fringe)
        body_block = self.cfg.new_block("try-body")
        self.cfg.connect(head, body_block.id)
        body_fringe = self._body(stmt.body, body_block.id)

        if stmt.orelse:
            body_fringe = self._body(stmt.orelse, self._merge(body_fringe, "try-else"))

        outgoing = list(body_fringe)
        for handler in stmt.handlers:
            handler_block = self.cfg.new_block("except")
            # Исключение может возникнуть в любой точке тела, поэтому
            # обработчик считается достижимым уже от входа в try.
            self.cfg.connect(head, handler_block.id)
            handler_block.instructions.append(Eval_handler(handler))
            outgoing += self._body(handler.body, handler_block.id)

        if stmt.finalbody:
            final_entry = self._merge(outgoing, "finally") if outgoing else self.cfg.new_block("finally").id
            outgoing = self._body(stmt.finalbody, final_entry)
        return outgoing

    def _on_trystar(self, stmt, fringe):
        return self._on_try(stmt, fringe)

    def _on_match(self, stmt: ast.Match, fringe: list[int]) -> list[int]:
        head = self._merge(fringe)
        self.cfg.blocks[head].instructions.append(Eval(stmt.subject, stmt, "subject"))
        outgoing: list[int] = []
        exhaustive = False
        for case in stmt.cases:
            case_block = self.cfg.new_block("case")
            self.cfg.connect(head, case_block.id)
            outgoing += self._body(case.body, case_block.id)
            if isinstance(case.pattern, ast.MatchAs) and case.pattern.pattern is None and case.guard is None:
                exhaustive = True  # `case _:` перехватывает всё
        if not exhaustive:
            fallthrough = self.cfg.new_block("match-exit")
            self.cfg.connect(head, fallthrough.id)
            outgoing.append(fallthrough.id)
        return outgoing

    def _on_return(self, stmt: ast.Return, fringe: list[int]) -> list[int]:
        target = self._merge(fringe)
        self.cfg.blocks[target].instructions.append(stmt)
        self.cfg.connect(target, self.cfg.exit)
        return []

    def _on_raise(self, stmt: ast.Raise, fringe: list[int]) -> list[int]:
        target = self._merge(fringe)
        self.cfg.blocks[target].instructions.append(stmt)
        self.cfg.connect(target, self.cfg.exit)
        return []

    def _on_break(self, stmt: ast.Break, fringe: list[int]) -> list[int]:
        target = self._merge(fringe)
        if self._loops:
            self._loops[-1].breaks.append(target)
        return []

    def _on_continue(self, stmt: ast.Continue, fringe: list[int]) -> list[int]:
        target = self._merge(fringe)
        if self._loops:
            self.cfg.connect(target, self._loops[-1].continue_target)
        return []


def Eval_handler(handler: ast.ExceptHandler) -> Eval:
    """Псевдо-инструкция входа в обработчик исключения."""
    placeholder = ast.Name(id=handler.name or "_exception", ctx=ast.Load())
    placeholder.lineno = handler.lineno
    placeholder.col_offset = handler.col_offset
    return Eval(placeholder, handler, "except")


def function_scopes(tree: ast.Module) -> list[tuple[str, ast.AST, list[ast.stmt]]]:
    """Все области видимости модуля: сам модуль и каждая функция отдельно."""
    scopes: list[tuple[str, ast.AST, list[ast.stmt]]] = [("<module>", tree, tree.body)]
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            scopes.append((node.name, node, node.body))
    return scopes


def build_all(tree: ast.Module) -> list[CFG]:
    return [CFGBuilder.build(name, node, body) for name, node, body in function_scopes(tree)]
