"""Универсальный решатель задач потока данных.

Классический worklist-алгоритм с поиском неподвижной точки. Конкретный
анализ задаёт три вещи: начальное состояние, функцию переноса (как оператор
меняет состояние) и функцию слияния (что получается, когда в блок сходятся
несколько путей).

Циклы обходятся повторным проходом, пока состояния не перестанут меняться.
Жёсткий лимит раундов защищает от случая, когда решётка состояний оказалась
не вполне корректной: лучше отдать приближённый результат, чем зависнуть.
"""

from __future__ import annotations

from typing import Callable, TypeVar

from .cfg import CFG, BasicBlock, Edge

State = TypeVar("State")

TransferFn = Callable[[BasicBlock, "State"], "State"]
JoinFn = Callable[[list["State"]], "State"]
EdgeFn = Callable[[Edge, "State"], "State"]

MAX_ROUNDS_PER_BLOCK = 24


class DataflowResult:
    """Состояния на входе и выходе каждого блока."""

    def __init__(self, entry_states: dict[int, State], exit_states: dict[int, State]) -> None:
        self.entry_states = entry_states
        self.exit_states = exit_states

    def at_entry(self, block_id: int, default: State = None) -> State:
        return self.entry_states.get(block_id, default)

    def at_exit(self, block_id: int, default: State = None) -> State:
        return self.exit_states.get(block_id, default)


def solve_forward(
    cfg: CFG,
    initial: State,
    transfer: TransferFn,
    join: JoinFn,
    edge_transfer: EdgeFn | None = None,
    empty: Callable[[], State] | None = None,
) -> DataflowResult:
    """Прямой анализ: состояние течёт от входа к выходу.

    ``edge_transfer`` позволяет уточнить состояние на конкретной ветке —
    так реализуется чувствительность к условиям (``if x is not None``).
    """
    make_empty = empty or (lambda: type(initial)())
    entry_states: dict[int, State] = {}
    exit_states: dict[int, State] = {}

    reachable = cfg.reachable()
    order = [b for b in sorted(cfg.blocks) if b in reachable]
    worklist: list[int] = list(order)
    in_list = set(worklist)
    budget = max(len(order) * MAX_ROUNDS_PER_BLOCK, 64)

    while worklist and budget > 0:
        budget -= 1
        block_id = worklist.pop(0)
        in_list.discard(block_id)
        block = cfg.blocks[block_id]

        if block_id == cfg.entry:
            incoming = initial
        else:
            contributions: list[State] = []
            for pred_id in block.preds:
                if pred_id not in exit_states:
                    continue
                state = exit_states[pred_id]
                if edge_transfer is not None:
                    for edge in cfg.blocks[pred_id].succs:
                        if edge.target == block_id:
                            state = edge_transfer(edge, state)
                            break
                contributions.append(state)
            incoming = join(contributions) if contributions else make_empty()

        entry_states[block_id] = incoming
        outgoing = transfer(block, incoming)

        if block_id in exit_states and exit_states[block_id] == outgoing:
            continue  # состояние стабилизировалось — соседей будить не нужно
        exit_states[block_id] = outgoing
        for edge in block.succs:
            if edge.target in reachable and edge.target not in in_list:
                worklist.append(edge.target)
                in_list.add(edge.target)

    return DataflowResult(entry_states, exit_states)


def merge_maps(states: list[dict], combine: Callable[[object, object], object]) -> dict:
    """Слияние словарей-состояний: ключ из любой ветки попадает в результат.

    Отсутствие ключа означает «значение по умолчанию», поэтому ключ,
    пришедший лишь по одной ветке, сохраняется — это консервативно и
    именно то, что нужно для поиска уязвимостей: пропустить реальную
    проблему хуже, чем лишний раз её показать.
    """
    if not states:
        return {}
    result: dict = dict(states[0])
    for state in states[1:]:
        for key, value in state.items():
            if key in result:
                result[key] = combine(result[key], value)
            else:
                result[key] = value
    return result
