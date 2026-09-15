"""Проверка исправления, предложенного языковой моделью.

Это узел, ради которого вся связка имеет смысл. Модель умеет предлагать
правдоподобный код, но не умеет гарантировать, что он верен. Анализатор,
наоборот, ничего не сочиняет — и может проверить предложение объективно.

Патч принимается, только если проходит все проверки разом:

1. разбирается синтаксически;
2. исходная находка действительно исчезла;
3. не появилось новых находок;
4. набор определений верхнего уровня не изменился;
5. правка локальна, а не переписывание файла целиком;
6. проблема решена, а не заглушена и не вырезана вместе с кодом.

Шестая проверка — не паранойя. Самый простой способ «убрать находку» —
дописать комментарий подавления или удалить опасную строку вместе с
функциональностью. И то и другое выглядит как успех, но им не является.
"""

from __future__ import annotations

import ast
import difflib
from dataclasses import dataclass, field

from ..core.findings import Finding

# Доля операторов, ниже которой правка считается вырезанием кода.
MIN_STATEMENT_RATIO = 0.7

# Сколько строк может затронуть точечное исправление.
DEFAULT_LINE_BUDGET = 40

SUPPRESSION_MARKERS = ("# aegis:", "#aegis:", "# noqa", "#noqa", "# type: ignore", "# nosec")


@dataclass
class Check:
    name: str
    passed: bool
    detail: str


@dataclass
class VerificationResult:
    """Итог проверки патча с полной расшифровкой."""

    accepted: bool
    checks: list[Check] = field(default_factory=list)
    resolved: list[Finding] = field(default_factory=list)
    introduced: list[Finding] = field(default_factory=list)
    diff: str = ""

    @property
    def failures(self) -> list[Check]:
        return [check for check in self.checks if not check.passed]

    def summary(self) -> str:
        if self.accepted:
            return "патч принят: все проверки пройдены"
        причины = "; ".join(f"{c.name} — {c.detail}" for c in self.failures)
        return f"патч отклонён: {причины}"


def _signature(finding: Finding) -> tuple[str, str]:
    """Признак находки, устойчивый к сдвигу строк после правки."""
    return (finding.rule_id, finding.message)


def _counts(findings: list[Finding]) -> dict[tuple[str, str], int]:
    result: dict[tuple[str, str], int] = {}
    for finding in findings:
        key = _signature(finding)
        result[key] = result.get(key, 0) + 1
    return result


def _top_level_names(tree: ast.Module) -> set[str]:
    names: set[str] = set()
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.add(node.name)
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    names.add(target.id)
    return names


def _statement_count(tree: ast.Module) -> int:
    return sum(1 for node in ast.walk(tree) if isinstance(node, ast.stmt))


def _function_bodies(tree: ast.Module) -> dict[str, int]:
    """Число операторов в теле каждой функции.

    Общей доли по файлу недостаточно: тело одной функции можно выпотрошить
    до ``pass``, и на фоне остального файла падение будет незаметным.
    Находка при этом исчезнет — вместе с функциональностью.
    """
    counts: dict[str, int] = {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            counts[node.name] = sum(
                1 for child in ast.walk(node) if isinstance(child, ast.stmt)
            ) - 1  # сам def не считаем
    return counts


def _added_lines(original: str, patched: str) -> list[str]:
    diff = difflib.unified_diff(original.splitlines(), patched.splitlines(), lineterm="", n=0)
    return [line[1:] for line in diff if line.startswith("+") and not line.startswith("+++")]


def _changed_line_count(original: str, patched: str) -> int:
    matcher = difflib.SequenceMatcher(None, original.splitlines(), patched.splitlines())
    changed = 0
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag != "equal":
            changed += max(i2 - i1, j2 - j1)
    return changed


class PatchVerifier:
    """Пропускает патч через все проверки и выносит решение."""

    def __init__(self, analyzer, line_budget: int = DEFAULT_LINE_BUDGET) -> None:
        self.analyzer = analyzer
        self.line_budget = line_budget

    def verify(
        self,
        original: str,
        patched: str,
        target: Finding,
        path: str = "patched.py",
    ) -> VerificationResult:
        checks: list[Check] = []

        if patched.strip() == original.strip():
            checks.append(Check("изменения", False, "патч ничего не меняет"))
            return VerificationResult(False, checks)

        # 1. Синтаксис.
        try:
            patched_tree = ast.parse(patched)
        except SyntaxError as error:
            checks.append(Check("синтаксис", False, f"код не разбирается: {error.msg} (строка {error.lineno})"))
            return VerificationResult(False, checks, diff=self._diff(original, patched))
        checks.append(Check("синтаксис", True, "код разбирается"))

        original_tree = ast.parse(original)

        # 6a. Подавление вместо исправления.
        added = _added_lines(original, patched)
        suppressions = [
            line.strip()
            for line in added
            if any(marker in line.lower() for marker in SUPPRESSION_MARKERS)
        ]
        if suppressions:
            checks.append(Check(
                "подавление",
                False,
                f"добавлен комментарий подавления вместо исправления: {suppressions[0]!r}",
            ))
        else:
            checks.append(Check("подавление", True, "комментарии подавления не добавлялись"))

        # 6b. Код не вырезан — ни по файлу в целом, ни в отдельной функции.
        before, after = _statement_count(original_tree), _statement_count(patched_tree)
        gutted: list[str] = []
        if after < before * MIN_STATEMENT_RATIO:
            gutted.append(f"по файлу операторов было {before}, стало {after}")
        before_bodies = _function_bodies(original_tree)
        after_bodies = _function_bodies(patched_tree)
        for name, size in before_bodies.items():
            if name not in after_bodies:
                continue
            if size and after_bodies[name] < size * MIN_STATEMENT_RATIO:
                gutted.append(f"тело {name}() сжалось с {size} до {after_bodies[name]} операторов")
        if gutted:
            checks.append(Check(
                "сохранность кода",
                False,
                "; ".join(gutted) + " — похоже на удаление функциональности",
            ))
        else:
            checks.append(Check("сохранность кода", True, f"операторов было {before}, стало {after}"))

        # 4. Определения верхнего уровня.
        lost = _top_level_names(original_tree) - _top_level_names(patched_tree)
        if lost:
            checks.append(Check(
                "структура",
                False,
                f"исчезли определения верхнего уровня: {', '.join(sorted(lost))}",
            ))
        else:
            checks.append(Check("структура", True, "все определения на месте"))

        # 5. Локальность правки.
        changed = _changed_line_count(original, patched)
        if changed > self.line_budget:
            checks.append(Check(
                "локальность",
                False,
                f"затронуто строк: {changed}, допустимо {self.line_budget}",
            ))
        else:
            checks.append(Check("локальность", True, f"затронуто строк: {changed}"))

        # 2 и 3. Что говорит сам анализатор о новом коде.
        before_findings = self.analyzer.analyze_source(original, path)
        after_findings = self.analyzer.analyze_source(patched, path)
        before_counts, after_counts = _counts(before_findings), _counts(after_findings)

        key = _signature(target)
        if after_counts.get(key, 0) < before_counts.get(key, 0):
            checks.append(Check("находка устранена", True, f"{target.rule_id} больше не срабатывает"))
        else:
            checks.append(Check(
                "находка устранена",
                False,
                f"{target.rule_id} по-прежнему срабатывает",
            ))

        introduced = [
            finding
            for finding in after_findings
            if after_counts.get(_signature(finding), 0) > before_counts.get(_signature(finding), 0)
            and _signature(finding) != key
        ]
        if introduced:
            names = ", ".join(sorted({f.rule_id for f in introduced}))
            checks.append(Check("новые проблемы", False, f"появились новые находки: {names}"))
        else:
            checks.append(Check("новые проблемы", True, "новых находок нет"))

        resolved = [
            finding
            for finding in before_findings
            if after_counts.get(_signature(finding), 0) < before_counts.get(_signature(finding), 0)
        ]

        accepted = all(check.passed for check in checks)
        return VerificationResult(
            accepted=accepted,
            checks=checks,
            resolved=resolved,
            introduced=introduced,
            diff=self._diff(original, patched),
        )

    @staticmethod
    def _diff(original: str, patched: str) -> str:
        return "\n".join(
            difflib.unified_diff(
                original.splitlines(),
                patched.splitlines(),
                fromfile="до",
                tofile="после",
                lineterm="",
            )
        )
