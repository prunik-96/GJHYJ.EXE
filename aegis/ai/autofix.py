"""Генерация исправлений моделью под контролем анализатора.

Схема работы — «генератор и проверяющий»:

    находка -> запрос к модели -> патч -> ПРОВЕРКА -> принять или отклонить
                     ^                                      |
                     +------- причина отказа ---------------+

Ненадёжность модели здесь безвредна: неверный патч не проходит проверку и
не попадает в код. При отказе причина возвращается модели, и та пробует
снова — обычно этого хватает, потому что отказ содержит конкретику
(«появилось AEG-INJ-003», «затронуто 80 строк»), а не общее «неправильно».
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field

from ..core.findings import Finding
from .provider import DEFAULT_MAX_TOKENS, LLMProvider, LLMUnavailable
from .verify import PatchVerifier, VerificationResult

MAX_ATTEMPTS = 3
MAX_SOURCE_CHARS = 60_000

SYSTEM_PROMPT = """\
Ты — инженер по безопасности, который правит код на Python.

Тебе дают файл и одну конкретную находку статического анализатора.
Твоя задача — устранить именно эту проблему, сохранив поведение программы.

Жёсткие требования:
1. Меняй минимум строк. Не переписывай файл, не переформатируй его, \
не переименовывай то, что не относится к проблеме.
2. Никогда не добавляй комментарии подавления (# aegis: ignore, # noqa, # nosec). \
Это не исправление.
3. Никогда не удаляй функциональность, чтобы убрать находку. Код должен \
продолжать делать то же, что делал.
4. Не создавай новых проблем безопасности.
5. Сохрани все определения верхнего уровня.

Ответ — только полный текст изменённого файла в одном блоке ```python.
Без пояснений до или после блока."""


@dataclass
class Attempt:
    """Одна попытка исправления."""

    number: int
    patch: str | None
    result: VerificationResult | None
    error: str | None = None

    @property
    def accepted(self) -> bool:
        return self.result is not None and self.result.accepted


@dataclass
class FixOutcome:
    """Итог работы над одной находкой."""

    finding: Finding
    patch: str | None = None
    attempts: list[Attempt] = field(default_factory=list)

    @property
    def success(self) -> bool:
        return self.patch is not None

    def explain(self) -> str:
        if self.success:
            return f"исправление принято с попытки {len(self.attempts)}"
        if not self.attempts:
            return "попыток не было"
        last = self.attempts[-1]
        if last.error:
            return f"не удалось: {last.error}"
        return f"не удалось за {len(self.attempts)} попыт(ки): {last.result.summary()}"


def _normalize(code: str) -> str:
    """Убрать обрамляющие пустые строки, но сохранить перевод строки в конце.

    Файл без завершающего перевода строки — мелкая, но настоящая порча:
    её заметит любой инструмент, работающий с diff.
    """
    return code.strip("\n").rstrip() + "\n"


def extract_code(response: str) -> str | None:
    """Достать код из ответа модели.

    Модель просят вернуть блок ```python. Если рамок нет, но весь ответ
    сам по себе разбирается как Python, принимаем и его — это лучше, чем
    отбрасывать корректный патч из-за оформления.
    """
    fenced = re.findall(r"```(?:python|py)?\s*\n(.*?)```", response, re.DOTALL)
    for block in fenced:
        candidate = _normalize(block)
        try:
            ast.parse(candidate)
            return candidate
        except SyntaxError:
            continue
    if fenced:
        return _normalize(fenced[0])  # отдадим на проверку — она и отклонит
    stripped = _normalize(response)
    try:
        ast.parse(stripped)
        return stripped
    except SyntaxError:
        return None


def build_request(source: str, finding: Finding, previous_failure: str | None = None) -> str:
    """Составить запрос к модели по одной находке."""
    trace = "\n".join(f"  строка {step.line}: {step.description}" for step in finding.trace)
    parts = [
        f"Файл: {finding.path}",
        "",
        "НАХОДКА",
        f"  правило:  {finding.rule_id} — {finding.title}",
        f"  строка:   {finding.line}",
        f"  суть:     {finding.message}",
    ]
    if finding.cwe:
        parts.append(f"  класс:    {finding.cwe}")
    if trace:
        parts += ["  путь данных:", trace]
    if finding.remediation:
        parts += ["", f"РЕКОМЕНДАЦИЯ АНАЛИЗАТОРА: {finding.remediation}"]
    if previous_failure:
        parts += [
            "",
            "ПРЕДЫДУЩАЯ ПОПЫТКА ОТКЛОНЕНА АНАЛИЗАТОРОМ:",
            f"  {previous_failure}",
            "Учти причину отказа и предложи другое исправление.",
        ]
    parts += ["", "ИСХОДНЫЙ ФАЙЛ", "```python", source[:MAX_SOURCE_CHARS], "```"]
    return "\n".join(parts)


class AutoFixer:
    """Цикл «предложить — проверить — при отказе повторить»."""

    def __init__(
        self,
        provider: LLMProvider,
        analyzer,
        max_attempts: int = MAX_ATTEMPTS,
        line_budget: int | None = None,
    ) -> None:
        self.provider = provider
        self.analyzer = analyzer
        self.max_attempts = max_attempts
        self.verifier = (
            PatchVerifier(analyzer, line_budget) if line_budget else PatchVerifier(analyzer)
        )

    def fix(self, source: str, finding: Finding) -> FixOutcome:
        outcome = FixOutcome(finding=finding)
        failure_note: str | None = None

        for number in range(1, self.max_attempts + 1):
            request = build_request(source, finding, failure_note)
            try:
                raw = self.provider.complete(SYSTEM_PROMPT, request, DEFAULT_MAX_TOKENS)
            except LLMUnavailable as error:
                outcome.attempts.append(Attempt(number, None, None, str(error)))
                return outcome

            patch = extract_code(raw)
            if patch is None:
                failure_note = "в ответе не найден блок кода на Python"
                outcome.attempts.append(Attempt(number, None, None, failure_note))
                continue

            result = self.verifier.verify(source, patch, finding, finding.path)
            outcome.attempts.append(Attempt(number, patch, result))
            if result.accepted:
                outcome.patch = patch
                return outcome
            failure_note = result.summary()

        return outcome

    def fix_all(self, source: str, findings: list[Finding]) -> list[FixOutcome]:
        """Обработать несколько находок, применяя принятые патчи по очереди.

        Каждое следующее исправление строится поверх уже принятых, поэтому
        патчи не конфликтуют между собой.
        """
        current = source
        outcomes: list[FixOutcome] = []
        for finding in findings:
            outcome = self.fix(current, finding)
            outcomes.append(outcome)
            if outcome.success:
                current = outcome.patch
        return outcomes

    @staticmethod
    def final_source(source: str, outcomes: list[FixOutcome]) -> str:
        for outcome in reversed(outcomes):
            if outcome.success:
                return outcome.patch
        return source
