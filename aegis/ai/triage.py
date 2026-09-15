"""Разбор находок моделью: объяснение и оценка правдоподобия.

Здесь действует жёсткое ограничение: **модель не может отменить находку**.
Она добавляет пометку и объяснение, но список находок остаётся ровно тем,
который выдал анализатор.

Причина простая. Анализатор ошибается предсказуемо: правило либо покрывает
случай, либо нет, и это проверяется. Модель ошибается непредсказуемо и при
этом убедительно формулирует. Дать ей право вычёркивать — значит поставить
между разработчиком и настоящей уязвимостью текст, который звучит уверенно
и ничем не подкреплён. Поэтому пометка справочная, а решение — за человеком.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass

from ..core.findings import Finding
from .provider import LLMProvider, LLMUnavailable

CONFIRMED = "подтверждено"
UNCERTAIN = "неоднозначно"
LIKELY_FALSE = "вероятно ложное"

_VERDICTS = {
    "confirmed": CONFIRMED,
    "uncertain": UNCERTAIN,
    "likely_false_positive": LIKELY_FALSE,
}

CONTEXT_LINES = 25

SYSTEM_PROMPT = """\
Ты — инженер по безопасности. Тебе дают находку статического анализатора \
и фрагмент кода вокруг неё.

Оцени, является ли находка реальной проблемой именно в этом контексте, \
и объясни это коротко и по существу — так, чтобы разработчик понял, \
что делать.

Ответ строго в формате JSON, без текста вокруг:
{"verdict": "confirmed" | "uncertain" | "likely_false_positive",
 "reason": "одно-два предложения по-русски",
 "impact": "что произойдёт при эксплуатации, одно предложение"}

Указания:
- "confirmed" — данные действительно доходят до опасной операции;
- "likely_false_positive" — в этом контексте эксплуатация невозможна \
(например, значение задаётся только в коде и недоступно извне);
- "uncertain" — из фрагмента нельзя сделать вывод.
Не преуменьшай риск, если сомневаешься: в этом случае выбирай "uncertain"."""


@dataclass(frozen=True)
class TriageNote:
    verdict: str
    reason: str
    impact: str = ""

    def as_notes(self) -> dict[str, str]:
        notes = {"ai_verdict": self.verdict, "ai_reason": self.reason}
        if self.impact:
            notes["ai_impact"] = self.impact
        return notes


def _context(source: str, finding: Finding, radius: int = CONTEXT_LINES) -> str:
    lines = source.splitlines()
    start = max(finding.line - radius - 1, 0)
    end = min(finding.line + radius, len(lines))
    numbered = [f"{number:5} {lines[number - 1]}" for number in range(start + 1, end + 1)]
    return "\n".join(numbered)


def build_request(source: str, finding: Finding) -> str:
    trace = "\n".join(f"  строка {step.line}: {step.description}" for step in finding.trace)
    parts = [
        "НАХОДКА",
        f"  правило:  {finding.rule_id} — {finding.title}",
        f"  уровень:  {finding.severity}",
        f"  место:    {finding.path}:{finding.line}",
        f"  суть:     {finding.message}",
    ]
    if trace:
        parts += ["  путь данных:", trace]
    parts += ["", "КОД", "```python", _context(source, finding), "```"]
    return "\n".join(parts)


def parse_note(raw: str) -> TriageNote | None:
    """Разобрать ответ модели. Любая неожиданность — отсутствие пометки."""
    match = re.search(r"\{.*\}", raw, re.DOTALL)
    if match is None:
        return None
    try:
        payload = json.loads(match.group(0))
    except (json.JSONDecodeError, ValueError):
        return None
    if not isinstance(payload, dict):
        return None
    verdict = _VERDICTS.get(str(payload.get("verdict", "")).strip().lower())
    reason = payload.get("reason")
    if verdict is None or not isinstance(reason, str) or not reason.strip():
        return None
    impact = payload.get("impact")
    return TriageNote(
        verdict=verdict,
        reason=reason.strip()[:500],
        impact=impact.strip()[:500] if isinstance(impact, str) else "",
    )


class Triager:
    """Добавляет к находкам пояснения модели, ничего не убирая."""

    def __init__(self, provider: LLMProvider, max_findings: int = 25) -> None:
        self.provider = provider
        self.max_findings = max_findings

    def review(self, source: str, finding: Finding) -> TriageNote | None:
        try:
            raw = self.provider.complete(SYSTEM_PROMPT, build_request(source, finding), 2000)
        except LLMUnavailable:
            return None
        return parse_note(raw)

    def annotate(self, source: str, findings: list[Finding]) -> list[Finding]:
        """Проставить пометки. Длина списка гарантированно не меняется.

        Разбираются только самые опасные находки — остальные остаются как есть.
        """
        ordered = sorted(findings, key=lambda f: f.sort_key())
        for finding in ordered[: self.max_findings]:
            note = self.review(source, finding)
            if note is not None:
                finding.notes.update(note.as_notes())
        return findings
