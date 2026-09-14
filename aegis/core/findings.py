"""Модель результата анализа: находка, уровень риска, уверенность."""

from __future__ import annotations

import enum
from dataclasses import dataclass, field


class Severity(enum.IntEnum):
    """Уровень опасности. Порядок важен — по нему идёт сортировка и фильтрация."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, raw: str) -> "Severity":
        try:
            return cls[raw.strip().upper()]
        except KeyError:
            valid = ", ".join(s.name.lower() for s in cls)
            raise ValueError(f"неизвестный уровень {raw!r}, доступны: {valid}") from None

    def __str__(self) -> str:
        return self.name.lower()


class Confidence(enum.IntEnum):
    """Насколько движок уверен, что это не ложное срабатывание."""

    LOW = 0
    MEDIUM = 1
    HIGH = 2

    def __str__(self) -> str:
        return self.name.lower()


@dataclass(frozen=True)
class TraceStep:
    """Один шаг в объяснении находки — например, где данные стали грязными."""

    line: int
    description: str


@dataclass
class Finding:
    """Одна проблема в коде.

    Кроме места и описания несёт `trace` — цепочку рассуждений движка.
    Именно она отличает анализатор от grep: пользователь видит, почему
    код признан опасным, и может проверить вывод сам.
    """

    rule_id: str
    title: str
    message: str
    severity: Severity
    confidence: Confidence
    path: str
    line: int
    column: int = 0
    end_line: int | None = None
    cwe: str | None = None
    category: str = "general"
    remediation: str | None = None
    trace: list[TraceStep] = field(default_factory=list)
    snippet: str | None = None

    @property
    def location(self) -> str:
        return f"{self.path}:{self.line}:{self.column}"

    def sort_key(self) -> tuple:
        # Сначала самое опасное и самое достоверное, затем стабильный порядок по месту.
        return (-self.severity, -self.confidence, self.path, self.line, self.rule_id)

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "message": self.message,
            "severity": str(self.severity),
            "confidence": str(self.confidence),
            "path": self.path,
            "line": self.line,
            "column": self.column,
            "end_line": self.end_line,
            "cwe": self.cwe,
            "category": self.category,
            "remediation": self.remediation,
            "trace": [{"line": s.line, "description": s.description} for s in self.trace],
            "snippet": self.snippet,
        }
