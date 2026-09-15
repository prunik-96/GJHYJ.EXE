"""Доступ к языковой модели — с возможностью работать полностью без сети.

Движок не зависит от конкретной модели: ему нужен объект с одним методом
``complete``. Это нужно не ради абстракции как таковой, а чтобы вся логика
проверки тестировалась без обращения к внешнему сервису и без ключа.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol

DEFAULT_MODEL = "claude-opus-5"
DEFAULT_MAX_TOKENS = 16000


class LLMUnavailable(RuntimeError):
    """Модель недоступна: нет ключа, нет пакета или сервис не ответил."""


class LLMProvider(Protocol):
    """Минимальный контракт: текст на входе, текст на выходе."""

    def complete(self, system: str, user: str, max_tokens: int = DEFAULT_MAX_TOKENS) -> str:
        ...


class AnthropicProvider:
    """Обращение к Claude через официальный SDK.

    Пакет ``anthropic`` импортируется лениво: без него остальной анализатор
    обязан работать как прежде.
    """

    def __init__(
        self,
        model: str = DEFAULT_MODEL,
        effort: str = "high",
        api_key: str | None = None,
    ) -> None:
        self.model = model
        self.effort = effort
        self._api_key = api_key
        self._client = None

    def _ensure_client(self):
        if self._client is not None:
            return self._client
        try:
            import anthropic
        except ImportError as error:
            raise LLMUnavailable(
                "не установлен пакет anthropic — выполните: pip install anthropic"
            ) from error
        try:
            self._client = (
                anthropic.Anthropic(api_key=self._api_key)
                if self._api_key
                else anthropic.Anthropic()
            )
        except Exception as error:  # ключ не найден, неверная конфигурация
            raise LLMUnavailable(f"не удалось создать клиент: {error}") from error
        return self._client

    def complete(self, system: str, user: str, max_tokens: int = DEFAULT_MAX_TOKENS) -> str:
        client = self._ensure_client()
        try:
            import anthropic
        except ImportError as error:  # pragma: no cover — уже проверено выше
            raise LLMUnavailable(str(error)) from error

        try:
            response = client.messages.create(
                model=self.model,
                max_tokens=max_tokens,
                system=system,
                thinking={"type": "adaptive"},
                output_config={"effort": self.effort},
                messages=[{"role": "user", "content": user}],
            )
        except anthropic.APIStatusError as error:
            raise LLMUnavailable(f"сервис ответил ошибкой {error.status_code}") from error
        except anthropic.APIConnectionError as error:
            raise LLMUnavailable(f"нет связи с сервисом: {error}") from error

        if response.stop_reason == "refusal":
            raise LLMUnavailable("модель отказалась отвечать на запрос")

        # В ответе рядом с текстом могут лежать блоки размышлений — берём только текст.
        parts = [block.text for block in response.content if block.type == "text"]
        if not parts:
            raise LLMUnavailable("модель вернула пустой ответ")
        return "\n".join(parts)


@dataclass
class ScriptedProvider:
    """Подставная модель для тестов и отладки.

    Отдаёт заранее заготовленные ответы по очереди и запоминает запросы.
    Позволяет проверить в том числе враждебные сценарии: модель вернула мусор,
    сломала код или попыталась заглушить находку вместо исправления.
    """

    responses: list[str] = field(default_factory=list)
    calls: list[tuple[str, str]] = field(default_factory=list)
    default: str | None = None

    def complete(self, system: str, user: str, max_tokens: int = DEFAULT_MAX_TOKENS) -> str:
        self.calls.append((system, user))
        if self.responses:
            return self.responses.pop(0)
        if self.default is not None:
            return self.default
        raise LLMUnavailable("у подставной модели закончились заготовленные ответы")


def build_provider(model: str = DEFAULT_MODEL, effort: str = "high") -> LLMProvider:
    return AnthropicProvider(model=model, effort=effort)
