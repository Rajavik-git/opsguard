"""Provider-agnostic data model shared by every LLM backend."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

Role = Literal["system", "user", "assistant", "tool"]


@dataclass
class ToolCall:
    id: str
    name: str
    arguments: dict[str, Any]


@dataclass
class Message:
    role: Role
    content: str = ""
    tool_calls: list[ToolCall] = field(default_factory=list)
    tool_call_id: str | None = None
    name: str | None = None  # tool name for role="tool"


@dataclass
class ToolSpec:
    """JSON-schema tool definition, translated per provider."""

    name: str
    description: str
    parameters: dict[str, Any]


@dataclass
class Usage:
    input_tokens: int = 0
    output_tokens: int = 0

    @property
    def total(self) -> int:
        return self.input_tokens + self.output_tokens


@dataclass
class LLMResponse:
    content: str
    tool_calls: list[ToolCall]
    usage: Usage
    model: str
    provider: str
    latency_ms: float = 0.0
    cost_usd: float = 0.0
    finish_reason: str = "stop"


class LLMError(Exception):
    """Base error. `retryable` drives the router's retry/fallback logic."""

    retryable: bool = False


class RateLimitError(LLMError):
    retryable = True


class TransientError(LLMError):
    retryable = True


class ContextLengthError(LLMError):
    retryable = False


class BudgetExceededError(LLMError):
    retryable = False
