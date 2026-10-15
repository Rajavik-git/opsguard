"""Abstract provider interface: every backend implements `_complete`."""

from __future__ import annotations

import time
from abc import ABC, abstractmethod

from .pricing import cost_usd
from .types import LLMResponse, Message, ToolSpec


class LLMProvider(ABC):
    name: str = "base"

    def __init__(self, model: str, timeout_s: float = 60.0):
        self.model = model
        self.timeout_s = timeout_s

    def complete(
        self,
        messages: list[Message],
        tools: list[ToolSpec] | None = None,
        temperature: float = 0.0,
        max_output_tokens: int = 1024,
        json_mode: bool = False,
    ) -> LLMResponse:
        start = time.perf_counter()
        resp = self._complete(messages, tools or [], temperature, max_output_tokens, json_mode)
        resp.latency_ms = (time.perf_counter() - start) * 1000
        resp.cost_usd = cost_usd(resp.model, resp.usage.input_tokens, resp.usage.output_tokens)
        return resp

    @abstractmethod
    def _complete(
        self,
        messages: list[Message],
        tools: list[ToolSpec],
        temperature: float,
        max_output_tokens: int,
        json_mode: bool,
    ) -> LLMResponse: ...
