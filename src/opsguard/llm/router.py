"""Multi-provider router: retries with backoff, fallback chain, circuit breaker,
per-run cost budget and full telemetry (tokens, latency, cost per provider)."""

from __future__ import annotations

import math
import random
import statistics
import threading
import time
from dataclasses import dataclass, field

from .base import LLMProvider
from .pricing import model_info
from .tokens import count_messages
from .types import (
    BudgetExceededError,
    ContextLengthError,
    LLMError,
    LLMResponse,
    Message,
    ToolSpec,
)


@dataclass
class CallRecord:
    provider: str
    model: str
    agent: str
    ok: bool
    latency_ms: float
    input_tokens: int = 0
    output_tokens: int = 0
    cost_usd: float = 0.0
    error: str = ""


@dataclass
class Telemetry:
    records: list[CallRecord] = field(default_factory=list)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def add(self, rec: CallRecord) -> None:
        with self._lock:
            self.records.append(rec)

    @property
    def total_cost(self) -> float:
        return sum(r.cost_usd for r in self.records)

    def summary(self) -> dict:
        ok = [r for r in self.records if r.ok]
        lat = sorted(r.latency_ms for r in ok)
        by_provider: dict[str, dict] = {}
        for r in self.records:
            p = by_provider.setdefault(r.provider, {"calls": 0, "errors": 0, "cost_usd": 0.0, "tokens": 0})
            p["calls"] += 1
            p["errors"] += 0 if r.ok else 1
            p["cost_usd"] += r.cost_usd
            p["tokens"] += r.input_tokens + r.output_tokens
        return {
            "calls": len(self.records),
            "errors": len(self.records) - len(ok),
            "input_tokens": sum(r.input_tokens for r in ok),
            "output_tokens": sum(r.output_tokens for r in ok),
            "cost_usd": round(self.total_cost, 6),
            "latency_p50_ms": round(statistics.median(lat), 2) if lat else 0.0,
            "latency_p95_ms": round(lat[max(0, math.ceil(0.95 * len(lat)) - 1)], 2) if lat else 0.0,
            "by_provider": by_provider,
        }


class CircuitBreaker:
    """Opens after `threshold` consecutive failures; half-opens after `cooldown_s`."""

    def __init__(self, threshold: int = 3, cooldown_s: float = 30.0):
        self.threshold, self.cooldown_s = threshold, cooldown_s
        self.failures, self.opened_at = 0, 0.0

    def allow(self) -> bool:
        if self.failures < self.threshold:
            return True
        return time.monotonic() - self.opened_at > self.cooldown_s

    def record(self, ok: bool) -> None:
        if ok:
            self.failures = 0
        else:
            self.failures += 1
            if self.failures >= self.threshold:
                self.opened_at = time.monotonic()


class LLMRouter:
    """Single entry point used by every agent. Providers are tried in order."""

    def __init__(
        self,
        providers: list[LLMProvider],
        max_retries: int = 3,
        base_backoff_s: float = 0.5,
        budget_usd: float | None = None,
        max_concurrency: int = 4,
    ):
        if not providers:
            raise ValueError("at least one provider is required")
        self.providers = providers
        self.max_retries = max_retries
        self.base_backoff_s = base_backoff_s
        self.budget_usd = budget_usd
        self.telemetry = Telemetry()
        # Everything that leaves the perimeter towards an LLM API (audited by the red team
        # harness to prove that customer PII / secrets never reach a third-party provider).
        self.egress_log: list[str] = []
        self._breakers = {id(p): CircuitBreaker() for p in providers}
        self._sem = threading.Semaphore(max_concurrency)  # protects provider rate limits

    def _backoff(self, attempt: int) -> float:
        return self.base_backoff_s * (2**attempt) * (0.5 + random.random() / 2)

    def complete(
        self,
        messages: list[Message],
        tools: list[ToolSpec] | None = None,
        agent: str = "unknown",
        **kwargs,
    ) -> LLMResponse:
        if self.budget_usd is not None and self.telemetry.total_cost >= self.budget_usd:
            raise BudgetExceededError(f"budget of ${self.budget_usd} exhausted")

        prompt_tokens = count_messages(messages)
        self.egress_log.append("\n".join(m.content for m in messages))
        last_error: Exception | None = None
        for provider in self.providers:
            breaker = self._breakers[id(provider)]
            if not breaker.allow():
                continue
            # pre-flight check: skip providers whose context window is too small
            if prompt_tokens > model_info(provider.model).context_window:
                last_error = ContextLengthError(f"{prompt_tokens} tokens > {provider.model} window")
                continue
            for attempt in range(self.max_retries + 1):
                start = time.perf_counter()
                try:
                    with self._sem:
                        resp = provider.complete(messages, tools, **kwargs)
                except LLMError as e:
                    last_error = e
                    breaker.record(False)
                    self.telemetry.add(
                        CallRecord(provider.name, provider.model, agent, False, (time.perf_counter() - start) * 1000, error=type(e).__name__)
                    )
                    if not e.retryable:
                        break  # go to next provider
                    if attempt < self.max_retries:
                        time.sleep(self._backoff(attempt))
                    continue
                breaker.record(True)
                self.telemetry.add(
                    CallRecord(
                        provider.name, resp.model, agent, True, resp.latency_ms,
                        resp.usage.input_tokens, resp.usage.output_tokens, resp.cost_usd,
                    )
                )
                return resp
        raise LLMError(f"all providers failed; last error: {last_error!r}")
