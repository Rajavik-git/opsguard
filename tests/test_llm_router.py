import pytest

from opsguard.llm import LLMError, LLMRouter, Message, MockSREProvider
from opsguard.llm.base import LLMProvider
from opsguard.llm.pricing import cost_usd
from opsguard.llm.tokens import truncate_to_tokens
from opsguard.llm.types import BudgetExceededError, LLMResponse, RateLimitError, Usage


class FlakyProvider(LLMProvider):
    """Fails `n` times with a retryable error, then succeeds."""

    name = "flaky"

    def __init__(self, failures: int, error=RateLimitError, model="gpt-4.1-mini"):
        super().__init__(model)
        self.failures, self.error, self.calls = failures, error, 0

    def _complete(self, *a, **k):
        self.calls += 1
        if self.calls <= self.failures:
            raise self.error("boom")
        return LLMResponse("ok", [], Usage(1000, 100), self.model, self.name)


MSGS = [Message("system", "hi"), Message("user", "ping")]


def test_retry_then_success():
    p = FlakyProvider(failures=2)
    r = LLMRouter([p], max_retries=3, base_backoff_s=0)
    assert r.complete(MSGS).content == "ok"
    assert p.calls == 3
    assert r.telemetry.summary()["errors"] == 2


def test_fallback_to_next_provider():
    bad = FlakyProvider(failures=99, error=LLMError)  # non-retryable → immediate fallback
    good = FlakyProvider(failures=0, model="gemini-2.5-flash")
    r = LLMRouter([bad, good], base_backoff_s=0)
    assert r.complete(MSGS).model == "gemini-2.5-flash"
    assert bad.calls == 1


def test_all_providers_fail():
    r = LLMRouter([FlakyProvider(99)], max_retries=1, base_backoff_s=0)
    with pytest.raises(LLMError):
        r.complete(MSGS)


def test_cost_and_budget():
    assert cost_usd("gpt-4.1-mini", 1_000_000, 0) == pytest.approx(0.40)
    r = LLMRouter([FlakyProvider(0)], budget_usd=0.0001)
    r.complete(MSGS)  # spends 0.00056 $
    with pytest.raises(BudgetExceededError):
        r.complete(MSGS)


def test_context_window_preflight_skips_small_model():
    small = MockSREProvider()  # 32k window
    big = FlakyProvider(0)  # 1M window
    r = LLMRouter([small, big])
    huge = [Message("user", "x " * 200_000)]
    assert r.complete(huge).provider == "flaky"


def test_mock_simulated_failures_are_retried():
    r = LLMRouter([MockSREProvider(fail_rate=0.5, seed=1)], max_retries=6, base_backoff_s=0)
    for _ in range(5):
        r.complete([Message("system", "[agent:chat]"), Message("user", "hello")])
    s = r.telemetry.summary()
    assert s["calls"] - s["errors"] == 5


def test_truncate_keeps_head_and_tail():
    text = "HEAD " + "x" * 10_000 + " TAIL"
    out = truncate_to_tokens(text, 100)
    assert out.startswith("HEAD") and out.endswith("TAIL") and "truncated" in out
