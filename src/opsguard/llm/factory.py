"""Build a router from config (`opsguard.yaml`) and the environment."""

from __future__ import annotations

import os

from .base import LLMProvider
from .router import LLMRouter


def build_provider(spec: dict) -> LLMProvider:
    kind, model = spec["provider"], spec.get("model")
    if kind == "openai":
        from .openai_provider import OpenAIProvider

        return OpenAIProvider(model or "gpt-4.1-mini")
    if kind == "gemini":
        from .gemini_provider import GeminiProvider

        return GeminiProvider(model or "gemini-2.5-flash")
    if kind == "mock":
        from .mock_provider import MockSREProvider

        return MockSREProvider(**{k: v for k, v in spec.items() if k not in ("provider",)})
    raise ValueError(f"unknown provider: {kind}")


def build_router(config: dict) -> LLMRouter:
    """Use configured chain; providers whose API key is missing are skipped,
    and the offline mock is always appended as last-resort fallback."""
    providers: list[LLMProvider] = []
    for spec in config.get("llm", {}).get("chain", []):
        key_var = {"openai": "OPENAI_API_KEY", "gemini": "GEMINI_API_KEY"}.get(spec["provider"])
        if key_var and not os.environ.get(key_var):
            continue
        try:
            providers.append(build_provider(spec))
        except ImportError:
            continue  # SDK not installed
    if not any(p.name == "mock" for p in providers):
        providers.append(build_provider({"provider": "mock"}))
    llm = config.get("llm", {})
    return LLMRouter(
        providers,
        max_retries=llm.get("max_retries", 3),
        budget_usd=llm.get("budget_usd_per_run"),
        max_concurrency=llm.get("max_concurrency", 4),
    )
