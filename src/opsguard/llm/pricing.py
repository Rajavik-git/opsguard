"""Model catalogue: context windows and indicative prices (USD per 1M tokens).

Prices are indicative and kept in one place so they can be updated from config;
the router uses them for cost accounting and budget enforcement.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ModelInfo:
    context_window: int
    input_per_m: float
    output_per_m: float


CATALOGUE: dict[str, ModelInfo] = {
    # OpenAI
    "gpt-4.1-mini": ModelInfo(1_000_000, 0.40, 1.60),
    "gpt-4.1": ModelInfo(1_000_000, 2.00, 8.00),
    "gpt-4o-mini": ModelInfo(128_000, 0.15, 0.60),
    # Google Gemini
    "gemini-2.5-flash": ModelInfo(1_000_000, 0.30, 2.50),
    "gemini-2.5-pro": ModelInfo(1_000_000, 1.25, 10.00),
    # Offline deterministic model used for tests / demo
    "mock-sre-1": ModelInfo(32_000, 0.0, 0.0),
}

_DEFAULT = ModelInfo(128_000, 1.0, 4.0)


def model_info(model: str) -> ModelInfo:
    return CATALOGUE.get(model, _DEFAULT)


def cost_usd(model: str, input_tokens: int, output_tokens: int) -> float:
    info = model_info(model)
    return (input_tokens * info.input_per_m + output_tokens * info.output_per_m) / 1_000_000
