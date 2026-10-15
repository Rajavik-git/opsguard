"""Token counting with graceful degradation (tiktoken if present, heuristic otherwise)."""

from __future__ import annotations

from functools import lru_cache

from .types import Message


@lru_cache(maxsize=1)
def _encoder():
    try:
        import tiktoken  # type: ignore

        return tiktoken.get_encoding("o200k_base")
    except Exception:  # pragma: no cover - optional dependency
        return None


def count_tokens(text: str) -> int:
    enc = _encoder()
    if enc is not None:
        return len(enc.encode(text))
    # ~4 chars/token is a conservative approximation for EN/FR technical text
    return max(1, (len(text) + 3) // 4) if text else 0


def count_messages(messages: list[Message]) -> int:
    total = 0
    for m in messages:
        total += 4 + count_tokens(m.content)  # per-message framing overhead
        for tc in m.tool_calls:
            total += count_tokens(tc.name) + count_tokens(str(tc.arguments))
    return total


def truncate_to_tokens(text: str, max_tokens: int, marker: str = "\n…[truncated]…\n") -> str:
    """Keep head and tail (most useful parts of logs) within a token budget."""
    if count_tokens(text) <= max_tokens:
        return text
    budget_chars = max_tokens * 4
    head = budget_chars * 2 // 3
    tail = budget_chars - head
    return text[:head] + marker + text[-tail:]
