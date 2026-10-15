"""OpenAI Chat Completions backend (function calling, JSON mode, error mapping)."""

from __future__ import annotations

import json
import os

from .base import LLMProvider
from .types import (
    ContextLengthError,
    LLMError,
    LLMResponse,
    Message,
    RateLimitError,
    ToolCall,
    ToolSpec,
    TransientError,
    Usage,
)


class OpenAIProvider(LLMProvider):
    name = "openai"

    def __init__(self, model: str = "gpt-4.1-mini", api_key: str | None = None, **kw):
        super().__init__(model, **kw)
        from openai import OpenAI  # lazy: optional dependency

        self._client = OpenAI(
            api_key=api_key or os.environ.get("OPENAI_API_KEY"),
            timeout=self.timeout_s,
            max_retries=0,  # retries are owned by the router
        )

    @staticmethod
    def _to_wire(messages: list[Message]) -> list[dict]:
        out = []
        for m in messages:
            if m.role == "tool":
                out.append({"role": "tool", "tool_call_id": m.tool_call_id, "content": m.content})
            elif m.tool_calls:
                out.append(
                    {
                        "role": "assistant",
                        "content": m.content or None,
                        "tool_calls": [
                            {
                                "id": tc.id,
                                "type": "function",
                                "function": {"name": tc.name, "arguments": json.dumps(tc.arguments)},
                            }
                            for tc in m.tool_calls
                        ],
                    }
                )
            else:
                out.append({"role": m.role, "content": m.content})
        return out

    def _complete(self, messages, tools: list[ToolSpec], temperature, max_output_tokens, json_mode):
        import openai

        kwargs: dict = {
            "model": self.model,
            "messages": self._to_wire(messages),
            "temperature": temperature,
            "max_tokens": max_output_tokens,
        }
        if tools:
            kwargs["tools"] = [
                {"type": "function", "function": {"name": t.name, "description": t.description, "parameters": t.parameters}}
                for t in tools
            ]
        if json_mode and not tools:
            kwargs["response_format"] = {"type": "json_object"}
        try:
            r = self._client.chat.completions.create(**kwargs)
        except openai.RateLimitError as e:
            raise RateLimitError(str(e)) from e
        except (openai.APITimeoutError, openai.APIConnectionError, openai.InternalServerError) as e:
            raise TransientError(str(e)) from e
        except openai.BadRequestError as e:
            if "context_length" in str(e):
                raise ContextLengthError(str(e)) from e
            raise LLMError(str(e)) from e

        choice = r.choices[0]
        calls = [
            ToolCall(id=tc.id, name=tc.function.name, arguments=json.loads(tc.function.arguments or "{}"))
            for tc in (choice.message.tool_calls or [])
        ]
        return LLMResponse(
            content=choice.message.content or "",
            tool_calls=calls,
            usage=Usage(r.usage.prompt_tokens, r.usage.completion_tokens),
            model=self.model,
            provider=self.name,
            finish_reason=choice.finish_reason or "stop",
        )
