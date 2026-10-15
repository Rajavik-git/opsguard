"""Google Gemini backend via the `google-genai` SDK."""

from __future__ import annotations

import os
import uuid

from .base import LLMProvider
from .types import LLMError, LLMResponse, Message, RateLimitError, ToolCall, ToolSpec, TransientError, Usage


class GeminiProvider(LLMProvider):
    name = "gemini"

    def __init__(self, model: str = "gemini-2.5-flash", api_key: str | None = None, **kw):
        super().__init__(model, **kw)
        from google import genai  # lazy: optional dependency

        self._client = genai.Client(api_key=api_key or os.environ.get("GEMINI_API_KEY"))

    @staticmethod
    def _to_wire(messages: list[Message]):
        from google.genai import types as gt

        system = "\n\n".join(m.content for m in messages if m.role == "system")
        contents = []
        for m in messages:
            if m.role == "system":
                continue
            if m.role == "tool":
                contents.append(
                    gt.Content(
                        role="user",
                        parts=[gt.Part.from_function_response(name=m.name or "tool", response={"result": m.content})],
                    )
                )
            elif m.tool_calls:
                contents.append(
                    gt.Content(
                        role="model",
                        parts=[gt.Part.from_function_call(name=tc.name, args=tc.arguments) for tc in m.tool_calls],
                    )
                )
            else:
                role = "model" if m.role == "assistant" else "user"
                contents.append(gt.Content(role=role, parts=[gt.Part.from_text(text=m.content)]))
        return system, contents

    def _complete(self, messages, tools: list[ToolSpec], temperature, max_output_tokens, json_mode):
        from google.genai import errors
        from google.genai import types as gt

        system, contents = self._to_wire(messages)
        config = gt.GenerateContentConfig(
            system_instruction=system or None,
            temperature=temperature,
            max_output_tokens=max_output_tokens,
        )
        if tools:
            config.tools = [
                gt.Tool(
                    function_declarations=[
                        gt.FunctionDeclaration(name=t.name, description=t.description, parameters=t.parameters)
                        for t in tools
                    ]
                )
            ]
        elif json_mode:
            config.response_mime_type = "application/json"
        try:
            r = self._client.models.generate_content(model=self.model, contents=contents, config=config)
        except errors.APIError as e:
            code = getattr(e, "code", 0) or 0
            if code == 429:
                raise RateLimitError(str(e)) from e
            if code >= 500:
                raise TransientError(str(e)) from e
            raise LLMError(str(e)) from e

        calls = [
            ToolCall(id=f"call_{uuid.uuid4().hex[:8]}", name=fc.name, arguments=dict(fc.args or {}))
            for fc in (r.function_calls or [])
        ]
        um = r.usage_metadata
        return LLMResponse(
            content=(r.text or "") if not calls else "",
            tool_calls=calls,
            usage=Usage(um.prompt_token_count or 0, um.candidates_token_count or 0),
            model=self.model,
            provider=self.name,
        )
