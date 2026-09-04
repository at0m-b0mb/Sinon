"""Adapter for any endpoint speaking the OpenAI chat-completions shape.

That covers far more than OpenAI: Ollama, vLLM, LM Studio, llama.cpp's server,
OpenRouter, Together, Groq, Azure deployments, and most internal gateways teams
put in front of their own models. If the thing under test is an agent built on
one of those, this is the adapter.

It runs a real tool loop: offer the instrumented toolbelt, execute whatever the
model calls, feed the results back, repeat until the model stops calling tools
or the turn budget runs out. That loop is what makes tool-abuse and
over-permission probes meaningful --- a single-shot request can only ever see
what the model *says*, never what it would *do*.
"""

from __future__ import annotations

import json
import os
import time
from typing import Any, Dict, List, Optional

from ..model import AgentRequest, AgentResponse, ToolCall
from ._http import HttpError, dig, identification_headers, post_json
from .base import Adapter, AdapterError, ToolRunner

MAX_TOOL_TURNS = 6


class OpenAICompatAdapter(Adapter):
    kind = "openai"
    supports_tools = True
    supports_multi_turn = True

    def __init__(
        self,
        base_url: str,
        model: str,
        api_key: str = "",
        name: str = "",
        temperature: float = 0.0,
        timeout: float = 60.0,
        max_tool_turns: int = MAX_TOOL_TURNS,
        extra_headers: Optional[Dict[str, str]] = None,
        identify: bool = True,
        verify_tls: bool = True,
    ) -> None:
        base = base_url.rstrip("/")
        if not base.endswith("/chat/completions"):
            base = base + "/chat/completions" if base.endswith("/v1") else base + "/v1/chat/completions"
        super().__init__(name=name or f"{model}", url=base)
        self.model = model
        self.api_key = api_key or os.environ.get("SINON_API_KEY", "")
        self.temperature = temperature
        self.timeout = timeout
        self.max_tool_turns = max_tool_turns
        self.extra_headers = dict(extra_headers or {})
        self.identify = identify
        self.verify_tls = verify_tls
        if not model:
            raise AdapterError("openai adapter requires --model")

    def describe(self) -> Dict[str, str]:
        info = super().describe()
        info["model"] = self.model
        info["max_tool_turns"] = str(self.max_tool_turns)
        return info

    # -- request ---------------------------------------------------------

    def _headers(self, request: AgentRequest) -> Dict[str, str]:
        headers = dict(self.extra_headers)
        if self.api_key:
            headers.setdefault("Authorization", f"Bearer {self.api_key}")
        if self.identify:
            headers.update(identification_headers(request.run_id, request.probe_id))
        return headers

    def send(
        self, request: AgentRequest, tool_runner: Optional[ToolRunner] = None
    ) -> AgentResponse:
        messages: List[Dict[str, Any]] = []
        if request.system_prompt:
            messages.append({"role": "system", "content": request.system_prompt})
        if request.memory:
            messages.append(
                {
                    "role": "system",
                    "content": f"[memory from earlier sessions]\n{request.memory}",
                }
            )
        messages.append({"role": "user", "content": _user_content(request)})

        tools = [tool.to_openai_schema() for tool in request.tools]
        observed: List[ToolCall] = []
        started = time.time()
        text = ""
        raw_last: Any = None

        for _turn in range(self.max_tool_turns):
            payload: Dict[str, Any] = {
                "model": self.model,
                "messages": messages,
                "temperature": self.temperature,
            }
            if tools:
                payload["tools"] = tools
                payload["tool_choice"] = "auto"

            try:
                _status, body = post_json(
                    self.url,
                    payload,
                    headers=self._headers(request),
                    timeout=self.timeout,
                    verify_tls=self.verify_tls,
                )
            except HttpError as exc:
                return AgentResponse(
                    text=text,
                    tool_calls=observed,
                    error=f"{exc} {exc.body[:300]}".strip(),
                    latency_ms=(time.time() - started) * 1000,
                )

            raw_last = body
            message = dig(body, "choices.0.message", {}) or {}
            content = message.get("content") or ""
            if content:
                text = f"{text}\n{content}".strip() if text else content

            calls = message.get("tool_calls") or []
            if not calls:
                break

            messages.append(_assistant_turn(message))
            for call in calls:
                name, args, call_id = _decode_call(call)
                if tool_runner is None:
                    observed.append(ToolCall(name=name, arguments=args, result=""))
                    result = ""
                else:
                    executed = tool_runner(name, args)
                    observed.append(executed)
                    result = executed.result
                messages.append(
                    {
                        "role": "tool",
                        "tool_call_id": call_id,
                        "name": name,
                        "content": result or "",
                    }
                )

        return AgentResponse(
            text=text,
            tool_calls=observed,
            raw=raw_last,
            latency_ms=(time.time() - started) * 1000,
        )


def _user_content(request: AgentRequest) -> str:
    from .base import inline_documents

    # Documents go inline here even though tools exist: a probe may serve the
    # same content both ways, and the tool path is exercised when the model
    # chooses to call the retrieval tool.
    if request.documents and not request.tools:
        return inline_documents(request)
    return request.prompt


def _assistant_turn(message: Dict[str, Any]) -> Dict[str, Any]:
    turn = {"role": "assistant", "content": message.get("content") or ""}
    if message.get("tool_calls"):
        turn["tool_calls"] = message["tool_calls"]
    return turn


def _decode_call(call: Dict[str, Any]) -> "tuple[str, Dict[str, Any], str]":
    function = call.get("function") or {}
    name = function.get("name") or call.get("name") or "unknown"
    raw_args = function.get("arguments") or call.get("arguments") or "{}"
    if isinstance(raw_args, str):
        try:
            args = json.loads(raw_args)
        except json.JSONDecodeError:
            args = {"_raw": raw_args}
    elif isinstance(raw_args, dict):
        args = raw_args
    else:
        args = {"_raw": str(raw_args)}
    return name, args, str(call.get("id") or name)
