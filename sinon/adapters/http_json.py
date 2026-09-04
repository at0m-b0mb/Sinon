"""Adapter for an arbitrary agent behind an HTTP/JSON endpoint.

This is the one that matters in a real engagement. The client has an agent at
``https://something/api/assistant``, it takes a blob of JSON and returns a blob
of JSON, and nobody is going to rewrite it to fit a test harness. So the shape
is configuration: say where the prompt goes in, where the reply comes out, and
Sinon does the rest.

If the target's response includes a tool or action trace --- many internal agents
return one for their own debugging --- point ``tool_calls_path`` at it and every
tool-abuse and over-permission probe becomes live. Without it the adapter
declares ``supports_tools = False``, those probes are skipped rather than
guessed at, and the grade is capped accordingly.
"""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional

from ..model import AgentRequest, AgentResponse, ToolCall
from ._http import HttpError, dig, identification_headers, post_json
from .base import Adapter, AdapterError, ToolRunner, inline_documents


def set_path(target: Dict[str, Any], path: str, value: Any) -> Dict[str, Any]:
    """Write ``value`` into ``target`` at a dotted path, creating dicts as needed."""
    parts = path.split(".")
    node: Any = target
    for part in parts[:-1]:
        if part not in node or not isinstance(node[part], dict):
            node[part] = {}
        node = node[part]
    node[parts[-1]] = value
    return target


class HttpJsonAdapter(Adapter):
    kind = "http"
    supports_tools = False

    def __init__(
        self,
        url: str,
        prompt_field: str = "message",
        response_path: str = "",
        system_field: str = "",
        headers: Optional[Dict[str, str]] = None,
        extra_body: Optional[Dict[str, Any]] = None,
        tool_calls_path: str = "",
        name: str = "",
        timeout: float = 60.0,
        identify: bool = True,
        verify_tls: bool = True,
    ) -> None:
        if not url:
            raise AdapterError("http adapter requires --target-url")
        super().__init__(name=name or url, url=url)
        self.prompt_field = prompt_field
        self.response_path = response_path
        self.system_field = system_field
        self.headers = dict(headers or {})
        self.extra_body = dict(extra_body or {})
        self.tool_calls_path = tool_calls_path
        self.timeout = timeout
        self.identify = identify
        self.verify_tls = verify_tls
        self.supports_tools = bool(tool_calls_path)

    def describe(self) -> Dict[str, str]:
        info = super().describe()
        info["prompt_field"] = self.prompt_field
        info["response_path"] = self.response_path or "(auto-detect)"
        info["tool_calls_path"] = self.tool_calls_path or "(none - tool probes will be skipped)"
        return info

    def send(
        self, request: AgentRequest, tool_runner: Optional[ToolRunner] = None
    ) -> AgentResponse:
        body: Dict[str, Any] = dict(self.extra_body)
        set_path(body, self.prompt_field, inline_documents(request))
        if self.system_field and request.system_prompt:
            set_path(body, self.system_field, request.system_prompt)

        headers = dict(self.headers)
        if self.identify:
            headers.update(identification_headers(request.run_id, request.probe_id))

        started = time.time()
        try:
            _status, parsed = post_json(
                self.url,
                body,
                headers=headers,
                timeout=self.timeout,
                verify_tls=self.verify_tls,
            )
        except HttpError as exc:
            return AgentResponse(
                error=f"{exc} {exc.body[:300]}".strip(),
                latency_ms=(time.time() - started) * 1000,
            )

        text = self._extract_text(parsed)
        calls = self._extract_tool_calls(parsed)
        return AgentResponse(
            text=text,
            tool_calls=calls,
            raw=parsed,
            latency_ms=(time.time() - started) * 1000,
        )

    # -- response shaping -------------------------------------------------

    def _extract_text(self, parsed: Any) -> str:
        if self.response_path:
            value = dig(parsed, self.response_path)
            return "" if value is None else _stringify(value)
        if isinstance(parsed, str):
            return parsed
        # Auto-detect the usual suspects before giving up and stringifying.
        for candidate in (
            "reply",
            "response",
            "message",
            "output",
            "text",
            "answer",
            "content",
            "result",
            "choices.0.message.content",
            "data.reply",
        ):
            value = dig(parsed, candidate)
            if isinstance(value, str) and value.strip():
                return value
        return _stringify(parsed)

    def _extract_tool_calls(self, parsed: Any) -> List[ToolCall]:
        if not self.tool_calls_path:
            return []
        raw = dig(parsed, self.tool_calls_path) or []
        if not isinstance(raw, list):
            return []
        calls: List[ToolCall] = []
        for item in raw:
            if isinstance(item, str):
                calls.append(ToolCall(name=item))
                continue
            if not isinstance(item, dict):
                continue
            name = str(item.get("name") or item.get("tool") or item.get("action") or "unknown")
            args = item.get("arguments") or item.get("args") or item.get("input") or {}
            if not isinstance(args, dict):
                args = {"_raw": _stringify(args)}
            calls.append(
                ToolCall(
                    name=name,
                    arguments=args,
                    result=_stringify(item.get("result") or item.get("output") or ""),
                )
            )
        return calls


def _stringify(value: Any) -> str:
    if isinstance(value, str):
        return value
    import json

    try:
        return json.dumps(value, ensure_ascii=False)
    except (TypeError, ValueError):
        return str(value)
