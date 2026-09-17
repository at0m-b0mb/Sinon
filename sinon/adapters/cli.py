"""Adapter for an agent that runs as a local command.

Two protocols, because agents come in two shapes.

``text`` (default)
    Prompt on stdin, reply on stdout. Works with anything --- a shell script, a
    Python entry point, an existing CLI assistant. No tool visibility, so tool
    probes are skipped.

``json``
    Sinon writes one JSON envelope to stdin and reads one JSON object from
    stdout. The envelope carries the prompt, system prompt, documents, offered
    tools and the results of any tools called on previous turns; the reply
    carries the text and any tool calls. Sinon executes those calls against the
    instrumented toolbelt and re-invokes the command with the results appended,
    up to the turn budget. That gives full tool telemetry for an agent you can
    run but cannot import.

The envelope schema is documented in ``docs/adapters.md`` and is stable; it is
deliberately small enough to implement in a twenty-line shim around whatever the
target actually is.
"""

from __future__ import annotations

import json
import os
import shlex
import subprocess
import time
from typing import Any, Dict, List, Optional

from ..model import AgentRequest, AgentResponse, ToolCall
from .base import Adapter, AdapterError, ToolRunner, inline_documents

MAX_TOOL_TURNS = 6


def split_command(command: str) -> List[str]:
    """Split a command line into argv, correctly on Windows as well as POSIX.

    ``shlex.split`` defaults to POSIX rules, under which a backslash is an
    escape character --- so ``C:\\Tools\\agent.exe`` silently becomes
    ``C:Toolsagent.exe`` and the command is not found. On Windows the split is
    done in non-POSIX mode, which preserves backslashes, and the quote
    characters it leaves behind are stripped afterwards.
    """
    if os.name != "nt":
        return shlex.split(command)
    tokens = shlex.split(command, posix=False)
    return [
        token[1:-1] if len(token) > 1 and token[0] == token[-1] and token[0] in "\"'" else token
        for token in tokens
    ]


class CliAdapter(Adapter):
    kind = "cli"
    runs_locally = True
    supports_multi_turn = True

    def __init__(
        self,
        command: str,
        protocol: str = "text",
        name: str = "",
        timeout: float = 60.0,
        max_tool_turns: int = MAX_TOOL_TURNS,
        cwd: str = "",
        env: Optional[Dict[str, str]] = None,
    ) -> None:
        if not command:
            raise AdapterError("cli adapter requires --command")
        if protocol not in ("text", "json"):
            raise AdapterError("cli protocol must be 'text' or 'json'")
        super().__init__(name=name or command.split()[0], url="")
        self.command = command
        self.argv = split_command(command)
        self.protocol = protocol
        self.timeout = timeout
        self.max_tool_turns = max_tool_turns
        self.cwd = cwd or None
        self.env = env
        self.supports_tools = protocol == "json"

    def describe(self) -> Dict[str, str]:
        info = super().describe()
        info["command"] = self.command
        info["protocol"] = self.protocol
        return info

    # -- execution -------------------------------------------------------

    def _invoke(self, stdin_text: str) -> str:
        try:
            completed = subprocess.run(
                self.argv,
                input=stdin_text,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                cwd=self.cwd,
                env=self.env,
                check=False,
            )
        except FileNotFoundError as exc:
            raise AdapterError(f"command not found: {self.argv[0]}") from exc
        except subprocess.TimeoutExpired as exc:
            raise AdapterError(f"command timed out after {self.timeout}s") from exc
        if completed.returncode != 0 and not completed.stdout.strip():
            raise AdapterError(
                f"command exited {completed.returncode}: {completed.stderr.strip()[:300]}"
            )
        return completed.stdout

    def send(
        self, request: AgentRequest, tool_runner: Optional[ToolRunner] = None
    ) -> AgentResponse:
        started = time.time()
        if self.protocol == "text":
            try:
                out = self._invoke(inline_documents(request))
            except AdapterError as exc:
                return AgentResponse(error=str(exc), latency_ms=(time.time() - started) * 1000)
            return AgentResponse(text=out.strip(), latency_ms=(time.time() - started) * 1000)

        return self._send_json(request, tool_runner, started)

    def _send_json(
        self, request: AgentRequest, tool_runner: Optional[ToolRunner], started: float
    ) -> AgentResponse:
        envelope: Dict[str, Any] = {
            "sinon_protocol": 1,
            "run_id": request.run_id,
            "probe_id": request.probe_id,
            "system": request.system_prompt,
            "memory": request.memory,
            "prompt": request.prompt,
            "documents": [
                {
                    "name": doc.name,
                    "url": doc.url,
                    "media_type": doc.media_type,
                    "content": doc.content,
                }
                for doc in request.documents
            ],
            "tools": [
                {
                    "name": tool.name,
                    "description": tool.description,
                    "parameters": tool.parameters,
                }
                for tool in request.tools
            ],
            "tool_results": [],
        }

        observed: List[ToolCall] = []
        text = ""
        raw: Any = None

        for _turn in range(self.max_tool_turns):
            try:
                out = self._invoke(json.dumps(envelope))
            except AdapterError as exc:
                return AgentResponse(
                    text=text,
                    tool_calls=observed,
                    error=str(exc),
                    latency_ms=(time.time() - started) * 1000,
                )

            try:
                parsed = json.loads(out.strip() or "{}")
            except json.JSONDecodeError:
                return AgentResponse(
                    text=out.strip(),
                    tool_calls=observed,
                    error="target did not return JSON (is --cli-protocol text what you want?)",
                    latency_ms=(time.time() - started) * 1000,
                )

            raw = parsed
            chunk = str(parsed.get("text") or parsed.get("reply") or "")
            if chunk:
                text = f"{text}\n{chunk}".strip() if text else chunk

            calls = parsed.get("tool_calls") or []
            if not calls:
                break

            results = []
            for call in calls:
                if not isinstance(call, dict):
                    continue
                name = str(call.get("name", "unknown"))
                args = call.get("arguments") or {}
                if not isinstance(args, dict):
                    args = {"_raw": str(args)}
                if tool_runner is None:
                    executed = ToolCall(name=name, arguments=args)
                else:
                    executed = tool_runner(name, args)
                observed.append(executed)
                results.append({"name": name, "arguments": args, "result": executed.result})
            envelope["tool_results"] = envelope["tool_results"] + results

        return AgentResponse(
            text=text,
            tool_calls=observed,
            raw=raw,
            latency_ms=(time.time() - started) * 1000,
        )
