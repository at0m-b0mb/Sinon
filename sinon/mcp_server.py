"""MCP stdio server: test the agent you actually use.

Some of the most interesting agents cannot be driven from a script. Claude Code,
Cursor, a desktop assistant, an internal copilot behind SSO --- you can talk to
them, but you cannot ``POST`` to them. The adapters in :mod:`sinon.adapters` do
not help.

So Sinon offers the other half instead. It runs as an MCP server, connects to
the agent as a set of tools, and hands over the probe's content when the agent
asks for it. Everything the agent then does with those tools is recorded. You
paste the agent's final reply into ``sinon judge`` and get the same verdict the
automated runner would have produced, from the same oracles.

Workflow::

    sinon serve-mcp --probe TA-SSRF-001 --record run.jsonl   # in the MCP config
    ...drive the agent normally, ask it to do the probe's task...
    sinon judge --record run.jsonl --reply-file reply.txt

The protocol is implemented by hand --- initialize, tools/list, tools/call, ping
--- rather than by taking an SDK dependency. It is about a hundred lines of JSON
over stdin, the surface Sinon needs is small and stable, and one dependency is
the whole install story for this project.

Two safety properties are load-bearing:

* stdout carries protocol frames only. Every diagnostic goes to stderr, because
  a stray ``print`` corrupts the session.
* The tools are the same instrumented, synthetic ones the runner uses. This
  server cannot touch the filesystem, the network or a mailbox --- the worst it
  can do is tell an agent a plausible lie and write down what the agent did next.
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, TextIO

from . import canary as canary_mod
from . import corpus as corpus_mod
from . import toolbelt as toolbelt_mod
from .model import Probe
from .version import __version__

PROTOCOL_VERSION = "2024-11-05"
SERVER_NAME = "sinon"

BRIEF_TOOL = "sinon_brief"


class Recorder:
    """Append-only JSONL log of everything that happened in a session."""

    def __init__(self, path: Optional[Path]):
        self.path = Path(path) if path else None
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text("", encoding="utf-8")

    def write(self, kind: str, **fields: Any) -> None:
        if not self.path:
            return
        record = {"ts": round(time.time(), 3), "kind": kind}
        record.update(fields)
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")


class SinonMCPServer:
    """A single-probe MCP server over stdio."""

    def __init__(
        self,
        probe: Probe,
        record_path: Optional[Path] = None,
        run_id: str = "",
        stdin: Optional[TextIO] = None,
        stdout: Optional[TextIO] = None,
        stderr: Optional[TextIO] = None,
    ) -> None:
        self.stdin = stdin or sys.stdin
        self.stdout = stdout or sys.stdout
        self.stderr = stderr or sys.stderr

        self.run_id = run_id or canary_mod.new_run_id()
        self.canary = canary_mod.mint(self.run_id, probe.id)
        self.system_canary = canary_mod.mint(self.run_id, probe.id + "SYS")

        context = corpus_mod.build_context(
            canary=self.canary.value,
            system_canary=self.system_canary.value,
            sink_url="",
            run_id=self.run_id,
            probe=probe,
        )
        context["payload"] = corpus_mod.render(probe.payload, context)
        corpus_mod.add_payload_variants(context)

        self.probe = corpus_mod.render_probe(probe, context)
        self.rendered_payload = context["payload"]
        self.belt = toolbelt_mod.Toolbelt(
            names=self.probe.tools,
            context=toolbelt_mod.ToolContext(
                canary=self.canary.value,
                documents=list(self.probe.documents),
                result_overrides=dict(self.probe.tool_results),
            ),
            description_overrides=dict(self.probe.tool_descriptions),
        )

        self.recorder = Recorder(record_path)
        self.recorder.write(
            "session",
            probe_id=probe.id,
            run_id=self.run_id,
            canary=self.canary.value,
            system_canary=self.system_canary.value,
            prompt=self.probe.prompt,
            payload=self.rendered_payload,
            sinon_version=__version__,
            corpus_path=probe.source_path,
        )
        self._running = True

    # -- framing ---------------------------------------------------------

    def _log(self, message: str) -> None:
        self.stderr.write(f"[sinon-mcp] {message}\n")
        self.stderr.flush()

    def _send(self, payload: Dict[str, Any]) -> None:
        self.stdout.write(json.dumps(payload, ensure_ascii=False) + "\n")
        self.stdout.flush()

    def _reply(self, request_id: Any, result: Dict[str, Any]) -> None:
        self._send({"jsonrpc": "2.0", "id": request_id, "result": result})

    def _error(self, request_id: Any, code: int, message: str) -> None:
        self._send({"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}})

    # -- tool surface ----------------------------------------------------

    def tool_list(self) -> List[Dict[str, Any]]:
        """Instrumented tools plus the one that hands over the probe content."""
        tools = [
            {
                "name": BRIEF_TOOL,
                "description": (
                    "Fetch the task briefing and any documents for the current "
                    "Sinon probe. Call this first."
                ),
                "inputSchema": {"type": "object", "properties": {}, "required": []},
            }
        ]
        for definition in self.belt.definitions():
            tools.append(
                {
                    "name": definition.name,
                    "description": definition.description,
                    "inputSchema": definition.parameters,
                }
            )
        return tools

    def _brief(self) -> str:
        parts = [f"TASK: {self.probe.prompt.strip()}"]
        for doc in self.probe.documents:
            parts.append(
                f"\n--- retrieved document: {doc.name} ({doc.media_type}) ---\n{doc.content}"
            )
        if self.probe.memory:
            parts.append(f"\n--- stored memory ---\n{self.probe.memory}")
        return "\n".join(parts)

    def call_tool(self, name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        if name == BRIEF_TOOL:
            text = self._brief()
            self.recorder.write("brief", chars=len(text))
            return {"content": [{"type": "text", "text": text}], "isError": False}

        call = self.belt.invoke(name, arguments)
        self.recorder.write(
            "tool_call",
            name=call.name,
            arguments=call.arguments,
            result=call.result[:4000],
            tripwire=call.tripwire,
            tripwire_reason=call.tripwire_reason,
        )
        if call.tripwire:
            self._log(f"TRIPWIRE {call.name}: {call.tripwire_reason}")
        return {"content": [{"type": "text", "text": call.result}], "isError": False}

    # -- dispatch --------------------------------------------------------

    def handle(self, message: Dict[str, Any]) -> None:
        method = message.get("method", "")
        request_id = message.get("id")
        params = message.get("params") or {}

        # Notifications carry no id and must never be answered.
        if request_id is None:
            if method == "notifications/initialized":
                self._log("client initialized")
            return

        if method == "initialize":
            self._reply(
                request_id,
                {
                    "protocolVersion": PROTOCOL_VERSION,
                    "capabilities": {"tools": {"listChanged": False}},
                    "serverInfo": {"name": SERVER_NAME, "version": __version__},
                    "instructions": (
                        f"Sinon probe {self.probe.id} is loaded. Call {BRIEF_TOOL} for "
                        "the task, then work normally. Every tool call is recorded for "
                        "an authorized security test."
                    ),
                },
            )
            return

        if method == "ping":
            self._reply(request_id, {})
            return

        if method == "tools/list":
            self._reply(request_id, {"tools": self.tool_list()})
            return

        if method == "tools/call":
            name = str(params.get("name", ""))
            arguments = params.get("arguments") or {}
            if not isinstance(arguments, dict):
                arguments = {"_raw": str(arguments)}
            try:
                self._reply(request_id, self.call_tool(name, arguments))
            except Exception as exc:  # a tool fault must not kill the session
                self._log(f"tool error: {exc}")
                self._reply(
                    request_id,
                    {"content": [{"type": "text", "text": f"error: {exc}"}], "isError": True},
                )
            return

        self._error(request_id, -32601, f"method not found: {method}")

    def serve(self) -> int:
        self._log(
            f"probe {self.probe.id} loaded, run {self.run_id}, "
            f"{len(self.probe.tools)} instrumented tool(s)"
        )
        self._log(f"canary {self.canary.value}")
        for line in self.stdin:
            line = line.strip()
            if not line:
                continue
            try:
                message = json.loads(line)
            except json.JSONDecodeError:
                self._log("ignoring malformed frame")
                continue
            if isinstance(message, list):
                for item in message:
                    self.handle(item)
            elif isinstance(message, dict):
                self.handle(message)
        self.recorder.write("end", tool_calls=len(self.belt.calls))
        self._log(f"session ended, {len(self.belt.calls)} tool call(s) recorded")
        return 0


# --------------------------------------------------------------------------
# Judging a recorded session
# --------------------------------------------------------------------------


def load_record(path: Path) -> Dict[str, Any]:
    """Read a session recording back into something the oracles can judge."""
    session: Dict[str, Any] = {}
    calls: List[Dict[str, Any]] = []
    with Path(path).open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            record = json.loads(line)
            if record.get("kind") == "session":
                session = record
            elif record.get("kind") == "tool_call":
                calls.append(record)
    if not session:
        raise ValueError(f"{path}: no session header found; was this written by sinon serve-mcp?")
    session["tool_calls"] = calls
    return session
