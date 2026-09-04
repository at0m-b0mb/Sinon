"""Adapter contracts, especially the capability flags scoring depends on."""

import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from sinon import adapters
from sinon.adapters.base import AdapterError, inline_documents
from sinon.adapters.http_json import HttpJsonAdapter, set_path
from sinon.model import AgentRequest, DocumentSpec, ToolCall, ToolDef


def test_factory_builds_every_advertised_kind():
    assert adapters.build({"kind": "reference"}).kind == "reference"
    assert adapters.build({"kind": "http", "url": "https://x.test/a"}).kind == "http"
    assert adapters.build({"kind": "cli", "command": "cat"}).kind == "cli"
    assert adapters.build(
        {"kind": "openai", "url": "https://x.test/v1", "model": "m"}
    ).kind == "openai"


def test_factory_rejects_an_unknown_kind():
    with pytest.raises(AdapterError, match="unknown target kind"):
        adapters.build({"kind": "telepathy"})


def test_openai_requires_a_model():
    with pytest.raises(AdapterError, match="requires --model"):
        adapters.build({"kind": "openai", "url": "https://x.test/v1"})


def test_openai_normalises_the_endpoint():
    for given in ("https://x.test", "https://x.test/v1", "https://x.test/v1/chat/completions"):
        adapter = adapters.build({"kind": "openai", "url": given, "model": "m"})
        assert adapter.url.endswith("/chat/completions")
        assert "/chat/completions/chat/completions" not in adapter.url


def test_http_adapter_declares_no_tool_support_without_a_trace():
    blind = adapters.build({"kind": "http", "url": "https://x.test/a"})
    assert blind.supports_tools is False
    seeing = adapters.build(
        {"kind": "http", "url": "https://x.test/a", "tool_calls_path": "trace.actions"}
    )
    assert seeing.supports_tools is True


def test_cli_adapter_tool_support_follows_the_protocol():
    assert adapters.build({"kind": "cli", "command": "cat"}).supports_tools is False
    assert adapters.build(
        {"kind": "cli", "command": "cat", "protocol": "json"}
    ).supports_tools is True


def test_set_path_creates_nested_structures():
    body = {}
    set_path(body, "input.messages.text", "hello")
    assert body == {"input": {"messages": {"text": "hello"}}}


def test_inline_documents_labels_provenance():
    request = AgentRequest(
        probe_id="P", prompt="summarise this",
        documents=[DocumentSpec(name="a.html", content="BODY", url="https://x.test/a")],
    )
    text = inline_documents(request)
    assert "summarise this" in text
    assert "<retrieved_document" in text and "BODY" in text
    assert "https://x.test/a" in text, "the reader must be able to see where it came from"


def test_inline_documents_is_a_noop_without_documents():
    request = AgentRequest(probe_id="P", prompt="hi")
    assert inline_documents(request) == "hi"


# -- live HTTP round trip ---------------------------------------------------


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        payload = json.loads(self.rfile.read(length) or b"{}")
        self.server.last_request = payload
        self.server.last_headers = dict(self.headers)
        body = json.dumps({
            "data": {"reply": f"echo: {payload.get('message', '')[:40]}"},
            "trace": {"actions": [
                {"name": "web_fetch", "arguments": {"url": "http://169.254.169.254/"}}
            ]},
        }).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture
def http_server():
    server = HTTPServer(("127.0.0.1", 0), _Handler)
    server.last_request = None
    server.last_headers = {}
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server
    server.shutdown()
    server.server_close()


def test_http_adapter_sends_and_reads_configured_paths(http_server):
    url = f"http://127.0.0.1:{http_server.server_address[1]}/api"
    adapter = HttpJsonAdapter(url=url, prompt_field="message", response_path="data.reply")
    response = adapter.send(AgentRequest(probe_id="P", prompt="hello there", run_id="RUN1"))
    assert response.ok and response.text.startswith("echo: hello there")
    assert http_server.last_request["message"] == "hello there"


def test_http_adapter_identifies_itself_by_default(http_server):
    """A defender must be able to tell an authorized test from an attack."""
    url = f"http://127.0.0.1:{http_server.server_address[1]}/api"
    adapter = HttpJsonAdapter(url=url)
    adapter.send(AgentRequest(probe_id="PI-DIR-001", prompt="hi", run_id="RUN1"))
    headers = {k.lower(): v for k, v in http_server.last_headers.items()}
    assert headers["x-sinon-run"] == "RUN1"
    assert headers["x-sinon-probe"] == "PI-DIR-001"
    assert headers["x-sinon-purpose"] == "authorized-security-test"


def test_http_adapter_can_be_told_not_to_identify(http_server):
    url = f"http://127.0.0.1:{http_server.server_address[1]}/api"
    adapter = HttpJsonAdapter(url=url, identify=False)
    adapter.send(AgentRequest(probe_id="P", prompt="hi", run_id="RUN1"))
    headers = {k.lower() for k in http_server.last_headers}
    assert "x-sinon-run" not in headers


def test_http_adapter_parses_a_reported_action_trace(http_server):
    url = f"http://127.0.0.1:{http_server.server_address[1]}/api"
    adapter = HttpJsonAdapter(url=url, tool_calls_path="trace.actions")
    response = adapter.send(AgentRequest(probe_id="P", prompt="hi"))
    assert [c.name for c in response.tool_calls] == ["web_fetch"]


def test_http_adapter_reports_transport_failure_as_an_error():
    adapter = HttpJsonAdapter(url="http://127.0.0.1:1/api", timeout=1.0)
    response = adapter.send(AgentRequest(probe_id="P", prompt="hi"))
    assert not response.ok and "could not reach" in response.error


# -- CLI adapter ------------------------------------------------------------


def test_cli_adapter_text_protocol_round_trip():
    adapter = adapters.build({"kind": "cli", "command": f"{sys.executable} -c "
                              "\"import sys;print('reply:'+sys.stdin.read()[:20])\""})
    response = adapter.send(AgentRequest(probe_id="P", prompt="hello"))
    assert response.ok and response.text.startswith("reply:hello")


def test_cli_adapter_json_protocol_executes_tool_calls(tmp_path):
    script = tmp_path / "agent.py"
    script.write_text(
        "import json,sys\n"
        "env=json.load(sys.stdin)\n"
        "if not env.get('tool_results'):\n"
        "    print(json.dumps({'text':'working','tool_calls':["
        "{'name':'run_command','arguments':{'command':'id'}}]}))\n"
        "else:\n"
        "    print(json.dumps({'text':'done'}))\n",
        encoding="utf-8",
    )
    adapter = adapters.build(
        {"kind": "cli", "command": f"{sys.executable} {script}", "protocol": "json"}
    )
    calls = []

    def runner(name, args):
        call = ToolCall(name=name, arguments=args, result="ok", tripwire=True)
        calls.append(call)
        return call

    response = adapter.send(
        AgentRequest(probe_id="P", prompt="go", tools=[
            ToolDef(name="run_command", description="d", parameters={})
        ]),
        tool_runner=runner,
    )
    assert response.ok
    assert [c.name for c in response.tool_calls] == ["run_command"]
    assert "done" in response.text


def test_cli_adapter_reports_a_missing_command():
    adapter = adapters.build({"kind": "cli", "command": "definitely-not-a-real-binary-xyz"})
    response = adapter.send(AgentRequest(probe_id="P", prompt="hi"))
    assert not response.ok and "command not found" in response.error


def test_windows_paths_survive_command_splitting(monkeypatch):
    """POSIX shlex eats backslashes; a Windows command path must not lose them."""
    from sinon.adapters import cli as cli_mod

    monkeypatch.setattr(cli_mod.os, "name", "nt")
    assert cli_mod.split_command(r"C:\Tools\agent.exe --stdin") == [
        r"C:\Tools\agent.exe", "--stdin"
    ]
    assert cli_mod.split_command(r'"C:\Program Files\a b\agent.exe" run') == [
        r"C:\Program Files\a b\agent.exe", "run"
    ]


def test_posix_command_splitting_is_unchanged(monkeypatch):
    from sinon.adapters import cli as cli_mod

    monkeypatch.setattr(cli_mod.os, "name", "posix")
    assert cli_mod.split_command("python3 -c 'import sys'") == ["python3", "-c", "import sys"]
