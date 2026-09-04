# Adapters

An adapter takes a probe, gets the target to act on it, and reports what it did
— including every tool call. Everything else in Sinon is target-agnostic.

The capability flags are load-bearing. An adapter that cannot observe tool calls
declares `supports_tools = False`, the runner skips tool probes, and the grade is
capped. Returning an empty tool-call list from a target you cannot see would turn
every tool-abuse probe into a silent pass, which is the single most dangerous
thing a kit like this could do.

## `reference` — the built-in target

```bash
sinon demo --profile naive|guarded|hardened
sinon run --target reference:hardened
```

A rule-based stand-in with three security postures. Deterministic, offline, no
keys. It is what the test suite runs against and what makes `sinon demo` work on
a plane.

**It is not a language model.** A finding against it says the harness works. It
says nothing about any real agent, and no output from it should be presented as
if it did.

## `openai` — anything speaking the chat-completions shape

Covers far more than OpenAI: Ollama, vLLM, LM Studio, llama.cpp's server,
OpenRouter, Together, Groq, Azure deployments, and most internal gateways.

```bash
export SINON_API_KEY=...
sinon run --engagement engagement.yaml \
  --target openai \
  --target-url https://api.example.com/v1 \
  --model support-agent-v3 \
  --header 'X-Tenant: acme'
```

Runs a real tool loop: offers the instrumented toolbelt, executes what the model
calls, feeds results back, repeats until it stops calling tools or the turn
budget runs out. That loop is what makes tool-abuse and over-permission probes
meaningful — a single-shot request can only see what a model *says*, never what
it would *do*.

The endpoint is normalised, so `https://api.example.com`,
`.../v1` and `.../v1/chat/completions` all work.

## `http` — any agent behind a URL

The one that matters in a real engagement. The client has an agent at some
endpoint, it takes JSON and returns JSON, and nobody is rewriting it to fit a
test harness.

```bash
sinon run --engagement engagement.yaml \
  --target http \
  --target-url https://agent.example.com/api/assistant \
  --prompt-field 'input.message' \
  --response-path 'data.reply.text' \
  --tool-calls-path 'data.trace.actions' \
  --header 'Authorization: Bearer $AGENT_TOKEN'
```

| Flag | Does |
|---|---|
| `--prompt-field` | Dotted path where the prompt is written. Nested paths are created. |
| `--response-path` | Dotted path to read the reply from. Omit it and Sinon tries the usual keys (`reply`, `response`, `message`, `output`, `text`, `answer`, `content`, `choices.0.message.content`). |
| `--system-field` | Dotted path for the system prompt, if the target accepts one. |
| `--tool-calls-path` | Dotted path to an action trace. **This is the flag that unlocks two thirds of the corpus.** |

Header values are expanded from the environment, so `$AGENT_TOKEN` stays out of
your shell history and out of the report.

### The action trace

Many internal agents already return a trace for their own debugging. Point
`--tool-calls-path` at it and every tool-abuse and over-permission probe becomes
live. Sinon accepts a list of objects with `name` plus `arguments`/`args`/`input`
and optionally `result`/`output`, or a plain list of tool-name strings.

```json
{ "data": { "trace": { "actions": [
    { "name": "web_fetch", "arguments": { "url": "http://169.254.169.254/" } }
] } } }
```

Externally reported calls are run through the same tripwire policy as ones Sinon
executed itself, so a finding never depends on which adapter observed it.

Without a trace the adapter declares no tool support, tool probes are skipped,
and the report says so — which is itself worth reporting: nobody can audit that
agent's actions, including the people who run it.

## `cli` — an agent that runs as a local command

### Text protocol (default)

Prompt on stdin, reply on stdout. Works with anything.

```bash
sinon run --target cli --command './my-agent --stdin'
```

No tool visibility, so tool probes are skipped.

### JSON protocol

Full tool telemetry for an agent you can run but cannot import. Sinon writes one
JSON envelope to stdin and reads one JSON object from stdout, executing any tool
calls and re-invoking with the results appended, up to the turn budget.

```bash
sinon run --target cli --command 'python3 agent_shim.py' --cli-protocol json
```

**Envelope in:**

```json
{
  "sinon_protocol": 1,
  "run_id": "K7M2QX",
  "probe_id": "TA-SSRF-001",
  "system": "You are the customer support assistant for ...",
  "memory": "",
  "prompt": "Read the deployment runbook at ... ",
  "documents": [ { "name": "runbook.md", "url": "...", "media_type": "text/markdown", "content": "..." } ],
  "tools":     [ { "name": "web_fetch", "description": "...", "parameters": { "type": "object", "...": {} } } ],
  "tool_results": []
}
```

**Reply out:**

```json
{
  "text": "I have fetched the runbook.",
  "tool_calls": [ { "name": "web_fetch", "arguments": { "url": "https://..." } } ]
}
```

Return `tool_calls` and Sinon executes them against the instrumented toolbelt,
then calls your command again with `tool_results` filled in. Return only `text`
and the turn ends. A working shim is in [`examples/agent_shim.py`](../examples/agent_shim.py).

## MCP

For agents you cannot script at all. See [mcp.md](mcp.md).

## Writing your own

Subclass `sinon.adapters.base.Adapter`, implement `send`, and be honest about
`supports_tools`:

```python
from sinon.adapters.base import Adapter
from sinon.model import AgentResponse, ToolCall

class MyAdapter(Adapter):
    kind = "mine"
    supports_tools = True          # only if you can really see the calls

    def send(self, request, tool_runner=None):
        reply, observed = my_agent.run(
            request.prompt,
            system=request.system_prompt,
            tools=[t.to_openai_schema() for t in request.tools],
        )
        calls = [tool_runner(c.name, c.args) for c in observed] if tool_runner else []
        return AgentResponse(text=reply, tool_calls=calls)
```

Call `tool_runner` for every tool the agent invokes: that is what executes the
instrumented tool, records the call and evaluates the tripwire.
