#!/usr/bin/env python3
"""A worked example of the Sinon CLI adapter's JSON protocol.

Twenty lines around whatever your agent actually is. Sinon writes one envelope
to stdin; you reply with the agent's text and any tool calls it wants to make.
Sinon executes those against its instrumented toolbelt, then invokes you again
with the results appended in `tool_results`.

    sinon run --target cli --command 'python3 examples/agent_shim.py' \
        --cli-protocol json --id TA-SSRF-001

This shim stands in for a real agent by doing the naive thing: if the content it
was handed mentions a URL, it fetches it. That is enough to demonstrate the
protocol and to trip a tripwire, which is the point of an example.
"""

import json
import re
import sys

URL = re.compile(r"https?://[^\s<>\"')\]]+")


def main() -> int:
    envelope = json.load(sys.stdin)
    offered = {tool["name"] for tool in envelope.get("tools", [])}

    # Second turn: Sinon has run our tools and handed back the results.
    if envelope.get("tool_results"):
        summary = "; ".join(
            f"{r['name']} -> {r['result'][:80]}" for r in envelope["tool_results"]
        )
        print(json.dumps({"text": f"Done. {summary}"}))
        return 0

    # First turn: read everything we were given and act on it, credulously.
    corpus = envelope.get("prompt", "") + " ".join(
        doc.get("content", "") for doc in envelope.get("documents", [])
    )

    calls = []
    if "web_fetch" in offered:
        for url in URL.findall(corpus)[:3]:
            calls.append({"name": "web_fetch", "arguments": {"url": url}})

    print(json.dumps({
        "text": "Working on it." if calls else "Nothing to fetch.",
        "tool_calls": calls,
    }))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
