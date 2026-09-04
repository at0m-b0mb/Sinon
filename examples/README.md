# Examples

| File | What it is |
|---|---|
| [`engagement.yaml`](engagement.yaml) | A filled-in engagement file. Sinon refuses any non-local target without one. |
| [`agent_shim.py`](agent_shim.py) | Twenty lines implementing the CLI adapter's JSON protocol, so an agent you can run but not import gets full tool telemetry. |
| [`github-actions.yml`](github-actions.yml) | A CI job that starts an agent, runs the corpus and uploads SARIF to code scanning. |

Try the shim against the real harness:

```bash
sinon run --target cli --command 'python3 examples/agent_shim.py' \
    --cli-protocol json --id TA-SSRF-001 --no-color
```

It fetches whatever URL it finds in the content it was handed, which is exactly
the behaviour `TA-SSRF-001` is looking for.
