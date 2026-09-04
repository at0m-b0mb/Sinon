# Changelog

All notable changes to this project are documented here. This project follows
[Semantic Versioning](https://semver.org/). The corpus format has its own
version (`CORPUS_SCHEMA_VERSION`), bumped only when a change would break an
existing probe file.

## [1.0.0] — 2026-09-04

First release.

### Methodology

- A documented, repeatable process for assessing an LLM agent: scope and
  authorization, trust-boundary mapping, baseline, full run, triage by cause,
  reporting, re-test ([docs/methodology.md](docs/methodology.md))
- Three commitments the tool enforces rather than merely states: a verdict is an
  observed fact, a skip is never a pass, a pass is not safety

### Corpus

- 54 probes across three families — 24 prompt injection, 15 tool abuse, 15
  over-permissioned actions — mapped to OWASP LLM Top 10 and MITRE ATLAS
- Six delivery channels; 40 of 54 probes arrive through content rather than the
  user turn
- Obfuscation coverage: base64, ROT13, zero-width characters, homoglyphs,
  non-English instructions, CSS-hidden text, payloads split across two sources

### Engine

- Transform-aware canary detection: literal, base64, ROT13, reversed, hex,
  separator-tolerant, and canaries hidden inside a larger encoded blob
- 16 instrumented tools with conditional and unconditional tripwires; nothing
  touches the real world
- 14 oracles, each declaring deterministic or heuristic confidence; a probe may
  lower a confidence but never raise it
- Loopback-only exfiltration sink
- Severity-weighted scoring with grade ceilings, coverage caps and no A+

### Targets

- `reference` — a deterministic rule-based stand-in with three security postures
- `openai` — any chat-completions endpoint, with a real tool loop
- `http` — any JSON agent, with optional action-trace parsing
- `cli` — local command, text or JSON protocol
- MCP server plus `sinon judge`, for agents that cannot be scripted

### Reporting

- Self-contained HTML report, JSON, Markdown and SARIF 2.1.0
- CI-friendly exit codes and a `--fail-on` threshold

### Safety

- Engagement gate: no non-local target without authorization, scope and an
  in-date window; no `--force`
- Requests identifiable by default; suppression requires explicit sign-off and
  is printed in the banner and the report

[1.0.0]: https://github.com/at0m-b0mb/Sinon/releases/tag/v1.0.0
