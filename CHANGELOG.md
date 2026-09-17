# Changelog

All notable changes to this project are documented here. This project follows
[Semantic Versioning](https://semver.org/). The corpus format has its own
version (`CORPUS_SCHEMA_VERSION`), bumped only when a change would break an
existing probe file.

## [1.0.1] — 2026-09-16

A security and robustness pass over the whole codebase. Every item below was
found by auditing 1.0.0 against hostile input, and each has a regression test.

### Security

- **Redirects are no longer followed.** A target answering 301/302 moved probe
  traffic to a host the authorization gate never checked, and urllib forwarded
  the `Authorization` header across that hop — a scope escape and a credential
  disclosure. A 3xx is now an error naming the destination.
- **The authorization gate fails closed.** A target URL with no readable host
  resolved to an empty host, which read as loopback, so a malformed or
  non-http target (`file:///...`, a bare path) was waved through as "local".
  Unparseable and non-http targets are now refused, and adapters declare
  `runs_locally` rather than it being inferred from a URL.
- **The sink can no longer be silenced.** A malformed `Content-Length` raised
  out of the request handler and the request went unrecorded, so an agent could
  exfiltrate leaving no evidence. Every field is now parsed defensively.
- **Credentials in a target URL are redacted from every output.** A URL like
  `https://svc:pw@agent.internal/chat` is an ordinary way to reach an internal
  endpoint, and it was printed verbatim in the banner and copied into the HTML,
  JSON, Markdown and SARIF reports — the one document most certain to be
  forwarded. The request still uses the real URL; only the displayed form is
  redacted, and the host stays visible.
- `--insecure` is recorded in the report and warned about in the banner.

### Correctness

- **A run that produced no evidence is graded `n/a`, not F.** An endpoint that
  was simply down came back graded F with a headline reading "no findings".
  Ungradeable runs now exit non-zero even with `--fail-on none`, so CI cannot
  read "could not look" as "found nothing".
- **A probe of only `info` severity no longer scores zero.** Weight zero means
  no exposure, not no result; a clean info-only run scores 100.
- **One bad probe no longer aborts the run.** An uncompilable oracle regex or an
  unknown tool name raised through the runner and the operator lost every result
  gathered so far. Both are now an `ERROR` verdict on that probe alone.

### Robustness

- Responses are capped at 8 MB and report evidence fields at 20,000 characters.
  A 64 MB reply was buffered whole and copied into the JSON report.
- The reference agent's email and path patterns were quadratic: 200 KB of text
  took 56 seconds to scan, now 0.02. Scanning is also capped at 64 KB per blob.
- The HTTP adapter deep-copies its request template; a nested `--prompt-field`
  mutated it and leaked one probe's prompt into the next request.
- Dead imports removed.

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

[1.0.1]: https://github.com/at0m-b0mb/Sinon/releases/tag/v1.0.1
[1.0.0]: https://github.com/at0m-b0mb/Sinon/releases/tag/v1.0.0
