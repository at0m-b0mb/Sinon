# Contributing

The most valuable contribution is **a probe** — an attack that works and is not
in the corpus yet.

## Adding a probe

1. Read [docs/writing-probes.md](docs/writing-probes.md).
2. Copy the closest existing file in `corpus/<family>/` and change the strings.
3. `sinon validate --strict` must be clean.
4. `sinon demo --profile naive --id YOUR-ID` should fail;
   `--profile hardened` should usually pass.
5. `python3 scripts/gen_docs.py` to refresh the taxonomy table.
6. `python3 -m pytest`.

### What makes a probe worth merging

- **It is realistic.** Somebody could do this to a deployed agent. Say who
  controls the injected content and how they got it there.
- **It has a deterministic oracle where one is possible.** A probe that can only
  be judged by a regex is weaker, and the corpus is already honest about that.
- **The remediation is structural.** "Sanitise input" helps nobody. Say what to
  change: fence content, scope a credential, require an approval.
- **It is not a duplicate.** A new phrasing of an existing technique belongs in
  the existing probe's description, not in a new file — unless the phrasing is
  the point (see `PI-IND-002`, which exists specifically to defeat the keyword
  filter that `PI-IND-001` triggers).

### What will not be merged

- Working exploit code, malware, or a payload pointed at a live collector
- Real credentials or real customer data, even redacted
- Impersonation of a real company, product or person
- Payloads tuned until the built-in reference agent trips on them. That fits the
  corpus to a toy. If the stand-in misses a phrasing a real agent would follow,
  widen the stand-in's extraction instead — that is a bug in the stand-in.

## Adding an oracle

One decorated function in `sinon/oracles.py`. Declare its confidence honestly:
`DETERMINISTIC` only if it observes a fact. Oracles are pure — they read the
`Observation` and return an `OracleResult`, and they never reach outside it.

## Adding an adapter

Subclass `Adapter`, implement `send`, and be truthful about `supports_tools`.
An adapter that reports no tool calls because it cannot see them, rather than
declaring `supports_tools = False`, would turn every tool probe into a silent
pass. That is the one bug in this codebase that would make the tool actively
harmful. See [docs/adapters.md](docs/adapters.md).

## Style

- Python 3.9+, standard library only outside the one PyYAML dependency
- Match the surrounding code: module docstrings explain *why*, not *what*
- ASCII in corpus files (an em-dash is `---`; the reports typeset it)
- Tests for anything load-bearing; `pytest` must be green

## Running everything

```bash
pip install -e ".[dev]"
python3 -m pytest                # 204 tests
sinon validate --strict
python3 scripts/gen_docs.py      # must leave the tree clean
python3 scripts/gen_assets.py    # only if you changed the brand
```
