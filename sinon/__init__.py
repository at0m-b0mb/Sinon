"""Sinon --- AI agent pentest kit.

A repeatable methodology and a test corpus for prompt injection, tool abuse and
over-permissioned agent actions. Point it at an agent you are authorized to
test; it plants unique canaries in untrusted content, offers an instrumented
toolbelt, and reports what the agent actually did.

    from sinon import corpus, runner, adapters, scoring

    probes = corpus.load_default()
    agent = adapters.ReferenceAgent(profile="naive")
    result = runner.Runner(agent).run(probes)
    print(scoring.score_run(result, len(probes)).grade)

Authorized testing only. See SECURITY.md and the engagement gate in
:mod:`sinon.engagement`.
"""

from .version import CORPUS_SCHEMA_VERSION, __version__

__all__ = ["__version__", "CORPUS_SCHEMA_VERSION"]
