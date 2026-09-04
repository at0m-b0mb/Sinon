"""Runner behaviour: skipping honestly, canary hygiene, repeat semantics."""

from sinon import corpus as corpus_mod
from sinon.adapters.base import Adapter
from sinon.model import AgentResponse, Verdict
from sinon.runner import Runner, RunOptions


class Echo(Adapter):
    """Repeats whatever it is given. Cannot see tools."""

    kind = "echo"
    supports_tools = False

    def __init__(self, reply=""):
        super().__init__(name="echo")
        self.reply = reply
        self.requests = []

    def send(self, request, tool_runner=None):
        self.requests.append(request)
        return AgentResponse(text=self.reply or request.prompt)


class Toolless(Echo):
    pass


class Flaky(Adapter):
    """Fails the injection on the first call only."""

    kind = "flaky"
    supports_tools = True

    def __init__(self):
        super().__init__(name="flaky")
        self.calls = 0

    def send(self, request, tool_runner=None):
        self.calls += 1
        canary = ""
        for token in request.prompt.split():
            if token.startswith("SINON-"):
                canary = token
        return AgentResponse(text=canary if self.calls == 1 else "I cannot do that.")


class Boom(Adapter):
    kind = "boom"
    supports_tools = True

    def send(self, request, tool_runner=None):
        raise RuntimeError("connection reset")


def test_tool_probes_are_skipped_not_passed_when_the_target_is_blind(probes_by_id):
    probe = probes_by_id["TA-SSRF-001"]
    result = Runner(Toolless()).run_probe(probe, "RUN")
    assert result.verdict is Verdict.SKIP
    assert "no tool telemetry" in result.skip_reason


def test_sink_probes_are_skipped_without_a_sink(probes_by_id):
    probe = probes_by_id["OP-EXFIL-002"]
    runner = Runner(Toolless(), sink=None)
    result = runner.run_probe(probe, "RUN")
    assert result.verdict is Verdict.SKIP


def test_canaries_are_unique_per_probe_and_run(probes):
    agent = Echo()
    run_a = Runner(agent).run(probes[:6])
    run_b = Runner(agent).run(probes[:6])
    canaries = [r.canary for r in run_a.results + run_b.results if r.canary]
    assert len(canaries) == len(set(canaries))


def test_content_and_system_canaries_differ(probes_by_id):
    result = Runner(Echo()).run_probe(probes_by_id["PI-DIR-001"], "RUN")
    assert result.canary and result.system_canary
    assert result.canary != result.system_canary


def test_default_system_prompt_carries_the_system_canary(probes_by_id):
    agent = Echo()
    result = Runner(agent).run_probe(probes_by_id["PI-SYS-001"], "RUN")
    assert result.system_canary in agent.requests[0].system_prompt


def test_repeat_reports_the_worst_outcome(probes_by_id):
    """An attack that lands one time in three is a finding, not a flake."""
    probe = probes_by_id["PI-DIR-001"]
    agent = Flaky()
    result = Runner(agent, options=RunOptions(repeat=3)).run_probe(probe, "RUN")
    assert result.verdict is Verdict.FAIL
    assert agent.calls == 1, "a failure short-circuits the remaining attempts"


def test_repeat_needs_every_attempt_to_pass(probes_by_id):
    class AlwaysSafe(Echo):
        supports_tools = True

    agent = AlwaysSafe(reply="I cannot help with that.")
    result = Runner(agent, options=RunOptions(repeat=3)).run_probe(
        probes_by_id["PI-DIR-001"], "RUN"
    )
    assert result.verdict is Verdict.PASS


def test_adapter_exceptions_become_errors_not_passes(probes_by_id):
    result = Runner(Boom()).run_probe(probes_by_id["PI-DIR-001"], "RUN")
    assert result.verdict is Verdict.ERROR
    assert "connection reset" in result.error


def test_transport_error_response_becomes_an_error(probes_by_id):
    class Broken(Adapter):
        kind = "broken"
        supports_tools = True

        def send(self, request, tool_runner=None):
            return AgentResponse(error="HTTP 502")

    result = Runner(Broken()).run_probe(probes_by_id["PI-DIR-001"], "RUN")
    assert result.verdict is Verdict.ERROR


def test_dry_run_builds_the_request_without_sending(probes_by_id):
    agent = Echo()
    runner = Runner(agent, options=RunOptions(dry_run=True))
    result = runner.run_probe(probes_by_id["PI-DIR-001"], "RUN")
    assert result.verdict is Verdict.SKIP
    assert result.rendered_prompt and not agent.requests


def test_placeholders_are_rendered_before_sending(probes_by_id):
    agent = Echo()
    Runner(agent).run_probe(probes_by_id["PI-DIR-001"], "RUN")
    prompt = agent.requests[0].prompt
    assert "{{" not in prompt, "an unrendered placeholder means a dead probe"
    assert "SINON-" in prompt


def test_stop_after_halts_the_run_and_says_so(probes):
    class AlwaysFail(Adapter):
        kind = "fail"
        supports_tools = True

        def send(self, request, tool_runner=None):
            canary = [t for t in request.prompt.split() if t.startswith("SINON-")]
            return AgentResponse(text=canary[0] if canary else "")

    run = Runner(AlwaysFail(), options=RunOptions(stop_after_findings=1)).run(probes)
    assert len(run.results) < len(probes)
    assert any("stopped early" in n for n in run.notes)


def test_capability_notes_explain_a_blind_target(probes):
    run = Runner(Toolless()).run(probes[:5])
    joined = " ".join(run.notes)
    assert "does not expose tool calls" in joined
    assert "capped" in joined
