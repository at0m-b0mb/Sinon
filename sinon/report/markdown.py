"""Markdown report --- the one that gets pasted into a ticket.

Deliberately plain. It has to survive being pasted into Jira, a GitHub issue, a
Slack message and a Word document, so there are no tables that need alignment,
no HTML, and no characters that a corporate mail client will mangle.

The ordering is the argument: what was found, how bad, what to do, and only then
what was tested and what could not be. Somebody who reads the first screen and
stops should still come away with the right conclusion.
"""

from __future__ import annotations

from typing import List

from ..model import RunResult, Verdict, excerpt
from ..scoring import Score, score_run
from ..version import __version__


def _typo(text: str) -> str:
    """Probe files spell an em-dash ``---``; Markdown readers want the character."""
    return (text or "").replace(" --- ", " \u2014 ").replace("---", "\u2014")


def render(run: RunResult, score: Score = None, selected_total: int = None) -> str:
    score = score or score_run(run, selected_total)
    out: List[str] = []
    add = out.append

    add(f"# Sinon report --- {run.target_name}")
    add("")
    add(f"**Grade {score.grade}** &middot; {score.headline}")
    add("")
    add(f"- Run: `{run.run_id}` ({run.started_at} to {run.finished_at or 'incomplete'})")
    add(f"- Target: {run.target_name} ({run.target_kind})")
    add(f"- Corpus coverage: {score.coverage:.0%} ({score.passed + score.failed} of {score.total} probes executed)")
    add(f"- Sinon {run.sinon_version or __version__}")

    engagement = run.engagement
    if engagement is not None and getattr(engagement, "is_declared", False):
        add("")
        add("## Authorization")
        add("")
        add(f"- Client: {engagement.client}")
        add(f"- Authorized by: {engagement.authorized_by}")
        add(f"- Reference: {engagement.authorization_ref}")
        add(f"- Window: {engagement.window.describe()}")
        add(f"- In-scope hosts: {', '.join(engagement.allow_hosts) or 'none declared'}")
        if not engagement.identify_requests:
            add(
                "- **Requests were not identified** as tests "
                f"({engagement.suppress_identification_reason or 'no reason recorded'})"
            )

    add("")
    add("## Result")
    add("")
    add(f"- Findings: {score.failed}")
    for severity in ("critical", "high", "medium", "low"):
        count = score.severity_counts.get(severity, 0)
        if count:
            add(f"  - {severity}: {count}")
    add(f"- Passed: {score.passed}")
    add(f"- Skipped (target could not answer): {score.skipped}")
    if score.errored:
        add(f"- Errored: {score.errored}")
    if score.ceilings:
        add("")
        add("Grade ceilings applied:")
        for ceiling in score.ceilings:
            add(f"- Capped at {ceiling.grade} --- {ceiling.reason}")

    findings = run.findings
    if findings:
        add("")
        add("## Findings")
        for index, result in enumerate(findings, start=1):
            probe = result.probe
            add("")
            add(f"### {index}. [{probe.severity.value.upper()}] {probe.id} --- {probe.title}")
            add("")
            add(f"- Family: {probe.family.label} &middot; channel: {probe.channel.label}")
            add(f"- Confidence: {result.confidence.value}")
            if probe.owasp:
                add(f"- OWASP LLM: {', '.join(probe.owasp)}")
            if probe.atlas:
                add(f"- MITRE ATLAS: {', '.join(probe.atlas)}")
            add("")
            if probe.description:
                add(_typo(probe.description.strip()))
                add("")
            add("**Evidence**")
            add("")
            for oracle in result.fired_oracles:
                add(f"- `{oracle.kind}` ({oracle.confidence.value}): {oracle.evidence}")
            tripwires = [c for c in result.tool_calls if c.tripwire]
            for call in tripwires:
                add(f"- Tool `{call.name}` --- {call.tripwire_reason}")
            add("")
            if result.rendered_payload:
                add("**Payload**")
                add("")
                add("```")
                add(excerpt(result.rendered_payload, 700))
                add("```")
                add("")
            if result.response and result.response.text:
                add("**Agent response (excerpt)**")
                add("")
                add("```")
                add(excerpt(result.response.text, 700))
                add("```")
                add("")
            if probe.expected:
                add(f"**Expected behaviour.** {_typo(probe.expected.strip())}")
                add("")
            if probe.remediation:
                add("**Remediation**")
                add("")
                add(_typo(probe.remediation.strip()))
                add("")
            if probe.references:
                add("**References**")
                add("")
                for reference in probe.references:
                    add(f"- {reference}")

    skipped = run.by_verdict(Verdict.SKIP)
    if skipped:
        add("")
        add("## Not tested")
        add("")
        add(
            "These probes did not run. They are not passes --- they lower coverage "
            "and cap the grade."
        )
        add("")
        for result in skipped:
            add(f"- `{result.probe.id}` {result.probe.title} --- {result.skip_reason}")

    errored = run.by_verdict(Verdict.ERROR)
    if errored:
        add("")
        add("## Errors")
        add("")
        for result in errored:
            add(f"- `{result.probe.id}` --- {result.error}")

    passed = run.by_verdict(Verdict.PASS)
    if passed:
        add("")
        add("## Probes that did not produce a finding")
        add("")
        add(", ".join(f"`{r.probe.id}`" for r in passed))

    add("")
    add("## How to read this")
    add("")
    for note in score.notes:
        add(f"- {note}")
    if run.notes:
        add("")
        for note in run.notes:
            add(f"- {note}")

    add("")
    return "\n".join(out)


def write(path: str, run: RunResult, score: Score = None, selected_total: int = None) -> str:
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(render(run, score, selected_total))
    return path
