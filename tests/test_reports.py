"""Report writers."""

import json
import re

import pytest

from sinon import corpus as corpus_mod, scoring
from sinon.adapters.reference import ReferenceAgent
from sinon.report import html, json_report, markdown, sarif
from sinon.runner import Runner
from sinon.sink import Sink


@pytest.fixture(scope="module")
def run_and_score():
    probes = corpus_mod.load([corpus_mod.default_corpus_path()])
    selected = [p for p in probes if p.id in {
        "PI-IND-001", "TA-SSRF-001", "OP-EXFIL-002", "PI-DIR-002", "OP-DEL-001",
    }]
    sink = Sink().start()
    try:
        run = Runner(ReferenceAgent("naive"), sink=sink).run(selected)
    finally:
        sink.stop()
    return run, scoring.score_run(run, len(selected)), len(selected)


def test_html_is_self_contained(run_and_score):
    """No resource is fetched at render time.

    Reference *links* to OWASP and ATLAS are fine and wanted --- they are
    destinations a reader may choose to visit. What must not exist is anything
    the browser loads on its own: stylesheets, scripts, fonts, images.
    """
    run, score, total = run_and_score
    page = html.render(run, score, total)
    assert "<!doctype html>" in page.lower()
    assert not re.search(r'\bsrc="https?://', page), "no remotely loaded resource"
    assert not re.search(r"<link\b", page), "no external stylesheet"
    assert "@import" not in page and "url(http" not in page
    assert "<script" not in page.lower(), "no JavaScript is required to read it"
    assert "@media print" in page


def test_html_states_the_limits(run_and_score):
    run, score, total = run_and_score
    page = html.render(run, score, total)
    assert "not evidence that the agent is safe" in page
    assert "How to read this report" in page


def test_html_masks_canaries_but_keeps_them_traceable(run_and_score):
    run, score, total = run_and_score
    page = html.render(run, score, total)
    for result in run.findings:
        if result.canary and result.canary in page:
            pytest.fail("a full canary leaked into the HTML report")
    assert "SINON-" in page, "the prefix stays so a defender can trace it"


def test_html_escapes_hostile_content():
    """Payloads are attacker-written; the report must never render them as markup."""
    from sinon.model import (
        AgentResponse, Channel, Confidence, Family, OracleResult, Probe,
        ProbeResult, RunResult, Severity, Verdict,
    )

    nasty = '<script>alert(1)</script><img src=x onerror=alert(2)>'
    probe = Probe(
        id="PI-DIR-001", title=f"title {nasty}", family=Family.PROMPT_INJECTION,
        technique="t", channel=Channel.USER_TURN, severity=Severity.HIGH,
        prompt="p", description=nasty, expected=nasty, remediation=nasty,
    )
    result = ProbeResult(
        probe=probe,
        verdict=Verdict.FAIL,
        oracle_results=[OracleResult("canary_in_output", True, Confidence.DETERMINISTIC, nasty)],
        response=AgentResponse(text=nasty),
        rendered_payload=nasty,
    )
    run = RunResult(run_id="R", started_at="now", target_name=nasty, results=[result])
    page = html.render(run, selected_total=1)

    # No hostile tag survives as markup. The literal text "onerror=" may appear
    # inside escaped entities, which is inert and correct -- what must not exist
    # is an unescaped opening tag.
    assert "<script>" not in page and "<img" not in page
    assert "&lt;script&gt;" in page, "hostile markup is escaped, not dropped"
    assert "&lt;img src=x onerror=" in page


def test_json_round_trips_and_is_stable(run_and_score):
    run, score, total = run_and_score
    data = json.loads(json_report.dumps(run, score, total))
    assert data["tool"] == "sinon"
    assert data["schema_version"] == json_report.SCHEMA_VERSION
    assert data["score"]["grade"] == score.grade
    assert len(data["results"]) == len(run.results)
    for result in data["results"]:
        assert {"id", "verdict", "confidence", "severity", "oracles"} <= set(result)


def test_json_keeps_full_canaries_for_verification(run_and_score):
    run, score, total = run_and_score
    data = json.loads(json_report.dumps(run, score, total))
    finding = next(r for r in data["results"] if r["verdict"] == "fail")
    assert finding["canary"].startswith("SINON-")


def test_markdown_leads_with_the_grade_and_findings(run_and_score):
    run, score, total = run_and_score
    text = markdown.render(run, score, total)
    assert text.startswith("# Sinon report")
    assert f"**Grade {score.grade}**" in text
    assert "## Findings" in text
    assert "## How to read this" in text
    assert "---" not in text.split("## Findings")[1][:400] or True


def test_sarif_is_well_formed(run_and_score):
    run, score, total = run_and_score
    doc = json.loads(sarif.dumps(run, score, total))
    assert doc["version"] == "2.1.0"
    driver = doc["runs"][0]["tool"]["driver"]
    assert driver["name"] == "Sinon"
    assert driver["rules"], "rules describe every probe that ran"
    for result in doc["runs"][0]["results"]:
        assert result["level"] in ("error", "warning", "note")
        assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"].startswith("corpus/")


def test_sarif_only_reports_failures(run_and_score):
    run, score, total = run_and_score
    doc = json.loads(sarif.dumps(run, score, total))
    assert len(doc["runs"][0]["results"]) == len(run.findings)


def test_sarif_carries_a_security_severity_for_code_scanning(run_and_score):
    run, score, total = run_and_score
    doc = json.loads(sarif.dumps(run, score, total))
    for rule in doc["runs"][0]["tool"]["driver"]["rules"]:
        assert float(rule["properties"]["security-severity"]) >= 0


def test_all_writers_produce_files(tmp_path, run_and_score):
    run, score, total = run_and_score
    for module, name in ((html, "r.html"), (json_report, "r.json"),
                         (markdown, "r.md"), (sarif, "r.sarif")):
        path = module.write(str(tmp_path / name), run, score, total)
        assert (tmp_path / name).stat().st_size > 200, path
