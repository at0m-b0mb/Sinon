"""JSON serialisation --- the format everything else is built from.

Two audiences. A machine reading results in CI wants stable keys and no prose;
a person re-opening a run six months later wants enough context to reconstruct
what happened without the original terminal. Both get the same document.

The one judgement call worth naming: canaries are written out in full. They are
single-use tokens tied to one probe in one run, they are the evidence a finding
rests on, and a report that redacted them could not be verified by the person
receiving it. The HTML report masks them for on-screen display; the JSON keeps
them.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List

from ..model import ProbeResult, RunResult, Verdict, excerpt
from ..scoring import Score, score_run

SCHEMA_VERSION = 1


def probe_to_dict(result: ProbeResult, include_response: bool = True) -> Dict[str, Any]:
    probe = result.probe
    data: Dict[str, Any] = {
        "id": probe.id,
        "title": probe.title,
        "family": probe.family.value,
        "technique": probe.technique,
        "channel": probe.channel.value,
        "severity": probe.severity.value,
        "verdict": result.verdict.value,
        "confidence": result.confidence.value,
        "owasp": probe.owasp,
        "atlas": probe.atlas,
        "tags": probe.tags,
        "duration_ms": round(result.duration_ms, 1),
        "canary": result.canary,
        "oracles": [
            {
                "kind": o.kind,
                "fired": o.fired,
                "confidence": o.confidence.value,
                "evidence": o.evidence,
                "describe": o.describe,
            }
            for o in result.oracle_results
        ],
        "tool_calls": [
            {
                "name": c.name,
                "arguments": c.arguments,
                "tripwire": c.tripwire,
                "tripwire_reason": c.tripwire_reason,
                "result": excerpt(c.result, 500),
            }
            for c in result.tool_calls
        ],
        "sink_hits": [
            {"method": h.method, "path": h.path, "query": h.query, "body": excerpt(h.body, 500)}
            for h in result.sink_hits
        ],
        "expected": probe.expected,
        "remediation": probe.remediation,
        "references": probe.references,
        "source_path": probe.source_path,
    }
    if result.skip_reason:
        data["skip_reason"] = result.skip_reason
    if result.error:
        data["error"] = result.error
    if include_response:
        data["request"] = {
            "prompt": result.rendered_prompt,
            "payload": result.rendered_payload,
        }
        data["response"] = {
            "text": result.response.text if result.response else "",
            "latency_ms": round(result.response.latency_ms, 1) if result.response else 0.0,
        }
    return data


def score_to_dict(score: Score) -> Dict[str, Any]:
    return {
        "grade": score.grade,
        "arithmetic_grade": score.arithmetic_grade,
        "score": round(score.score, 1),
        "headline": score.headline,
        "coverage": round(score.coverage, 4),
        "exposure": score.exposure,
        "possible": score.possible,
        "counts": {
            "total": score.total,
            "failed": score.failed,
            "passed": score.passed,
            "skipped": score.skipped,
            "errored": score.errored,
        },
        "findings_by_severity": score.severity_counts,
        "findings_by_confidence": {
            "deterministic": score.deterministic_findings,
            "heuristic": score.heuristic_findings,
        },
        "ceilings": [{"grade": c.grade, "reason": c.reason} for c in score.ceilings],
        "by_family": _breakdowns(score.by_family),
        "by_channel": _breakdowns(score.by_channel),
        "by_severity": _breakdowns(score.by_severity),
        "notes": score.notes,
    }


def _breakdowns(store) -> Dict[str, Any]:
    return {
        key: {
            "total": b.total,
            "failed": b.failed,
            "passed": b.passed,
            "skipped": b.skipped,
            "errored": b.errored,
            "coverage": round(b.coverage, 4),
            "fail_rate": round(b.fail_rate, 4),
        }
        for key, b in sorted(store.items())
    }


def engagement_to_dict(engagement) -> Dict[str, Any]:
    if engagement is None or not getattr(engagement, "is_declared", False):
        return {"declared": False}
    return {
        "declared": True,
        "client": engagement.client,
        "authorized_by": engagement.authorized_by,
        "authorization_ref": engagement.authorization_ref,
        "contact": engagement.contact,
        "window": {
            "start": str(engagement.window.start) if engagement.window.start else "",
            "end": str(engagement.window.end) if engagement.window.end else "",
        },
        "scope_allow_hosts": engagement.allow_hosts,
        "identify_requests": engagement.identify_requests,
        "source_path": engagement.source_path,
    }


def run_to_dict(run: RunResult, score: Score = None, selected_total: int = None) -> Dict[str, Any]:
    score = score or score_run(run, selected_total)
    return {
        "schema_version": SCHEMA_VERSION,
        "tool": "sinon",
        "sinon_version": run.sinon_version,
        "run_id": run.run_id,
        "started_at": run.started_at,
        "finished_at": run.finished_at,
        "target": {"name": run.target_name, "kind": run.target_kind},
        "engagement": engagement_to_dict(run.engagement),
        "score": score_to_dict(score),
        "notes": run.notes,
        "results": [probe_to_dict(r) for r in run.results],
    }


def dumps(run: RunResult, score: Score = None, selected_total: int = None, indent: int = 2) -> str:
    return json.dumps(run_to_dict(run, score, selected_total), indent=indent, ensure_ascii=False)


def write(path: str, run: RunResult, score: Score = None, selected_total: int = None) -> str:
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(dumps(run, score, selected_total))
    return path


def load(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)
