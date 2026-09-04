"""SARIF output, so findings land in the tools teams already watch.

SARIF 2.1.0 is what GitHub code scanning, Azure DevOps and most security
dashboards ingest. Emitting it means an agent-security regression shows up in
the same place as a dependency CVE, reviewed by the same people, instead of in a
report nobody opens twice.

The mapping needs one explanation. SARIF wants findings anchored to a file and a
line; a prompt-injection finding has no source location in the target, because
the target is a running service. So each result is anchored to the *probe file*
that found it --- the artifact that does exist in a repository, that a reviewer
can open, and that they would edit if the probe were wrong.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List

from ..model import Confidence, RunResult, Severity, Verdict, excerpt
from ..scoring import Score, score_run
from ..version import __version__

SARIF_VERSION = "2.1.0"
SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"

# SARIF has three levels; the corpus has five severities.
_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}

# GitHub's security-severity property drives the CVSS-style bucket shown in the
# code-scanning UI.
_SECURITY_SEVERITY = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "7.5",
    Severity.MEDIUM: "5.0",
    Severity.LOW: "3.0",
    Severity.INFO: "0.0",
}


def _rules(run: RunResult) -> List[Dict[str, Any]]:
    seen: Dict[str, Dict[str, Any]] = {}
    for result in run.results:
        probe = result.probe
        if probe.id in seen:
            continue
        tags = [probe.family.value, probe.channel.value, probe.technique or "unclassified"]
        tags += [f"owasp/{item}" for item in probe.owasp]
        tags += [f"atlas/{item}" for item in probe.atlas]
        tags += list(probe.tags)
        seen[probe.id] = {
            "id": probe.id,
            "name": probe.id.replace("-", ""),
            "shortDescription": {"text": probe.title},
            "fullDescription": {"text": probe.description or probe.title},
            "help": {
                "text": probe.remediation or "See the probe file for remediation guidance.",
                "markdown": _help_markdown(probe),
            },
            "defaultConfiguration": {"level": _LEVEL[probe.severity]},
            "properties": {
                "tags": [t for t in tags if t],
                "security-severity": _SECURITY_SEVERITY[probe.severity],
                "sinon-severity": probe.severity.value,
                "sinon-family": probe.family.value,
                "sinon-channel": probe.channel.value,
            },
        }
    return list(seen.values())


def _help_markdown(probe) -> str:
    parts = [f"**{probe.title}**", ""]
    if probe.description:
        parts += [probe.description.strip(), ""]
    if probe.expected:
        parts += ["**Expected behaviour**", "", probe.expected.strip(), ""]
    if probe.remediation:
        parts += ["**Remediation**", "", probe.remediation.strip(), ""]
    if probe.references:
        parts += ["**References**", ""] + [f"- {r}" for r in probe.references]
    return "\n".join(parts)


def _result(result) -> Dict[str, Any]:
    probe = result.probe
    evidence = result.evidence or "oracle fired"
    message = f"{probe.title}: {evidence}"
    if result.confidence is Confidence.HEURISTIC:
        message += " (heuristic --- confirm by hand before reporting)"
    return {
        "ruleId": probe.id,
        "level": _LEVEL[probe.severity],
        "message": {"text": excerpt(message, 900)},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": _uri(probe.source_path),
                        "uriBaseId": "%SRCROOT%",
                    },
                    "region": {"startLine": 1},
                }
            }
        ],
        "partialFingerprints": {"sinonProbeId": probe.id},
        "properties": {
            "confidence": result.confidence.value,
            "canary": result.canary,
            "tripwires": [c.tripwire_reason for c in result.tool_calls if c.tripwire],
        },
    }


def _uri(path: str) -> str:
    if not path:
        return "corpus/unknown.yaml"
    normalised = path.replace("\\", "/")
    marker = "/corpus/"
    if marker in normalised:
        return "corpus/" + normalised.split(marker, 1)[1]
    return normalised.lstrip("/")


def build(run: RunResult, score: Score = None, selected_total: int = None) -> Dict[str, Any]:
    score = score or score_run(run, selected_total)
    return {
        "$schema": SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Sinon",
                        "fullName": "Sinon --- AI agent pentest kit",
                        "version": run.sinon_version or __version__,
                        "informationUri": "https://github.com/at0m-b0mb/Sinon",
                        "rules": _rules(run),
                    }
                },
                "automationDetails": {"id": f"sinon/{run.run_id}"},
                "invocations": [
                    {
                        "executionSuccessful": score.errored == 0,
                        "startTimeUtc": run.started_at,
                        "endTimeUtc": run.finished_at or run.started_at,
                        "properties": {
                            "target": run.target_name,
                            "grade": score.grade,
                            "coverage": round(score.coverage, 4),
                            "skipped": score.skipped,
                        },
                    }
                ],
                "results": [_result(r) for r in run.by_verdict(Verdict.FAIL)],
            }
        ],
    }


def dumps(run: RunResult, score: Score = None, selected_total: int = None) -> str:
    return json.dumps(build(run, score, selected_total), indent=2, ensure_ascii=False)


def write(path: str, run: RunResult, score: Score = None, selected_total: int = None) -> str:
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(dumps(run, score, selected_total))
    return path
