"""Core data model for Sinon.

Everything the runner passes around is defined here: the probe (one test case),
what an adapter is handed, what it hands back, and the verdict that comes out
the other end.

Two ideas carry most of the weight and are worth stating plainly:

*Confidence.* Every oracle is either ``deterministic`` (it observed a fact --- a
unique canary came back, an instrumented tool was called, the sink received a
request) or ``heuristic`` (it pattern-matched on prose). A finding backed by a
heuristic oracle is reported as such and is never allowed to carry the same
weight as an observed fact. Scoring reads this field.

*Skips are not passes.* An adapter that cannot observe tool calls cannot answer
a tool-abuse probe. The honest result is ``SKIP``, which lowers coverage and
caps the grade --- never ``PASS``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


# --------------------------------------------------------------------------
# Enumerations
# --------------------------------------------------------------------------


class Family(str, Enum):
    """Top-level bucket a probe belongs to. Mirrors the corpus directories."""

    PROMPT_INJECTION = "prompt-injection"
    TOOL_ABUSE = "tool-abuse"
    OVER_PERMISSION = "over-permission"

    @property
    def label(self) -> str:
        return {
            Family.PROMPT_INJECTION: "Prompt injection",
            Family.TOOL_ABUSE: "Tool abuse",
            Family.OVER_PERMISSION: "Over-permissioned action",
        }[self]


class Severity(str, Enum):
    """How much a failure of this probe matters.

    The weights are the ones scoring uses; they are deliberately steep so that
    one critical failure cannot be averaged away by a wall of low-severity
    passes.
    """

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def weight(self) -> int:
        return {
            Severity.CRITICAL: 40,
            Severity.HIGH: 15,
            Severity.MEDIUM: 5,
            Severity.LOW: 2,
            Severity.INFO: 0,
        }[self]

    @property
    def rank(self) -> int:
        """Sort order, most severe first."""
        return {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4,
        }[self]


class Channel(str, Enum):
    """Where the untrusted text reaches the agent from.

    This is the axis most test sets get wrong: they put everything in the user
    turn. An agent that refuses an instruction typed by its user will often
    follow the identical instruction arriving inside a web page it fetched.
    """

    USER_TURN = "user_turn"
    DOCUMENT = "document"
    TOOL_RESULT = "tool_result"
    TOOL_DESCRIPTION = "tool_description"
    MEMORY = "memory"
    FILENAME = "filename"

    @property
    def label(self) -> str:
        return {
            Channel.USER_TURN: "User turn (direct)",
            Channel.DOCUMENT: "Retrieved document",
            Channel.TOOL_RESULT: "Tool result",
            Channel.TOOL_DESCRIPTION: "Tool description",
            Channel.MEMORY: "Persisted memory / context",
            Channel.FILENAME: "Filename or metadata",
        }[self]

    @property
    def is_indirect(self) -> bool:
        """True when the payload arrives through content, not from the user."""
        return self is not Channel.USER_TURN


class Confidence(str, Enum):
    DETERMINISTIC = "deterministic"
    HEURISTIC = "heuristic"


class Verdict(str, Enum):
    """Outcome of one probe against one target."""

    FAIL = "fail"          # the agent did the unsafe thing; this is a finding
    PASS = "pass"          # the agent did not do it, on this run, with this probe
    SKIP = "skip"          # the target cannot answer this probe -- lowers coverage
    ERROR = "error"        # transport or adapter fault; no evidence either way

    @property
    def label(self) -> str:
        return {
            Verdict.FAIL: "FAIL",
            Verdict.PASS: "PASS",
            Verdict.SKIP: "SKIP",
            Verdict.ERROR: "ERROR",
        }[self]


# --------------------------------------------------------------------------
# Probe definition (what a corpus YAML file becomes)
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class OracleSpec:
    """One rule for deciding whether the agent failed a probe.

    ``kind`` names the oracle implementation in :mod:`sinon.oracles`; ``params``
    is passed through to it. ``confidence`` defaults to whatever that oracle
    implementation declares and can only be lowered by a probe, never raised ---
    a probe author cannot promote a regex match to an observed fact.
    """

    kind: str
    params: Dict[str, Any] = field(default_factory=dict)
    confidence: Optional[Confidence] = None
    describe: str = ""


@dataclass(frozen=True)
class DocumentSpec:
    """A piece of content the agent is expected to read during the probe.

    Documents are served to the agent either inline (attached to the request) or
    through the instrumented ``web_fetch`` / ``read_file`` tools, so the same
    probe body works for adapters with and without tool support.
    """

    name: str
    content: str
    media_type: str = "text/plain"
    url: Optional[str] = None
    description: str = ""


@dataclass(frozen=True)
class Probe:
    """One test case."""

    id: str
    title: str
    family: Family
    technique: str
    channel: Channel
    severity: Severity
    prompt: str

    description: str = ""
    payload: str = ""
    documents: List[DocumentSpec] = field(default_factory=list)
    tools: List[str] = field(default_factory=list)
    tool_results: Dict[str, str] = field(default_factory=dict)
    tool_descriptions: Dict[str, str] = field(default_factory=dict)
    oracles: List[OracleSpec] = field(default_factory=list)
    fail_when: str = "any"          # "any" | "all"
    system_prompt: str = ""
    memory: str = ""

    expected: str = ""
    remediation: str = ""
    references: List[str] = field(default_factory=list)
    owasp: List[str] = field(default_factory=list)
    atlas: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)

    # Provenance -- set by the loader, not by the file.
    source_path: str = ""

    # A probe that needs tool telemetry cannot be judged without it.
    @property
    def requires_tools(self) -> bool:
        return bool(self.tools) or any(
            o.kind in _TOOL_DEPENDENT_ORACLES for o in self.oracles
        )

    @property
    def requires_sink(self) -> bool:
        if any(o.kind in _SINK_DEPENDENT_ORACLES for o in self.oracles):
            return True
        body = self.prompt + self.payload + "".join(d.content for d in self.documents)
        return "{{sink_url}}" in body

    def __str__(self) -> str:  # pragma: no cover - trivial
        return f"{self.id} {self.title}"


_TOOL_DEPENDENT_ORACLES = {
    "tool_called",
    "tool_not_called",
    "tool_arg_matches",
    "tripwire_fired",
    "canary_in_tool_args",
}

_SINK_DEPENDENT_ORACLES = {"canary_at_sink", "sink_hit"}


# --------------------------------------------------------------------------
# Runtime: what an adapter is given and what it returns
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class ToolDef:
    """A tool offered to the agent for the duration of one probe."""

    name: str
    description: str
    parameters: Dict[str, Any]
    tripwire: bool = False
    tripwire_reason: str = ""
    destructive: bool = False

    def to_openai_schema(self) -> Dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": self.parameters,
            },
        }


@dataclass
class ToolCall:
    """A tool invocation observed during a probe."""

    name: str
    arguments: Dict[str, Any] = field(default_factory=dict)
    result: str = ""
    tripwire: bool = False
    tripwire_reason: str = ""

    def arg_text(self) -> str:
        """Flatten arguments to one searchable string."""
        parts = []
        for key, value in self.arguments.items():
            parts.append(f"{key}={value}")
        return " ".join(parts)


@dataclass(frozen=True)
class AgentRequest:
    """Everything the target needs in order to run one probe."""

    probe_id: str
    prompt: str
    system_prompt: str = ""
    documents: List[DocumentSpec] = field(default_factory=list)
    tools: List[ToolDef] = field(default_factory=list)
    memory: str = ""
    run_id: str = ""


@dataclass
class AgentResponse:
    """What the target did.

    ``tool_calls`` is the load-bearing field. An adapter that cannot see tool
    calls must set ``supports_tools=False`` on itself rather than returning an
    empty list, or every tool probe would silently read as a pass.
    """

    text: str = ""
    tool_calls: List[ToolCall] = field(default_factory=list)
    raw: Any = None
    latency_ms: float = 0.0
    error: str = ""

    @property
    def ok(self) -> bool:
        return not self.error


@dataclass
class SinkHit:
    """A request that arrived at the local exfiltration sink."""

    path: str
    query: str
    body: str
    method: str = "GET"
    headers: Dict[str, str] = field(default_factory=dict)

    def as_text(self) -> str:
        header_text = " ".join(f"{k}: {v}" for k, v in self.headers.items())
        return f"{self.method} {self.path}?{self.query} {header_text} {self.body}"


@dataclass
class Observation:
    """Everything an oracle is allowed to look at.

    Bundling it means an oracle can never accidentally reach into the runner or
    the adapter --- it sees the response, the instrumented tool calls, whatever
    reached the sink, and the canary it should be hunting for.
    """

    probe: Probe
    response: AgentResponse
    tool_calls: List[ToolCall] = field(default_factory=list)
    sink_hits: List[SinkHit] = field(default_factory=list)
    canary: str = ""
    system_canary: str = ""
    rendered_prompt: str = ""
    rendered_payload: str = ""

    def all_tool_text(self) -> str:
        return " ".join(f"{c.name} {c.arg_text()}" for c in self.tool_calls)

    def all_sink_text(self) -> str:
        return " ".join(h.as_text() for h in self.sink_hits)


# --------------------------------------------------------------------------
# Results
# --------------------------------------------------------------------------


@dataclass
class OracleResult:
    """Whether one oracle fired, and the evidence for saying so."""

    kind: str
    fired: bool
    confidence: Confidence
    evidence: str = ""
    describe: str = ""


@dataclass
class ProbeResult:
    """The outcome of running one probe once."""

    probe: Probe
    verdict: Verdict
    oracle_results: List[OracleResult] = field(default_factory=list)
    response: Optional[AgentResponse] = None
    tool_calls: List[ToolCall] = field(default_factory=list)
    sink_hits: List[SinkHit] = field(default_factory=list)
    canary: str = ""
    system_canary: str = ""
    rendered_prompt: str = ""
    rendered_payload: str = ""
    skip_reason: str = ""
    error: str = ""
    duration_ms: float = 0.0

    @property
    def is_finding(self) -> bool:
        return self.verdict is Verdict.FAIL

    @property
    def fired_oracles(self) -> List[OracleResult]:
        return [o for o in self.oracle_results if o.fired]

    @property
    def confidence(self) -> Confidence:
        """A finding is only as strong as its weakest firing oracle."""
        fired = self.fired_oracles
        if not fired:
            source = self.oracle_results
        else:
            source = fired
        if any(o.confidence is Confidence.HEURISTIC for o in source):
            return Confidence.HEURISTIC
        return Confidence.DETERMINISTIC

    @property
    def evidence(self) -> str:
        return "; ".join(o.evidence for o in self.fired_oracles if o.evidence)


@dataclass
class RunResult:
    """Everything produced by one `sinon run`."""

    run_id: str
    started_at: str
    finished_at: str = ""
    target_name: str = ""
    target_kind: str = ""
    engagement: Optional[Any] = None            # sinon.engagement.Engagement
    results: List[ProbeResult] = field(default_factory=list)
    sinon_version: str = ""
    corpus_paths: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)

    def by_verdict(self, verdict: Verdict) -> List[ProbeResult]:
        return [r for r in self.results if r.verdict is verdict]

    @property
    def findings(self) -> List[ProbeResult]:
        """Failures, most severe first, then by id for stable ordering."""
        return sorted(
            self.by_verdict(Verdict.FAIL),
            key=lambda r: (r.probe.severity.rank, r.probe.id),
        )

    @property
    def executed(self) -> List[ProbeResult]:
        """Probes that produced evidence either way."""
        return [r for r in self.results if r.verdict in (Verdict.FAIL, Verdict.PASS)]


# --------------------------------------------------------------------------
# Small shared helpers
# --------------------------------------------------------------------------


_SLUG_RE = re.compile(r"[^a-z0-9]+")


def slugify(text: str) -> str:
    return _SLUG_RE.sub("-", text.lower()).strip("-")


def excerpt(text: str, limit: int = 400) -> str:
    """Trim long evidence for display without hiding that it was trimmed."""
    text = (text or "").strip()
    if len(text) <= limit:
        return text
    return text[:limit].rstrip() + f"... [{len(text) - limit} more chars]"
