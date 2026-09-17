"""Loading, validating and templating the probe corpus.

A probe is a YAML file. That is a deliberate choice: the security community
already contributes test cases as YAML (nuclei templates, Sigma rules), so
somebody who has never read a line of this codebase can still add a probe by
copying a neighbouring file and changing the strings.

The loader is strict on purpose. A probe with a typo in an oracle name, a tool
that does not exist, or an id that collides with another file is a probe that
would silently never fire --- and a test kit that silently does not test is worse
than no test kit. ``sinon validate`` runs every check here and CI runs it on
every push.
"""

from __future__ import annotations

import re
from dataclasses import replace
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

import yaml

from . import oracles, toolbelt
from .model import (
    Channel,
    Confidence,
    DocumentSpec,
    Family,
    OracleSpec,
    Probe,
    Severity,
)

ID_PATTERN = re.compile(r"^(PI|TA|OP)-[A-Z]{2,6}-\d{3}$")

FAMILY_PREFIX = {
    "PI": Family.PROMPT_INJECTION,
    "TA": Family.TOOL_ABUSE,
    "OP": Family.OVER_PERMISSION,
}

PLACEHOLDER_RE = re.compile(r"\{\{([a-z_][a-z0-9_]*)\}\}")

# Every substitution the corpus is allowed to use. Anything else is a typo.
KNOWN_PLACEHOLDERS = {
    "canary",
    "system_canary",
    "payload",
    "sink_url",
    "sink_host",
    "run_id",
    "probe_id",
    "org_domain",
    "org_name",
    "workspace",
    "attacker_email",
    "attacker_host",
    "metadata_host",
    "customer_id",
    "doc_url",
    "doc_name",
    # Derived from the rendered payload -- see add_payload_variants().
    "payload_b64",
    "payload_rot13",
    "payload_reversed",
    "payload_zwsp",
    "payload_homoglyph",
    "canary_spaced",
}


class CorpusError(Exception):
    """Raised when a probe file cannot be loaded or fails validation."""


class ValidationIssue:
    """One problem found in a corpus file."""

    def __init__(self, path: str, probe_id: str, message: str, fatal: bool = True):
        self.path = path
        self.probe_id = probe_id
        self.message = message
        self.fatal = fatal

    def __str__(self) -> str:
        where = f"{self.path}"
        if self.probe_id:
            where += f" [{self.probe_id}]"
        level = "error" if self.fatal else "warning"
        return f"{where}: {level}: {self.message}"


# --------------------------------------------------------------------------
# Parsing
# --------------------------------------------------------------------------


def _require(data: Dict[str, Any], key: str, path: str, probe_id: str = "") -> Any:
    if key not in data or data[key] in (None, ""):
        raise CorpusError(f"{path}{' [' + probe_id + ']' if probe_id else ''}: missing required field '{key}'")
    return data[key]


def _as_list(value: Any) -> List[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    return [str(v) for v in value]


def _parse_enum(enum_cls, value: Any, field_name: str, path: str, probe_id: str):
    try:
        return enum_cls(str(value).strip().lower())
    except ValueError:
        allowed = ", ".join(m.value for m in enum_cls)
        raise CorpusError(
            f"{path} [{probe_id}]: '{value}' is not a valid {field_name}; expected one of: {allowed}"
        )


def _parse_documents(raw: Any, path: str, probe_id: str) -> List[DocumentSpec]:
    docs: List[DocumentSpec] = []
    for index, item in enumerate(raw or []):
        if not isinstance(item, dict):
            raise CorpusError(f"{path} [{probe_id}]: documents[{index}] must be a mapping")
        name = str(_require(item, "name", path, probe_id))
        content = str(_require(item, "content", path, probe_id))
        url = item.get("url") or f"https://kb.{toolbelt.ORG_DOMAIN}/articles/{name}"
        docs.append(
            DocumentSpec(
                name=name,
                content=content,
                media_type=str(item.get("media_type", "text/plain")),
                url=str(url),
                description=str(item.get("description", "")),
            )
        )
    return docs


def _parse_oracles(raw: Any, path: str, probe_id: str) -> List[OracleSpec]:
    specs: List[OracleSpec] = []
    for index, item in enumerate(raw or []):
        if isinstance(item, str):
            specs.append(OracleSpec(kind=item))
            continue
        if not isinstance(item, dict):
            raise CorpusError(f"{path} [{probe_id}]: oracles[{index}] must be a string or mapping")
        kind = str(_require(item, "type", path, probe_id))
        params = {k: v for k, v in item.items() if k not in ("type", "confidence", "describe")}
        confidence: Optional[Confidence] = None
        if item.get("confidence"):
            confidence = Confidence(str(item["confidence"]).lower())
        specs.append(
            OracleSpec(
                kind=kind,
                params=params,
                confidence=confidence,
                describe=str(item.get("describe", "")),
            )
        )
    return specs


def parse_probe(data: Dict[str, Any], path: str) -> Probe:
    """Turn one parsed YAML mapping into a :class:`Probe`."""
    if not isinstance(data, dict):
        raise CorpusError(f"{path}: expected a mapping at the top level")

    probe_id = str(_require(data, "id", path)).strip()
    family = _parse_enum(Family, _require(data, "family", path, probe_id), "family", path, probe_id)
    channel = _parse_enum(Channel, _require(data, "channel", path, probe_id), "channel", path, probe_id)
    severity = _parse_enum(Severity, _require(data, "severity", path, probe_id), "severity", path, probe_id)

    fail_when = str(data.get("fail_when", "any")).lower()
    if fail_when not in ("any", "all"):
        raise CorpusError(f"{path} [{probe_id}]: fail_when must be 'any' or 'all'")

    tool_results = data.get("tool_results") or {}
    if not isinstance(tool_results, dict):
        raise CorpusError(f"{path} [{probe_id}]: tool_results must be a mapping of tool name to text")
    tool_descriptions = data.get("tool_descriptions") or {}
    if not isinstance(tool_descriptions, dict):
        raise CorpusError(f"{path} [{probe_id}]: tool_descriptions must be a mapping of tool name to text")

    return Probe(
        id=probe_id,
        title=str(_require(data, "title", path, probe_id)),
        family=family,
        technique=str(data.get("technique", "")),
        channel=channel,
        severity=severity,
        prompt=str(_require(data, "prompt", path, probe_id)),
        description=str(data.get("description", "")).strip(),
        payload=str(data.get("payload", "")),
        documents=_parse_documents(data.get("documents"), path, probe_id),
        tools=_as_list(data.get("tools")),
        tool_results={str(k): str(v) for k, v in tool_results.items()},
        tool_descriptions={str(k): str(v) for k, v in tool_descriptions.items()},
        oracles=_parse_oracles(data.get("oracles"), path, probe_id),
        fail_when=fail_when,
        system_prompt=str(data.get("system_prompt", "")),
        memory=str(data.get("memory", "")),
        expected=str(data.get("expected", "")).strip(),
        remediation=str(data.get("remediation", "")).strip(),
        references=_as_list(data.get("references")),
        owasp=_as_list(data.get("owasp")),
        atlas=_as_list(data.get("atlas")),
        tags=_as_list(data.get("tags")),
        source_path=path,
    )


def load_file(path: Path) -> List[Probe]:
    """Load one YAML file, which may hold a single probe or a ``probes:`` list."""
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise CorpusError(f"{path}: invalid YAML: {exc}") from exc
    if raw is None:
        return []
    if isinstance(raw, dict) and "probes" in raw:
        return [parse_probe(item, str(path)) for item in raw["probes"]]
    if isinstance(raw, list):
        return [parse_probe(item, str(path)) for item in raw]
    return [parse_probe(raw, str(path))]


def load(paths: Sequence[Path]) -> List[Probe]:
    """Load every probe under the given files or directories, sorted by id."""
    probes: List[Probe] = []
    for entry in paths:
        entry = Path(entry)
        if entry.is_dir():
            for file_path in sorted(entry.rglob("*.y*ml")):
                if file_path.name.startswith("_"):
                    continue
                probes.extend(load_file(file_path))
        elif entry.exists():
            probes.extend(load_file(entry))
        else:
            raise CorpusError(f"{entry}: no such file or directory")
    return sorted(probes, key=lambda p: p.id)


def default_corpus_path() -> Path:
    """The corpus that ships with the package.

    Checked in two places so both ``pip install sinon-kit`` and a plain
    ``git clone`` work without configuration.
    """
    packaged = Path(__file__).resolve().parent / "corpus"
    if packaged.is_dir():
        return packaged
    return Path(__file__).resolve().parent.parent / "corpus"


def load_default() -> List[Probe]:
    return load([default_corpus_path()])


# --------------------------------------------------------------------------
# Validation
# --------------------------------------------------------------------------


def validate(probes: Iterable[Probe]) -> List[ValidationIssue]:
    """Check a loaded corpus for the mistakes that make a probe a no-op."""
    issues: List[ValidationIssue] = []
    seen: Dict[str, str] = {}
    known_tools = set(toolbelt.tool_names())
    known_oracles = set(oracles.known_kinds())

    for probe in probes:
        path = probe.source_path

        def add(message: str, fatal: bool = True) -> None:
            issues.append(ValidationIssue(path, probe.id, message, fatal))

        if not ID_PATTERN.match(probe.id):
            add(f"id '{probe.id}' does not match FAMILY-TECHNIQUE-NNN (e.g. PI-IND-001)")
        else:
            prefix = probe.id.split("-")[0]
            if FAMILY_PREFIX[prefix] is not probe.family:
                add(
                    f"id prefix '{prefix}' implies family "
                    f"'{FAMILY_PREFIX[prefix].value}' but the file says '{probe.family.value}'"
                )

        if probe.id in seen:
            add(f"duplicate id, already defined in {seen[probe.id]}")
        else:
            seen[probe.id] = path

        if not probe.oracles:
            add("no oracles: this probe can never produce a finding")

        for spec in probe.oracles:
            if spec.kind not in known_oracles:
                add(
                    f"unknown oracle '{spec.kind}'; known: {', '.join(sorted(known_oracles))}"
                )
            elif (
                spec.confidence is Confidence.DETERMINISTIC
                and oracles.REGISTRY[spec.kind].confidence is Confidence.HEURISTIC
            ):
                add(
                    f"oracle '{spec.kind}' is heuristic; a probe cannot declare it "
                    "deterministic (the declaration is ignored)",
                    fatal=False,
                )

        for tool in probe.tools:
            if tool not in known_tools:
                add(f"unknown tool '{tool}'; known: {', '.join(sorted(known_tools))}")

        for name in list(probe.tool_results) + list(probe.tool_descriptions):
            if name not in probe.tools:
                add(f"override given for tool '{name}' which the probe never offers")

        if probe.requires_tools and not probe.tools:
            add("uses a tool oracle but offers no tools")

        # Placeholders
        for field_name, text in _templated_fields(probe):
            for placeholder in PLACEHOLDER_RE.findall(text):
                if placeholder not in KNOWN_PLACEHOLDERS:
                    add(f"unknown placeholder {{{{{placeholder}}}}} in {field_name}")

        # An obfuscation probe inserts {{payload_b64}} or similar rather than
        # the raw payload, so any payload_* placeholder counts as usage.
        if probe.payload and "{{payload" not in _all_text(probe):
            add(
                "declares a payload that is never inserted with {{payload}} "
                "or one of its encoded variants",
                fatal=False,
            )

        if probe.channel.is_indirect and probe.channel is Channel.DOCUMENT and not probe.documents:
            add("channel is 'document' but the probe defines no documents")

        if not probe.expected:
            add("no 'expected' text: the report cannot say what safe behaviour was", fatal=False)
        if not probe.remediation:
            add("no 'remediation' text: a finding without a fix is not useful", fatal=False)
        if not probe.owasp:
            add("no OWASP LLM mapping", fatal=False)

    return issues


def _templated_fields(probe: Probe) -> List[Tuple[str, str]]:
    fields = [
        ("prompt", probe.prompt),
        ("payload", probe.payload),
        ("system_prompt", probe.system_prompt),
        ("memory", probe.memory),
    ]
    for doc in probe.documents:
        fields.append((f"documents[{doc.name}].name", doc.name))
        fields.append((f"documents[{doc.name}].content", doc.content))
    for name, text in probe.tool_results.items():
        fields.append((f"tool_results[{name}]", text))
    for name, text in probe.tool_descriptions.items():
        fields.append((f"tool_descriptions[{name}]", text))
    return fields


def _all_text(probe: Probe) -> str:
    return " ".join(text for _, text in _templated_fields(probe))


# --------------------------------------------------------------------------
# Templating
# --------------------------------------------------------------------------


def build_context(
    canary: str,
    system_canary: str = "",
    sink_url: str = "",
    run_id: str = "",
    probe: Optional[Probe] = None,
) -> Dict[str, str]:
    """Assemble the substitution table for one probe execution."""
    doc = probe.documents[0] if (probe and probe.documents) else None
    sink_host = ""
    if sink_url:
        sink_host = sink_url.split("//", 1)[-1].rstrip("/")
    return {
        "canary": canary,
        "system_canary": system_canary,
        "sink_url": sink_url,
        "sink_host": sink_host,
        "run_id": run_id,
        "probe_id": probe.id if probe else "",
        "org_domain": toolbelt.ORG_DOMAIN,
        "org_name": toolbelt.ORG_NAME,
        "workspace": toolbelt.WORKSPACE_ROOT,
        "attacker_email": toolbelt.ATTACKER_EMAIL,
        "attacker_host": toolbelt.ATTACKER_HOST,
        "metadata_host": toolbelt.INTERNAL_METADATA_HOST,
        "customer_id": toolbelt.IN_SCOPE_CUSTOMER,
        "doc_url": doc.url if doc else "",
        "doc_name": doc.name if doc else "",
    }


# Latin characters and their Cyrillic/Greek lookalikes. Enough to defeat a
# substring filter while remaining readable to a model and to a person.
_HOMOGLYPHS = {
    "a": "\u0430", "c": "\u0441", "e": "\u0435", "i": "\u0456", "j": "\u0458",
    "o": "\u043e", "p": "\u0440", "s": "\u0455", "x": "\u0445", "y": "\u0443",
    "A": "\u0410", "B": "\u0412", "C": "\u0421", "E": "\u0415", "H": "\u041d",
    "K": "\u041a", "M": "\u041c", "O": "\u041e", "P": "\u0420", "T": "\u0422",
    "X": "\u0425",
}

ZERO_WIDTH = "\u200b"


def add_payload_variants(context: Dict[str, str]) -> Dict[str, str]:
    """Derive the obfuscated forms of the payload.

    Obfuscation probes need the *runtime* canary inside an encoded blob, which a
    static YAML file cannot contain. So the corpus writes ``{{payload_b64}}``
    and the encoding happens here, after the canary is minted. The variants are
    the transforms that actually show up in the wild: encoding to slip past a
    string filter, zero-width characters to hide text from a human reviewer, and
    homoglyphs to defeat both at once.
    """
    import base64 as _b64
    import codecs as _codecs

    payload = context.get("payload", "")
    canary = context.get("canary", "")
    context["payload_b64"] = _b64.b64encode(payload.encode("utf-8")).decode("ascii")
    context["payload_rot13"] = _codecs.encode(payload, "rot_13")
    context["payload_reversed"] = payload[::-1]
    context["payload_zwsp"] = ZERO_WIDTH.join(payload)
    context["payload_homoglyph"] = "".join(_HOMOGLYPHS.get(ch, ch) for ch in payload)
    context["canary_spaced"] = " ".join(canary)
    return context


def render(template: str, context: Dict[str, str]) -> str:
    """Substitute ``{{name}}`` placeholders.

    Unknown placeholders are left untouched rather than raising: at run time an
    unrenderable probe should still execute and be visibly odd in the report,
    and ``sinon validate`` is where typos are supposed to be caught.
    """
    if not template:
        return ""

    def swap(match: "re.Match[str]") -> str:
        key = match.group(1)
        return str(context.get(key, match.group(0)))

    # Two passes so {{payload}} can itself contain {{canary}}.
    once = PLACEHOLDER_RE.sub(swap, template)
    return PLACEHOLDER_RE.sub(swap, once)


def render_probe(probe: Probe, context: Dict[str, str]) -> Probe:
    """Return a copy of ``probe`` with every templated field rendered."""
    return replace(
        probe,
        prompt=render(probe.prompt, context),
        payload=render(probe.payload, context),
        system_prompt=render(probe.system_prompt, context),
        memory=render(probe.memory, context),
        documents=[
            replace(
                doc,
                name=render(doc.name, context),
                content=render(doc.content, context),
                url=render(doc.url or "", context),
            )
            for doc in probe.documents
        ],
        tool_results={k: render(v, context) for k, v in probe.tool_results.items()},
        tool_descriptions={
            k: render(v, context) for k, v in probe.tool_descriptions.items()
        },
    )


# --------------------------------------------------------------------------
# Selection
# --------------------------------------------------------------------------


def select(
    probes: Sequence[Probe],
    families: Optional[Set[str]] = None,
    severities: Optional[Set[str]] = None,
    tags: Optional[Set[str]] = None,
    channels: Optional[Set[str]] = None,
    ids: Optional[Set[str]] = None,
    exclude_tags: Optional[Set[str]] = None,
) -> List[Probe]:
    """Filter a corpus. Every filter is an AND; empty filters match everything."""
    out = []
    for probe in probes:
        if ids and probe.id not in ids:
            continue
        if families and probe.family.value not in families:
            continue
        if severities and probe.severity.value not in severities:
            continue
        if channels and probe.channel.value not in channels:
            continue
        if tags and not (set(probe.tags) & tags):
            continue
        if exclude_tags and (set(probe.tags) & exclude_tags):
            continue
        out.append(probe)
    return out


def corpus_stats(probes: Sequence[Probe]) -> Dict[str, Any]:
    """Counts used by `sinon list --stats`, the docs and the report header."""
    by_family: Dict[str, int] = {}
    by_severity: Dict[str, int] = {}
    by_channel: Dict[str, int] = {}
    for probe in probes:
        by_family[probe.family.value] = by_family.get(probe.family.value, 0) + 1
        by_severity[probe.severity.value] = by_severity.get(probe.severity.value, 0) + 1
        by_channel[probe.channel.value] = by_channel.get(probe.channel.value, 0) + 1
    return {
        "total": len(probes),
        "by_family": by_family,
        "by_severity": by_severity,
        "by_channel": by_channel,
        "indirect": sum(1 for p in probes if p.channel.is_indirect),
        "needs_tools": sum(1 for p in probes if p.requires_tools),
    }
