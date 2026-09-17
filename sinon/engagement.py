"""The authorization gate.

Sinon sends adversarial input to an agent. Against your own laptop that is
research; against someone else's production endpoint without paperwork it is an
attack. So the tool asks for the paperwork, and it asks *before* the first
request rather than in a README nobody reads.

The rules, in full:

* A **loopback or built-in target** needs nothing. Your own machine is yours.
* **Anything else** needs an engagement file naming the client, the person who
  authorized the test, a reference to the authorization, and a date window that
  includes today. The target's host must be in the scope allowlist.
* The window is checked on every run, so an engagement file left lying around
  stops working when the engagement ends.
* Every request is **identifiable by default** --- Sinon sets ``X-Sinon-Run`` and
  a canary prefix that traces back to the run --- so a defender who sees the
  traffic can tell a test from an incident. Suppressing that is possible for a
  genuine detection-evasion exercise, but it requires a separate explicit flag
  in the engagement file and it is printed in the banner and stamped into the
  report. It never happens quietly.

There is no ``--force``. If the gate says no, fix the engagement file.
"""

from __future__ import annotations

import datetime as _dt
import ipaddress
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import yaml

# Note the absence of "": a URL with no host is refused by authorize() rather
# than treated as loopback. "I could not parse it" is not "it is local".
LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1"}


class AuthorizationError(Exception):
    """Raised when a run is not permitted to proceed."""


@dataclass
class Window:
    start: Optional[_dt.date] = None
    end: Optional[_dt.date] = None

    def covers(self, day: _dt.date) -> bool:
        if self.start and day < self.start:
            return False
        if self.end and day > self.end:
            return False
        return True

    def describe(self) -> str:
        if not self.start and not self.end:
            return "no window declared"
        return f"{self.start or 'open'} to {self.end or 'open'}"


@dataclass
class Engagement:
    """A signed-off authorization to test a specific target in a date window."""

    client: str = ""
    authorized_by: str = ""
    authorization_ref: str = ""
    contact: str = ""
    window: Window = field(default_factory=Window)
    allow_hosts: List[str] = field(default_factory=list)
    deny_hosts: List[str] = field(default_factory=list)
    identify_requests: bool = True
    suppress_identification_authorized: bool = False
    suppress_identification_reason: str = ""
    notes: str = ""
    target: Dict[str, Any] = field(default_factory=dict)
    source_path: str = ""

    # -- validity -------------------------------------------------------

    @property
    def is_declared(self) -> bool:
        return bool(self.client or self.authorized_by or self.authorization_ref)

    def missing_fields(self) -> List[str]:
        missing = []
        for name in ("client", "authorized_by", "authorization_ref"):
            if not getattr(self, name):
                missing.append(name)
        if not self.window.start or not self.window.end:
            missing.append("window.start and window.end")
        if not self.allow_hosts:
            missing.append("scope.allow_hosts")
        return missing

    def host_allowed(self, host: str) -> bool:
        host = (host or "").lower()
        if any(_host_matches(host, pattern) for pattern in self.deny_hosts):
            return False
        return any(_host_matches(host, pattern) for pattern in self.allow_hosts)

    # -- presentation ----------------------------------------------------

    def banner_lines(self) -> List[str]:
        if not self.is_declared:
            return [
                "TARGET      local / built-in (no engagement file required)",
                "IDENTIFIED  yes - requests carry X-Sinon-Run and SINON- canaries",
            ]
        lines = [
            f"CLIENT      {self.client}",
            f"AUTHORIZED  {self.authorized_by}  (ref: {self.authorization_ref})",
            f"WINDOW      {self.window.describe()}",
            f"SCOPE       {', '.join(self.allow_hosts) or 'none'}",
        ]
        if self.identify_requests:
            lines.append("IDENTIFIED  yes - requests carry X-Sinon-Run and SINON- canaries")
        else:
            lines.append(
                "IDENTIFIED  NO - identification suppressed: "
                + (self.suppress_identification_reason or "no reason recorded")
            )
        return lines


def _host_matches(host: str, pattern: str) -> bool:
    pattern = (pattern or "").lower().strip()
    if not pattern:
        return False
    if pattern == "*":
        return True
    if pattern.startswith("*."):
        return host == pattern[2:] or host.endswith(pattern[1:])
    return host == pattern


def _as_date(value: Any) -> Optional[_dt.date]:
    if value in (None, ""):
        return None
    if isinstance(value, _dt.datetime):
        return value.date()
    if isinstance(value, _dt.date):
        return value
    try:
        return _dt.date.fromisoformat(str(value).strip())
    except ValueError as exc:
        raise AuthorizationError(f"invalid date '{value}' (expected YYYY-MM-DD)") from exc


def load(path: Path) -> Engagement:
    """Read an engagement file."""
    path = Path(path)
    if not path.exists():
        raise AuthorizationError(f"engagement file not found: {path}")
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise AuthorizationError(f"{path}: invalid YAML: {exc}") from exc

    block = raw.get("engagement") or {}
    scope = raw.get("scope") or {}
    options = raw.get("options") or {}
    window_raw = block.get("window") or {}

    identify = options.get("identify_requests", True)
    suppress_ok = bool(options.get("suppress_identification_authorized", False))
    if not identify and not suppress_ok:
        raise AuthorizationError(
            f"{path}: options.identify_requests is false, but "
            "options.suppress_identification_authorized is not set. Running an "
            "unidentifiable test requires the client to have explicitly agreed to "
            "a detection-evasion exercise; record that agreement and set the flag."
        )

    return Engagement(
        client=str(block.get("client", "")).strip(),
        authorized_by=str(block.get("authorized_by", "")).strip(),
        authorization_ref=str(block.get("authorization_ref", "")).strip(),
        contact=str(block.get("contact", "")).strip(),
        window=Window(_as_date(window_raw.get("start")), _as_date(window_raw.get("end"))),
        allow_hosts=[str(h).lower() for h in (scope.get("allow_hosts") or [])],
        deny_hosts=[str(h).lower() for h in (scope.get("deny_hosts") or [])],
        identify_requests=bool(identify),
        suppress_identification_authorized=suppress_ok,
        suppress_identification_reason=str(
            options.get("suppress_identification_reason", "")
        ).strip(),
        notes=str(block.get("notes", "")).strip(),
        target=raw.get("target") or {},
        source_path=str(path),
    )


NETWORK_SCHEMES = {"http", "https", ""}


def target_host(target_url: str) -> str:
    if not target_url:
        return ""
    parsed = urlparse(target_url if "//" in target_url else "//" + target_url)
    return (parsed.hostname or "").lower()


def target_scheme(target_url: str) -> str:
    if not target_url:
        return ""
    return (urlparse(target_url).scheme or "").lower()


def is_local(host: str) -> bool:
    if host in LOOPBACK_HOSTS:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


@dataclass
class Decision:
    allowed: bool
    reasons: List[str] = field(default_factory=list)
    requires_engagement: bool = False

    def raise_if_denied(self) -> None:
        if not self.allowed:
            raise AuthorizationError(
                "refusing to run:\n  - " + "\n  - ".join(self.reasons)
            )


def authorize(
    target_url: str,
    engagement: Optional[Engagement],
    today: Optional[_dt.date] = None,
    target_is_builtin: bool = False,
) -> Decision:
    """Decide whether this run may proceed. Fails closed."""
    today = today or _dt.date.today()
    host = target_host(target_url)
    scheme = target_scheme(target_url)

    # A target that runs as a local process (the built-in agent, a command) is
    # the operator's own machine and needs no paperwork.
    if target_is_builtin:
        return Decision(allowed=True, reasons=["target runs locally"], requires_engagement=False)

    # Everything else is reached over the network, so it must be addressable and
    # the address must be one this gate can reason about. Failing closed here
    # matters: an unparseable URL used to yield an empty host, and an empty host
    # read as loopback, so a malformed or non-http target was waved through as
    # "local".
    if scheme not in NETWORK_SCHEMES:
        return Decision(
            allowed=False,
            requires_engagement=True,
            reasons=[
                f"target URL scheme '{scheme}' is not supported; "
                "use http:// or https://, or a local target kind"
            ],
        )
    if not host:
        return Decision(
            allowed=False,
            requires_engagement=True,
            reasons=[
                f"no host could be read from the target URL ({target_url!r}); "
                "give a full URL such as https://agent.example.com/chat"
            ],
        )

    if is_local(host):
        return Decision(allowed=True, reasons=["target is loopback"], requires_engagement=False)

    if engagement is None or not engagement.is_declared:
        return Decision(
            allowed=False,
            requires_engagement=True,
            reasons=[
                f"target host '{host}' is not local, so an engagement file is required",
                "create one with: sinon init --engagement engagement.yaml",
                "then run: sinon run --engagement engagement.yaml --target ...",
            ],
        )

    reasons: List[str] = []
    missing = engagement.missing_fields()
    if missing:
        reasons.append(
            "engagement file is incomplete; missing: " + ", ".join(missing)
        )
    if not engagement.window.covers(today):
        reasons.append(
            f"today ({today}) is outside the authorized window "
            f"({engagement.window.describe()})"
        )
    if not engagement.host_allowed(host):
        reasons.append(
            f"target host '{host}' is not in scope.allow_hosts "
            f"({', '.join(engagement.allow_hosts) or 'empty'})"
        )

    if reasons:
        return Decision(allowed=False, reasons=reasons, requires_engagement=True)
    return Decision(
        allowed=True,
        requires_engagement=True,
        reasons=[f"authorized by {engagement.authorized_by} ({engagement.authorization_ref})"],
    )


TEMPLATE = """\
# Sinon engagement file
#
# Sinon will not test a non-local target without this. Fill it in from the
# signed rules of engagement, not from memory --- the fields below end up
# verbatim in the report you hand back to the client.

engagement:
  client: "ACME Corp"
  authorized_by: "Name, Title"          # the person who signed off
  authorization_ref: "PO-2026-0001 / RoE signed 2026-01-01"
  contact: "security@acme.example"      # who to call if something breaks
  window:
    start: 2026-01-01                   # inclusive
    end: 2026-01-08                     # inclusive; runs outside this are refused
  notes: |
    Scope limited to the customer-support agent in staging.
    No production data. Escalation contact on call during the window.

scope:
  # Sinon refuses any target host not listed here. Wildcards: *.acme.example
  allow_hosts:
    - agent-staging.acme.example
  deny_hosts: []

target:
  # Optional: keeps the target definition next to its authorization so a run is
  # one flag. Override any of it on the command line.
  kind: http                            # reference | openai | http | cli | mcp
  name: "support-agent-staging"
  url: "https://agent-staging.acme.example/v1/chat"
  # request/response shaping for the generic HTTP adapter:
  # prompt_field: "message"
  # response_path: "reply.text"
  # headers:
  #   Authorization: "Bearer ${AGENT_TOKEN}"

options:
  # Requests carry X-Sinon-Run and SINON- prefixed canaries so the client's blue
  # team can tell a test from an incident. Turning this off is a
  # detection-evasion exercise and needs its own explicit sign-off below.
  identify_requests: true
  # suppress_identification_authorized: false
  # suppress_identification_reason: ""
  rate_limit_per_min: 60
  timeout_seconds: 60
"""


def write_template(path: Path) -> Path:
    path = Path(path)
    if path.exists():
        raise AuthorizationError(f"{path} already exists; refusing to overwrite it")
    path.write_text(TEMPLATE, encoding="utf-8")
    return path
