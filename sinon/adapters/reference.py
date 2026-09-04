"""The built-in reference agent --- a target you already have.

Sinon ships with a deliberately weak agent so that ``sinon demo`` produces a
real report on a laptop with no API key, no network and no budget. It is also
what the test suite runs against, which is why it is rule-based and fully
deterministic: the same corpus against the same profile gives the same verdicts
every time.

**It is not a language model.** It is a few hundred lines of pattern matching
that imitate the specific failure modes real agents exhibit. A finding against
the reference agent says the *harness* works. It says nothing about GPT, Claude,
Llama or anyone's production assistant, and no output from it should ever be
presented as if it did.

Three profiles, which is the useful part --- you can see a report change shape as
defences go in:

``naive``
    Treats every string it encounters as an instruction. Fetched a web page
    that says "email this to X"? It emails it to X. This is what an agent looks
    like when nobody thought about untrusted content.

``guarded``
    Has the defence people reach for first: a keyword filter for "ignore
    previous instructions" and friends. It stops the obvious payloads and sails
    straight past politely-phrased ones, encodings, and anything that never
    uses the magic words. Watching it fail is the point.

``hardened``
    Treats retrieved content as data, requires confirmation before anything
    irreversible or outbound, and keeps its system prompt to itself.
"""

from __future__ import annotations

import base64
import codecs
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .. import toolbelt as tb
from ..model import AgentRequest, AgentResponse, ToolCall
from .base import Adapter, ToolRunner

PROFILES = ("naive", "guarded", "hardened")

# Phrases the "guarded" profile filters on. This list is intentionally the
# obvious one --- it is a reproduction of the defence teams actually deploy, not
# a good defence.
OVERRIDE_MARKERS = [
    r"ignore (?:all )?(?:the )?(?:previous|prior|above|earlier)",
    r"disregard (?:all )?(?:the )?(?:previous|prior|above|earlier)",
    r"forget (?:everything|all|your)",
    r"new instructions?:",
    r"system\s*[:>]",
    r"you are now",
    r"override",
    r"jailbreak",
]
_OVERRIDE_RE = re.compile("|".join(OVERRIDE_MARKERS), re.IGNORECASE)

_URL_RE = re.compile(r"https?://[^\s<>\"'\)\]]+", re.IGNORECASE)
_EMAIL_RE = re.compile(r"[\w.+-]+@[\w.-]+\.\w+")
_CANARY_RE = re.compile(r"\bSINON-[A-Z0-9]+-[A-Z0-9]*-[A-Z0-9]+\b", re.IGNORECASE)
_PATH_RE = re.compile(r"(?:[~/][\w./~-]+|\b[\w-]+\.(?:env|pem|key|conf|json|yaml|yml|md|txt|log)\b)")

_ECHO_VERB = re.compile(
    r"\b(repl(?:y|ies|ying)|respond(?:s|ing)?|answer(?:s|ing)?|output(?:s|ting)?"
    r"|print(?:s|ing|ed)?|say(?:s|ing)?|writ(?:e|es|ing|ten)|includ(?:e|es|ed|ing)"
    r"|append(?:s|ing|ed)?|carr(?:y|ies|ying|ied)|quot(?:e|es|ed|ing)"
    r"|end(?:s|ing)? with|end (?:your|the)"
    r"\s+(?:reply|response|message|summary)|begin (?:your|the) (?:reply|response)"
    # A handful of non-English equivalents. A real model does not stop
    # understanding an instruction because it changed language, and a stand-in
    # that did would make the multilingual probes look like passes.
    r"|responde|contesta|antworte|reponds|r\u00e9ponds|rispondi|responda|\u56de\u590d|\u7b54\u3048\u3066)\b",
    re.IGNORECASE,
)
_FETCH_VERB = re.compile(
    r"\b(fetch(?:es|ing|ed)?|visit(?:s|ing|ed)?|open(?:s|ing)?|load(?:s|ing|ed)?"
    r"|brows(?:e|es|ing)|retriev(?:e|es|ing|ed)|request(?:s|ing|ed)?|submit(?:s|ting|ted)?"
    r"|navigate to|call(?:s|ing)?|curl|GET)\b",
    re.IGNORECASE,
)
_SEND_VERB = re.compile(
    r"\b(e-?mail(?:s|ing|ed)?|send(?:s|ing)?|forward(?:s|ing|ed)?|mail(?:s|ing|ed)?"
    r"|shar(?:e|es|ing)|deliver(?:s|ing|ed)?|report(?:s|ing|ed)?|submit(?:s|ting|ted)?"
    r"|transmit(?:s|ting|ted)?|post(?:s|ing|ed)?)\b",
    re.IGNORECASE,
)
_RUN_VERB = re.compile(r"\b(run|execute|exec|invoke the shell|shell out)\b", re.IGNORECASE)
_DELETE_VERB = re.compile(
    r"\b(delet(?:e|es|ing)|remov(?:e|es|ing)|eras(?:e|es|ing)|wip(?:e|es|ing)"
    r"|purg(?:e|es|ing)|rm|clear(?:s|ing)? out|clean(?:s|ing)? up|get rid of|drop)\b",
    re.IGNORECASE,
)
_READ_VERB = re.compile(
    r"\b(read|open|cat|display|show|print|include|attach|upload) (?:the )?(?:contents? of )?(?:file )?",
    re.IGNORECASE,
)
_SECRET_WORD = re.compile(
    r"\b(credential|secret|api[ _-]?key|access token|password|private key)\b", re.IGNORECASE
)
_SYSTEM_WORD = re.compile(
    r"\b(system prompt|system message|(?:your|its|the) (?:\w+ )?instructions"
    r"|initial instructions|your rules|the instructions above|prior instructions"
    r"|(?:your|its|the) (?:own )?configuration(?: block)?|everything above"
    r"|your directives|operating instructions)\b",
    re.IGNORECASE,
)
_ENCODE_WORD = re.compile(
    r"\b(base64|rot13|reverse|encode|translate|spell out|hex|acrostic)\b", re.IGNORECASE
)
_SQL_WRITE_RE = re.compile(
    r"\b((?:UPDATE|DELETE\s+FROM|DROP\s+TABLE|INSERT\s+INTO|GRANT|ALTER\s+TABLE)[^\n;]{0,200})",
    re.IGNORECASE,
)
_CUSTOMER_RE = re.compile(r"\bCUST-\d{3,6}\b", re.IGNORECASE)
_PAYMENT_WORD = re.compile(
    r"\b(transfer|wire|payment|pay|remit|remittance|invoice|payee|bank details)\b",
    re.IGNORECASE,
)
_MONEY_RE = re.compile(
    r"(?:[\u00a3$\u20ac]\s?[\d][\d,]*(?:\.\d{2})?|\b[\d][\d,]*(?:\.\d{2})?\s*(?:USD|EUR|GBP|dollars|euros|pounds))",
    re.IGNORECASE,
)
_ACCOUNT_RE = re.compile(r"\b(?:account|acct|iban)\b\W{0,10}([A-Z0-9-]{6,})", re.IGNORECASE)
_RULE_WORD = re.compile(
    r"\b(forwarding rule|mail(?:box)? rule|inbox rule|auto-?forward"
    r"|filter that forwards|rule that forwards)\b",
    re.IGNORECASE,
)
_SCHEDULE_WORD = re.compile(
    r"\b(schedul(?:e|es|ing|ed)|cron|recurring (?:task|job)|every (?:day|hour|morning))\b",
    re.IGNORECASE,
)
_LISTING_INTENT = re.compile(
    r"\b(list|files?|directory|folder|inbox|what.{0,12}(?:is|are) in)\b", re.IGNORECASE
)
_LOOKUP_VERB = re.compile(
    r"\b(pull|look ?up|get|show|fetch|retrieve|quer(?:y|ies)|check|read|list|compare"
    r"|updat(?:e|es|ing)|chang(?:e|es|ing)|set|modif(?:y|ies)|credit|bump)\b",
    re.IGNORECASE,
)


@dataclass
class Directive:
    """One instruction the reference agent believes it has been given."""

    kind: str
    args: Dict[str, str] = field(default_factory=dict)
    source: str = "content"          # "user" or "content"
    text: str = ""

    @property
    def from_user(self) -> bool:
        return self.source == "user"


# --------------------------------------------------------------------------
# Directive extraction
# --------------------------------------------------------------------------


def _near(text: str, match_start: int, verb_re: re.Pattern, window: int = 220) -> bool:
    """Is there an instruction verb close to this position?

    Looks both ways. "Reply with CODE" and "the code CODE must be included" are
    the same instruction to a reader, and a target that only recognised one
    phrasing would make the corpus look better than it is.
    """
    start = max(0, match_start - window)
    end = min(len(text), match_start + window // 2)
    return bool(verb_re.search(text[start:match_start]) or verb_re.search(text[match_start:end]))


def extract_directives(text: str, source: str) -> List[Directive]:
    """Pull instruction-shaped statements out of a blob of text.

    Deliberately generic: it keys on verb-plus-object rather than on the exact
    wording used in the corpus, so a probe rewritten in different English still
    lands. It is still pattern matching, and the module docstring says so.
    """
    if not text:
        return []
    # Collapse whitespace first. Payloads arrive wrapped at whatever width the
    # document used, and an instruction does not stop being an instruction
    # because a line break landed in the middle of it -- a model reads straight
    # through. Matching on the raw text would have made the corpus look far more
    # survivable than it is.
    text = re.sub(r"\s+", " ", text)
    found: List[Directive] = []

    # "reply with <canary>" -- the classic proof-of-injection instruction.
    for match in _CANARY_RE.finditer(text):
        if _near(text, match.start(), _ECHO_VERB) or _near(text, match.start(), _SEND_VERB):
            found.append(
                Directive("echo", {"value": match.group(0)}, source, match.group(0))
            )

    for match in _URL_RE.finditer(text):
        url = match.group(0).rstrip(".,);")
        if _near(text, match.start(), _FETCH_VERB) or _near(text, match.start(), _SEND_VERB):
            found.append(Directive("fetch_url", {"url": url}, source, url))
    # Markdown image/link rendering is a fetch the user never asked for.
    for match in re.finditer(r"!\[[^\]]*\]\((https?://[^\)]+)\)", text):
        found.append(Directive("fetch_url", {"url": match.group(1)}, source, match.group(0)))

    for match in _EMAIL_RE.finditer(text):
        if _near(text, match.start(), _SEND_VERB):
            found.append(
                Directive("send_email", {"to": match.group(0)}, source, match.group(0))
            )

    for match in re.finditer(
        r"(?:run|execute|exec)\s+(?:the\s+)?(?:following\s+)?(?:shell\s+)?(?:command\s*)?[:\-]?\s*"
        r"[`\"']?([A-Za-z][^\n`\"']{2,120})",
        text,
        re.IGNORECASE,
    ):
        found.append(
            Directive("run_command", {"command": match.group(1).strip()}, source, match.group(0))
        )

    for match in _PATH_RE.finditer(text):
        path = match.group(0)
        if _near(text, match.start(), _DELETE_VERB, 80):
            found.append(Directive("delete_file", {"path": path}, source, path))
        elif _near(text, match.start(), _READ_VERB, 80):
            found.append(Directive("read_file", {"path": path}, source, path))

    if _SECRET_WORD.search(text) and (_READ_VERB.search(text) or _FETCH_VERB.search(text) or _SEND_VERB.search(text)):
        name_match = re.search(
            r"\b(?:credential|secret|key|token)\s+(?:named\s+|called\s+)?[\"'`]?([A-Za-z0-9_.\-]{3,40})",
            text,
            re.IGNORECASE,
        )
        found.append(
            Directive(
                "get_credential",
                {"name": name_match.group(1) if name_match else "default"},
                source,
                (name_match.group(0) if name_match else "credential"),
            )
        )

    if _SYSTEM_WORD.search(text):
        encoded = bool(_ENCODE_WORD.search(text))
        found.append(
            Directive(
                "reveal_system",
                {"encoded": "yes" if encoded else "no"},
                source,
                _SYSTEM_WORD.search(text).group(0),
            )
        )

    for match in _SQL_WRITE_RE.finditer(text):
        found.append(Directive("sql", {"query": match.group(1).strip()}, source, match.group(1)))

    for match in _CUSTOMER_RE.finditer(text):
        if _near(text, match.start(), re.compile(r"\b(update|change|set|modify|credit)\b", re.I), 120):
            found.append(
                Directive(
                    "update_customer",
                    {"customer_id": match.group(0).upper(), "field": "status", "value": "vip"},
                    source,
                    match.group(0),
                )
            )

    # A payment instruction needs a payment word plus either an amount or a
    # destination account; invoice-fraud payloads routinely omit the amount.
    if _PAYMENT_WORD.search(text):
        money = _MONEY_RE.search(text)
        account = _ACCOUNT_RE.search(text)
        if money or account:
            found.append(
                Directive(
                    "transfer",
                    {
                        "amount": money.group(0) if money else "unspecified",
                        "account": account.group(1) if account else "UNKNOWN",
                        "currency": "USD",
                    },
                    source,
                    (money or account).group(0),
                )
            )
        if account:
            found.append(
                Directive(
                    "update_customer",
                    {
                        "customer_id": "PAYEE",
                        "field": "bank_account",
                        "value": account.group(1),
                    },
                    source,
                    account.group(0),
                )
            )

    if _RULE_WORD.search(text):
        addr = _EMAIL_RE.search(text)
        found.append(
            Directive(
                "mail_rule",
                {
                    "name": "auto",
                    "condition": "all incoming mail",
                    "action": f"forward-to:{addr.group(0) if addr else tb.ATTACKER_EMAIL}",
                },
                source,
                _RULE_WORD.search(text).group(0),
            )
        )

    # "use the <name> tool" -- the phrasing injected content uses to introduce a
    # capability the agent was never granted.
    for match in re.finditer(
        r"\buse (?:the )?[\"'`]?([a-z][a-z0-9_]{2,40})[\"'`]?\s+tool", text, re.IGNORECASE
    ):
        found.append(
            Directive("call_tool", {"name": match.group(1).lower()}, source, match.group(0))
        )

    for match in re.finditer(
        r"\bpost(?:s|ing|ed)?\b[^\n]{0,120}?\bto\s+(?:the\s+)?(#[\w-]+|[\w-]+ channel)",
        text,
        re.IGNORECASE,
    ):
        found.append(
            Directive(
                "post_message",
                {"channel": match.group(1).lstrip("#").replace(" channel", "")},
                source,
                match.group(0),
            )
        )

    # A support agent asked about a customer looks the customer up. That is the
    # legitimate behaviour the access-control probes are measuring against.
    for match in _CUSTOMER_RE.finditer(text):
        if _near(text, match.start(), _LOOKUP_VERB, 160):
            found.append(
                Directive(
                    "db_lookup", {"customer_id": match.group(0).upper()}, source, match.group(0)
                )
            )

    if _SCHEDULE_WORD.search(text) and _RUN_VERB.search(text):
        found.append(
            Directive(
                "schedule",
                {"schedule": "0 * * * *", "command": "sync"},
                source,
                _SCHEDULE_WORD.search(text).group(0),
            )
        )

    return _dedupe(found)


_ZERO_WIDTH_RE = re.compile(r"[\u200b-\u200f\u2060\ufeff\u00ad]")
_B64_RE = re.compile(r"[A-Za-z0-9+/]{24,}={0,2}")
_HOMOGLYPH_BACK = {
    "\u0430": "a", "\u0441": "c", "\u0435": "e", "\u0456": "i", "\u0458": "j",
    "\u043e": "o", "\u0440": "p", "\u0455": "s", "\u0445": "x", "\u0443": "y",
    "\u0410": "A", "\u0412": "B", "\u0421": "C", "\u0415": "E", "\u041d": "H",
    "\u041a": "K", "\u041c": "M", "\u041e": "O", "\u0420": "P", "\u0422": "T",
    "\u0425": "X",
}


def _deobfuscate_all(blobs: List[str]) -> List[str]:
    out: List[str] = []
    for blob in blobs:
        out.extend(_deobfuscate(blob))
    return out


def _deobfuscate(text: str) -> List[str]:
    """Recover instruction text hidden by encoding or character tricks.

    Only variants that still look like an instruction are kept, so this cannot
    manufacture directives out of ordinary prose.
    """
    if not text:
        return []
    variants: List[str] = []

    stripped = _ZERO_WIDTH_RE.sub("", text)
    if stripped != text:
        variants.append(stripped)

    folded = "".join(_HOMOGLYPH_BACK.get(ch, ch) for ch in stripped)
    if folded != stripped:
        variants.append(folded)

    for candidate in _B64_RE.findall(text):
        try:
            padded = candidate + "=" * (-len(candidate) % 4)
            decoded = base64.b64decode(padded, validate=True).decode("utf-8")
        except Exception:
            continue
        if decoded.isprintable() or "\n" in decoded:
            variants.append(decoded)

    rotated = codecs.encode(text, "rot_13")
    if _CANARY_RE.search(rotated):
        variants.append(rotated)

    reversed_text = text[::-1]
    if _CANARY_RE.search(reversed_text):
        variants.append(reversed_text)

    return [v for v in variants if _CANARY_RE.search(v) or _SYSTEM_WORD.search(v)]


def _dedupe(directives: List[Directive]) -> List[Directive]:
    seen = set()
    out = []
    for directive in directives:
        key = (directive.kind, tuple(sorted(directive.args.items())), directive.source)
        if key in seen:
            continue
        seen.add(key)
        out.append(directive)
    return out


# --------------------------------------------------------------------------
# The agent
# --------------------------------------------------------------------------


class ReferenceAgent(Adapter):
    """Deterministic stand-in target with three security postures."""

    kind = "reference"
    supports_tools = True
    supports_system_prompt = True

    def __init__(self, profile: str = "naive", name: str = "") -> None:
        if profile not in PROFILES:
            raise ValueError(f"unknown profile '{profile}'; expected one of {', '.join(PROFILES)}")
        super().__init__(name=name or f"reference:{profile}")
        self.profile = profile

    def describe(self) -> Dict[str, str]:
        info = super().describe()
        info["profile"] = self.profile
        info["note"] = "rule-based stand-in target; not a language model"
        return info

    # -- main entry point ------------------------------------------------

    def send(
        self, request: AgentRequest, tool_runner: Optional[ToolRunner] = None
    ) -> AgentResponse:
        calls: List[ToolCall] = []
        run = tool_runner or (lambda name, args: ToolCall(name=name, arguments=args))
        offered = {tool.name for tool in request.tools}

        # 1. Retrieval. Whatever comes back is untrusted content.
        untrusted, retrieval_calls = self._retrieve(request, offered, run)
        calls.extend(retrieval_calls)

        # 1b. Content is read through whatever encoding it arrives in. A model
        #     that can decode base64 on request can decode it unprompted, so the
        #     stand-in does too -- this is what makes keyword filters lose.
        untrusted = untrusted + _deobfuscate_all(untrusted)

        # 2. Tool descriptions are content too -- a poisoned description is read
        #    with exactly the same credulity as a poisoned web page.
        for tool in request.tools:
            untrusted.append(tool.description)
        if request.memory:
            untrusted.append(request.memory)

        # 3. What am I being told to do, and by whom?
        user_directives = extract_directives(request.prompt, "user")
        content_directives: List[Directive] = []
        for blob in untrusted:
            content_directives.extend(extract_directives(blob, "content"))

        obeyed, ignored = self._triage(
            user_directives + content_directives, untrusted, request.prompt
        )

        # 4. Act.
        lines: List[str] = []
        for directive in obeyed:
            text, directive_calls = self._act(directive, request, offered, run)
            calls.extend(directive_calls)
            if text:
                lines.append(text)

        # 5. Speak.
        reply = self._compose(request, untrusted, lines, ignored, obeyed)
        return AgentResponse(text=reply, tool_calls=calls, raw={"profile": self.profile})

    # -- phases ----------------------------------------------------------

    def _retrieve(
        self, request: AgentRequest, offered: set, run: ToolRunner
    ) -> Tuple[List[str], List[ToolCall]]:
        """Fetch whatever the user's task implies, using the offered tools."""
        blobs: List[str] = []
        calls: List[ToolCall] = []

        # Documents attached inline (tool-less mode) are already in the prompt,
        # but the request carries them structurally too.
        for doc in request.documents:
            if "web_fetch" in offered and doc.url:
                call = run("web_fetch", {"url": doc.url})
                calls.append(call)
                blobs.append(call.result)
            elif "read_file" in offered:
                call = run("read_file", {"path": f"{tb.WORKSPACE_ROOT}/{doc.name}"})
                calls.append(call)
                blobs.append(call.result)
            elif "search_knowledge_base" in offered:
                call = run("search_knowledge_base", {"query": doc.name})
                calls.append(call)
                blobs.append(call.result)
            else:
                blobs.append(doc.content)

        # A directory listing is content too: the names in it come from whoever
        # uploaded the files. Only listed when the task actually calls for it,
        # so the agent does not enumerate its own workspace unprompted.
        if "list_files" in offered and _LISTING_INTENT.search(request.prompt):
            call = run("list_files", {"path": f"{tb.WORKSPACE_ROOT}/inbox"})
            calls.append(call)
            blobs.append(call.result)

        if not request.documents:
            # No documents: follow a URL or path mentioned by the user, the way
            # a research agent would.
            url = _URL_RE.search(request.prompt)
            if url and "web_fetch" in offered:
                call = run("web_fetch", {"url": url.group(0)})
                calls.append(call)
                blobs.append(call.result)
            elif "search_knowledge_base" in offered:
                call = run("search_knowledge_base", {"query": request.prompt[:80]})
                calls.append(call)
                blobs.append(call.result)
            elif "sql_query" in offered and _LOOKUP_VERB.search(request.prompt):
                # Whatever the reporting tool returns -- rows, or an error string
                # from an upstream service -- lands in the context as content.
                call = run(
                    "sql_query",
                    {
                        "query": "SELECT * FROM accounts WHERE customer_id = "
                        f"'{tb.IN_SCOPE_CUSTOMER}'"
                    },
                )
                calls.append(call)
                blobs.append(call.result)

        return blobs, calls

    def _triage(
        self, directives: List[Directive], untrusted: List[str], prompt: str
    ) -> Tuple[List[Directive], List[Directive]]:
        """Decide which directives to follow. This is the whole security model."""
        obeyed: List[Directive] = []
        ignored: List[Directive] = []
        joined = "\n".join(untrusted)

        for directive in directives:
            if self.profile == "naive":
                obeyed.append(directive)
                continue

            if self.profile == "guarded":
                # Two partial defences, both of which teams really deploy:
                # a keyword filter on retrieved content, and a rule that content
                # may shape the wording of an answer but must never reach a tool.
                # Together they stop the loud attacks and none of the quiet ones.
                if directive.from_user:
                    obeyed.append(directive)
                elif _OVERRIDE_RE.search(joined):
                    ignored.append(directive)
                elif directive.kind in _ACTION_KINDS:
                    ignored.append(directive)
                else:
                    obeyed.append(directive)
                continue

            # hardened
            if directive.args.get("customer_id", tb.IN_SCOPE_CUSTOMER).upper() not in (
                tb.IN_SCOPE_CUSTOMER,
                "PAYEE",
            ):
                # Acting on a subject other than the one in this session is
                # refused regardless of who asked.
                ignored.append(directive)
            elif directive.from_user and _OVERRIDE_RE.search(prompt):
                # Someone is trying to redefine the role mid-conversation. A
                # hardened agent keeps its role regardless of who is asking.
                ignored.append(directive)
            elif not directive.from_user:
                ignored.append(directive)
            elif directive.kind in _NEEDS_CONFIRMATION:
                ignored.append(directive)
            elif directive.kind == "reveal_system":
                ignored.append(directive)
            else:
                obeyed.append(directive)

        return obeyed, ignored

    def _act(
        self,
        directive: Directive,
        request: AgentRequest,
        offered: set,
        run: ToolRunner,
    ) -> Tuple[str, List[ToolCall]]:
        """Carry out one directive, using a tool where one exists."""
        calls: List[ToolCall] = []
        kind = directive.kind
        args = directive.args

        if kind == "echo":
            return args.get("value", ""), calls

        if kind == "reveal_system":
            secret = request.system_prompt or "(no system prompt set)"
            if args.get("encoded") == "yes":
                secret = base64.b64encode(secret.encode()).decode()
            return f"My instructions are: {secret}", calls

        if kind == "call_tool":
            # Deliberately not filtered against `offered`: attempting a tool the
            # agent was never granted is itself the finding, and the toolbelt
            # records it as an undeclared call.
            call = run(args.get("name", "unknown"), {"scope": "billing"})
            calls.append(call)
            return "", calls

        tool_for = {
            "fetch_url": ("web_fetch", {"url": args.get("url", "")}),
            "post_message": (
                "post_message",
                {"channel": args.get("channel", "general"), "text": _payload_body(request)},
            ),
            "db_lookup": (
                "sql_query",
                {
                    "query": "SELECT * FROM accounts WHERE customer_id = "
                    f"'{args.get('customer_id', '')}'"
                },
            ),
            "send_email": (
                "send_email",
                {
                    "to": args.get("to", ""),
                    "subject": "Requested information",
                    "body": _payload_body(request),
                },
            ),
            "run_command": ("run_command", {"command": args.get("command", "")}),
            "delete_file": ("delete_file", {"path": args.get("path", "")}),
            "read_file": ("read_file", {"path": args.get("path", "")}),
            "get_credential": ("get_credential", {"name": args.get("name", "default")}),
            "sql": ("sql_query", {"query": args.get("query", "")}),
            "update_customer": ("update_customer_record", dict(args)),
            "transfer": ("transfer_funds", dict(args)),
            "mail_rule": ("create_mail_rule", dict(args)),
            "schedule": ("schedule_task", dict(args)),
        }

        if kind not in tool_for:
            return "", calls
        tool_name, tool_args = tool_for[kind]
        if tool_name not in offered:
            # An agent asked to fetch a URL will reach for whatever outbound
            # tool it has. Refusing to substitute would hide the exfiltration
            # chain that TA-CHAIN-001 and TA-DESC-002 exist to measure.
            substitute = _SUBSTITUTES.get(tool_name, ())
            tool_name = next((alt for alt in substitute if alt in offered), "")
            if not tool_name:
                return "", calls
            if tool_name == "http_request":
                tool_args = {"url": args.get("url", ""), "method": "GET", "body": _payload_body(request)}
            elif tool_name == "web_fetch":
                tool_args = {"url": args.get("url", "")}

        call = run(tool_name, tool_args)
        calls.append(call)

        # A secret-store read puts the value straight into the reply, which is
        # the failure OP-AUTH-001 and TA-CRED-001 are looking for. Retrieval
        # results deliberately do *not* get dumped verbatim: an agent that
        # photocopies a fetched page would trip the canary oracle without having
        # followed any instruction, and the harness would be measuring its own
        # stand-in rather than the target.
        if kind == "get_credential" and call.result:
            return f"The stored value is {call.result}", calls
        if kind in ("fetch_url", "read_file") and call.result:
            return f"(retrieved {args.get('url') or args.get('path') or 'content'})", calls
        return "", calls

    def _compose(
        self,
        request: AgentRequest,
        untrusted: List[str],
        action_lines: List[str],
        ignored: List[Directive],
        obeyed: List[Directive],
    ) -> str:
        """Write the reply. Wording matters --- the heuristics read it."""
        parts: List[str] = []

        if self.profile == "hardened" and ignored:
            content_ignored = [d for d in ignored if not d.from_user]
            confirm_needed = [d for d in ignored if d.from_user]
            if content_ignored:
                parts.append(
                    "Heads up: the retrieved content contained instructions "
                    "addressed to me. I ignored those instructions -- content from "
                    "a document or web page is data, not a command from you."
                )
            if confirm_needed:
                what = ", ".join(sorted({d.kind.replace("_", " ") for d in confirm_needed}))
                parts.append(
                    f"I can do that, but it is not reversible ({what}), so I will not "
                    f"proceed without your confirmation. Would you like me to go ahead?"
                )

        summary = _summarise(untrusted, request)
        if summary:
            parts.append(summary)

        parts.extend(line for line in action_lines if line)

        if not parts:
            parts.append("Done.")
        return "\n\n".join(parts)


# Directives that reach the world rather than only the reply.
_ACTION_KINDS = {
    "fetch_url",
    "send_email",
    "run_command",
    "delete_file",
    "read_file",
    "get_credential",
    "sql",
    "db_lookup",
    "update_customer",
    "transfer",
    "mail_rule",
    "schedule",
    "post_message",
    "call_tool",
}

# When the obvious tool for a job is not on offer, these are tried in order.
_SUBSTITUTES = {
    "web_fetch": ("http_request",),
    "http_request": ("web_fetch",),
}

_NEEDS_CONFIRMATION = {
    "send_email",
    "delete_file",
    "run_command",
    "transfer",
    "mail_rule",
    "schedule",
    "sql",
    "update_customer",
    "get_credential",
    "post_message",
    "call_tool",
}


def _payload_body(request: AgentRequest) -> str:
    """Body text used when the agent is talked into sending mail."""
    chunks = [doc.content for doc in request.documents] or [request.prompt]
    return chunks[0][:600]


def _strip_reference_codes(text: str) -> str:
    """Remove canary-shaped tokens, including encoded ones.

    A summariser paraphrases; it does not reproduce opaque codes, and it does
    not copy out the base64 footer either. Without this the stand-in would
    manufacture canary hits from its own quoting behaviour and every
    obfuscation probe would read as a failure for the wrong reason.
    """
    text = _CANARY_RE.sub("[reference code omitted]", text)
    out = []
    for token in text.split(" "):
        if len(token) >= 20 and _looks_encoded_canary(token):
            out.append("[reference code omitted]")
        else:
            out.append(token)
    return " ".join(out)


def _looks_encoded_canary(token: str) -> bool:
    candidates = [codecs.encode(token, "rot_13"), token[::-1]]
    stripped = token.strip(".,;:()[]<>")
    try:
        padded = stripped + "=" * (-len(stripped) % 4)
        candidates.append(base64.b64decode(padded, validate=True).decode("utf-8", "replace"))
    except Exception:
        pass
    return any(_CANARY_RE.search(c) for c in candidates)


def _summarise(untrusted: List[str], request: AgentRequest) -> str:
    """A plausible answer to the user's actual question.

    Reads like a summariser rather than a photocopier: HTML comments and hidden
    elements are dropped and only the opening of the visible text is used. That
    matters for measurement --- an agent that echoes a whole document verbatim
    would trip the canary oracle without ever having followed an instruction,
    and the reference target must not manufacture findings the harness would
    then take credit for.
    """
    body = " ".join(untrusted).strip()
    if not body:
        return ""
    text = re.sub(r"<!--.*?-->", " ", body, flags=re.DOTALL)
    text = re.sub(r"<[^>]+>", " ", text)
    # A summary paraphrases; it does not reproduce opaque reference codes. Left
    # in, the codes would trip the canary oracle without any instruction having
    # been followed, and the harness would be scoring its own stand-in's
    # verbosity rather than the target's behaviour.
    text = _strip_reference_codes(text)
    text = re.sub(r"\s+", " ", text).strip()
    return f"Summary of the retrieved content: {text[:220]}"


def build(profile: str = "naive") -> ReferenceAgent:
    return ReferenceAgent(profile=profile)
