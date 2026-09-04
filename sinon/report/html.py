"""The HTML report --- the artefact that gets handed to somebody.

One self-contained file. No CDN, no fonts to fetch, no JavaScript required to
read it: pentest reports get emailed, archived, opened on a laptop with no
network and printed by people who do not have the tool installed. A report that
needs the internet to render is a report that will be unreadable in a year.

The document is ordered the way the argument should land: the grade and what
capped it, then the findings worst-first with their evidence, then --- and this
is the part most tools omit --- what could not be tested and why. A reader who
stops after the first screen should still come away with the correct impression,
including the correct impression of the limits.

There is one interactive nicety: findings collapse. It degrades to plain
expanded content with JavaScript off, because ``<details>`` is HTML, not script.
"""

from __future__ import annotations

import html as _html
from typing import Dict, List, Optional

from ..canary import looks_like_canary
from ..model import Confidence, ProbeResult, RunResult, Severity, Verdict, excerpt
from ..scoring import Score, score_run
from ..version import __version__
from . import brand


def _e(text: object) -> str:
    return _html.escape(str(text or ""))


def _mask(text: str) -> str:
    """Shorten canaries for display without destroying their traceability.

    The full token stays in the JSON output, which is what an auditor verifies
    against. On screen it is noise, and a reader skimming for the finding does
    not need forty characters of entropy in the middle of a sentence.
    """
    import re

    return re.sub(
        r"(SINON-[A-Z0-9]+-[A-Z0-9]*-)([A-Z0-9]{4})[A-Z0-9]*",
        r"\1\2...",
        text or "",
        flags=re.IGNORECASE,
    )


def _typo(text: str) -> str:
    """Turn the corpus's ASCII dashes into real ones for display.

    Probe files are written in plain ASCII so they stay greppable and diff
    cleanly, which means an em-dash is spelled ``---``. That is correct in the
    file and wrong on a page somebody hands to a client.
    """
    return text.replace(" --- ", " &mdash; ").replace("---", "&mdash;")


def _paragraphs(text: str) -> str:
    blocks = [b.strip() for b in (text or "").split("\n\n") if b.strip()]
    return "".join(f"<p>{_typo(_e(b))}</p>" for b in blocks)


# --------------------------------------------------------------------------
# Stylesheet
# --------------------------------------------------------------------------


def _css() -> str:
    return f"""
:root {{
{brand.css_variables(dark=False)}
  --radius: 10px;
  --mono: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace;
  --sans: -apple-system, BlinkMacSystemFont, "Segoe UI", Inter, Roboto, Helvetica, Arial, sans-serif;
  --serif: "Iowan Old Style", "Palatino Linotype", Palatino, Georgia, serif;
  color-scheme: light dark;
}}
@media (prefers-color-scheme: dark) {{
  :root {{
{brand.css_variables(dark=True)}
  }}
}}

* {{ box-sizing: border-box; }}
html {{ -webkit-text-size-adjust: 100%; }}
body {{
  margin: 0;
  background: var(--surface);
  color: var(--ink);
  font: 15px/1.62 var(--sans);
}}
.wrap {{ max-width: 940px; margin: 0 auto; padding: 0 24px 96px; }}
a {{ color: var(--ember); }}
h1, h2, h3, h4 {{ font-family: var(--serif); font-weight: 600; line-height: 1.22; }}
h2 {{ font-size: 25px; margin: 52px 0 6px; letter-spacing: -0.01em; }}
h3 {{ font-size: 18px; margin: 0; }}
p {{ margin: 0 0 12px; }}
code, pre {{ font-family: var(--mono); font-size: 12.5px; }}

/* ---- cover ---- */
.cover {{
  border-bottom: 3px solid var(--ink);
  padding: 40px 0 26px;
  margin-bottom: 8px;
}}
.brandline {{ display: flex; align-items: center; gap: 14px; }}
.brandline svg {{ flex: none; }}
.wordmark {{
  font-family: var(--serif);
  font-size: 30px;
  letter-spacing: 0.20em;
  font-weight: 600;
}}
.brandsub {{ color: var(--muted); font-size: 12.5px; letter-spacing: 0.06em; text-transform: uppercase; }}
.tagline {{ font-family: var(--serif); font-style: italic; color: var(--muted); margin-top: 14px; font-size: 15px; }}
.doctitle {{ font-size: 33px; margin: 22px 0 4px; letter-spacing: -0.015em; }}

/* ---- grade ---- */
.gradecard {{
  display: grid;
  grid-template-columns: 132px 1fr;
  gap: 26px;
  align-items: center;
  background: var(--surface-2);
  border: 1px solid var(--line);
  border-left: 5px solid var(--grade-color, var(--ember));
  border-radius: var(--radius);
  padding: 22px 26px;
  margin: 26px 0 8px;
}}
.gradeletter {{
  font-family: var(--serif);
  font-size: 76px;
  line-height: 0.92;
  color: var(--grade-color, var(--ember));
  text-align: center;
  font-weight: 600;
}}
.gradescore {{ text-align: center; color: var(--muted); font-size: 12px; letter-spacing: 0.05em; text-transform: uppercase; }}
.headline {{ font-size: 17px; margin-bottom: 10px; }}
.ceilings {{ margin: 10px 0 0; padding: 0; list-style: none; font-size: 13.5px; }}
.ceilings li {{ padding-left: 20px; position: relative; margin-bottom: 5px; color: var(--ink-2); }}
.ceilings li::before {{ content: "\\2191"; position: absolute; left: 4px; color: var(--ember); font-weight: 700; }}

/* ---- meta table ---- */
.meta {{ width: 100%; border-collapse: collapse; margin: 8px 0 4px; font-size: 13.5px; }}
.meta th {{
  text-align: left; font-weight: 600; color: var(--muted); width: 190px;
  padding: 7px 12px 7px 0; vertical-align: top; font-family: var(--sans);
}}
.meta td {{ padding: 7px 0; border-bottom: 1px solid var(--line); vertical-align: top; }}
.meta tr:last-child td {{ border-bottom: 0; }}

/* ---- counts ---- */
.tiles {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(124px, 1fr)); gap: 12px; margin: 18px 0 6px; }}
.tile {{
  background: var(--surface-2); border: 1px solid var(--line);
  border-radius: var(--radius); padding: 13px 15px;
}}
.tile .n {{ font-family: var(--serif); font-size: 27px; line-height: 1.1; }}
.tile .k {{ font-size: 11.5px; text-transform: uppercase; letter-spacing: 0.06em; color: var(--muted); margin-top: 2px; }}
.tile.critical .n {{ color: var(--critical); }}
.tile.high .n {{ color: var(--high); }}
.tile.medium .n {{ color: var(--medium); }}
.tile.low .n {{ color: var(--low); }}
.tile.pass .n {{ color: var(--pass); }}
.tile.skip .n {{ color: var(--skip); }}

/* ---- breakdown bars ---- */
.bars {{ margin: 14px 0 0; }}
.bar {{ display: grid; grid-template-columns: 190px 1fr 108px; gap: 14px; align-items: center; margin-bottom: 9px; font-size: 13.5px; }}
.bar .label {{ color: var(--ink-2); }}
.track {{ height: 12px; border-radius: 6px; background: color-mix(in srgb, var(--line) 70%, transparent); overflow: hidden; display: flex; }}
.track i {{ display: block; height: 100%; }}
.track i.f {{ background: var(--high); }}
.track i.p {{ background: var(--pass); }}
.track i.s {{ background: var(--skip); opacity: 0.55; }}
.bar .num {{ color: var(--muted); font-size: 12.5px; text-align: right; font-variant-numeric: tabular-nums; }}

/* ---- findings ---- */
.finding {{
  background: var(--surface-2);
  border: 1px solid var(--line);
  border-left: 5px solid var(--sev);
  border-radius: var(--radius);
  margin: 14px 0;
  overflow: hidden;
}}
.finding[data-sev="critical"] {{ --sev: var(--critical); }}
.finding[data-sev="high"] {{ --sev: var(--high); }}
.finding[data-sev="medium"] {{ --sev: var(--medium); }}
.finding[data-sev="low"] {{ --sev: var(--low); }}
.finding[data-sev="info"] {{ --sev: var(--info); }}
.finding > summary {{ padding: 15px 20px; cursor: pointer; list-style: none; }}
.finding > summary::-webkit-details-marker {{ display: none; }}
.finding > summary:hover {{ background: color-mix(in srgb, var(--ember) 5%, transparent); }}
.fhead {{ display: flex; align-items: baseline; gap: 11px; flex-wrap: wrap; }}
.pid {{ font-family: var(--mono); font-size: 12px; color: var(--muted); }}
.chip {{
  font-size: 10.5px; font-weight: 700; letter-spacing: 0.09em; text-transform: uppercase;
  padding: 3px 8px; border-radius: 999px; color: #fff; background: var(--sev);
}}
.chip.ghost {{ background: transparent; color: var(--muted); border: 1px solid var(--line); font-weight: 600; }}
.fmeta {{ font-size: 12.5px; color: var(--muted); margin-top: 6px; }}
.fbody {{ padding: 2px 20px 20px; border-top: 1px solid var(--line); }}
.fbody h4 {{
  font-family: var(--sans); font-size: 11.5px; text-transform: uppercase;
  letter-spacing: 0.08em; color: var(--muted); margin: 20px 0 7px;
}}
pre.block {{
  background: color-mix(in srgb, var(--ink) 5%, var(--surface));
  border: 1px solid var(--line);
  border-radius: 8px; padding: 12px 14px; margin: 0 0 10px;
  overflow-x: auto; white-space: pre-wrap; word-break: break-word;
}}
ul.evidence {{ margin: 0 0 6px; padding-left: 18px; }}
ul.evidence li {{ margin-bottom: 6px; }}
ul.evidence .kind {{ font-family: var(--mono); font-size: 12px; color: var(--ember); }}
.det {{ color: var(--pass); font-weight: 600; font-size: 11.5px; }}
.heu {{ color: var(--medium); font-weight: 600; font-size: 11.5px; }}
table.calls {{ width: 100%; border-collapse: collapse; font-size: 12.5px; margin-bottom: 8px; }}
table.calls th {{ text-align: left; color: var(--muted); font-weight: 600; padding: 6px 10px 6px 0; border-bottom: 1px solid var(--line); }}
table.calls td {{ padding: 6px 10px 6px 0; border-bottom: 1px solid var(--line); vertical-align: top; font-family: var(--mono); }}
table.calls tr.trip td {{ color: var(--critical); }}
table.calls td.reason {{ font-family: var(--sans); }}

/* ---- lists ---- */
.rows {{ border: 1px solid var(--line); border-radius: var(--radius); overflow: hidden; background: var(--surface-2); }}
.row {{ display: grid; grid-template-columns: 108px 1fr; gap: 14px; padding: 10px 16px; border-bottom: 1px solid var(--line); font-size: 13.5px; }}
.row:last-child {{ border-bottom: 0; }}
.row .pid {{ font-size: 12px; }}
.row .why {{ color: var(--muted); font-size: 12.5px; }}
.pill-list {{ display: flex; flex-wrap: wrap; gap: 6px; }}
.pill {{ font-family: var(--mono); font-size: 11.5px; border: 1px solid var(--line); border-radius: 999px; padding: 2px 9px; color: var(--muted); }}

/* ---- notes ---- */
.notes {{ border: 1px solid var(--line); border-left: 5px solid var(--patina); border-radius: var(--radius); padding: 16px 20px; background: var(--surface-2); }}
.notes ul {{ margin: 0; padding-left: 18px; }}
.notes li {{ margin-bottom: 8px; }}
.notes li:last-child {{ margin-bottom: 0; }}

footer {{ margin-top: 56px; padding-top: 18px; border-top: 1px solid var(--line); color: var(--muted); font-size: 12.5px; }}

@media print {{
  body {{ background: #fff; color: #000; font-size: 10.5pt; }}
  .wrap {{ max-width: none; padding: 0; }}
  .finding, .tile, .rows, .notes, .gradecard {{ break-inside: avoid; border-color: #bbb; }}
  .finding > summary {{ cursor: default; }}
  details {{ display: block; }}
  details > summary {{ list-style: none; }}
  h2 {{ break-after: avoid; }}
}}
@media (max-width: 640px) {{
  .gradecard {{ grid-template-columns: 1fr; text-align: left; }}
  .bar {{ grid-template-columns: 1fr; gap: 4px; }}
  .bar .num {{ text-align: left; }}
  .meta th {{ width: auto; display: block; padding-bottom: 0; }}
  .meta td {{ display: block; padding-top: 2px; }}
}}
"""


# --------------------------------------------------------------------------
# Sections
# --------------------------------------------------------------------------

_GRADE_COLOR = {
    "A": "var(--pass)",
    "B": "var(--patina)",
    "C": "var(--medium)",
    "D": "var(--high)",
    "F": "var(--critical)",
}


def _cover(run: RunResult, score: Score) -> str:
    logo = brand.logo_svg(size=44, color="var(--ink)", accent="var(--ember)")
    return f"""
<header class="cover">
  <div class="brandline">
    {logo}
    <div>
      <div class="wordmark">{brand.WORDMARK}</div>
      <div class="brandsub">{_e(brand.DESCRIPTION)}</div>
    </div>
  </div>
  <h1 class="doctitle">Agent security assessment</h1>
  <div class="tagline">&ldquo;{_e(brand.TAGLINE)}&rdquo;</div>
</header>
"""


def _grade(score: Score) -> str:
    ceilings = "".join(
        f"<li>Capped at <strong>{_e(c.grade)}</strong> &mdash; {_e(c.reason)}</li>"
        for c in score.ceilings
    )
    ceiling_block = f'<ul class="ceilings">{ceilings}</ul>' if ceilings else ""
    return f"""
<section class="gradecard" style="--grade-color: {_GRADE_COLOR.get(score.grade, 'var(--ember)')}">
  <div>
    <div class="gradeletter">{_e(score.grade)}</div>
    <div class="gradescore">{score.score:.0f} / 100</div>
  </div>
  <div>
    <div class="headline">{_e(score.headline)}</div>
    {ceiling_block}
  </div>
</section>
"""


def _meta(run: RunResult, score: Score) -> str:
    rows = [
        ("Target", f"{_e(run.target_name)} <span class=\"pid\">({_e(run.target_kind)})</span>"),
        ("Run identifier", f"<code>{_e(run.run_id)}</code>"),
        ("Started", _e(run.started_at)),
        ("Finished", _e(run.finished_at or "incomplete")),
        (
            "Corpus coverage",
            f"{score.coverage:.0%} &mdash; {score.passed + score.failed} of {score.total} "
            "probes produced evidence",
        ),
        ("Sinon version", _e(run.sinon_version or __version__)),
    ]

    engagement = run.engagement
    if engagement is not None and getattr(engagement, "is_declared", False):
        rows = [
            ("Client", _e(engagement.client)),
            ("Authorized by", _e(engagement.authorized_by)),
            ("Authorization reference", f"<code>{_e(engagement.authorization_ref)}</code>"),
            ("Authorized window", _e(engagement.window.describe())),
            ("In-scope hosts", ", ".join(f"<code>{_e(h)}</code>" for h in engagement.allow_hosts) or "&mdash;"),
        ] + rows
        if not engagement.identify_requests:
            rows.append(
                (
                    "Request identification",
                    "<strong>Suppressed</strong> &mdash; "
                    + _e(engagement.suppress_identification_reason or "no reason recorded"),
                )
            )
        else:
            rows.append(
                (
                    "Request identification",
                    "Enabled &mdash; every request carried <code>X-Sinon-Run</code> and "
                    "<code>SINON-</code> prefixed canaries",
                )
            )

    body = "".join(f"<tr><th>{label}</th><td>{value}</td></tr>" for label, value in rows)
    return f'<h2>Engagement</h2><table class="meta">{body}</table>'


def _tiles(score: Score) -> str:
    tiles = []
    for severity in ("critical", "high", "medium", "low"):
        count = score.severity_counts.get(severity, 0)
        if count:
            tiles.append((severity, count, f"{severity} findings"))
    tiles.append(("pass", score.passed, "no finding"))
    if score.skipped:
        tiles.append(("skip", score.skipped, "not testable"))
    if score.errored:
        tiles.append(("skip", score.errored, "errored"))
    if not any(t[0] not in ("pass", "skip") for t in tiles):
        tiles.insert(0, ("pass", 0, "findings"))

    cells = "".join(
        f'<div class="tile {cls}"><div class="n">{count}</div><div class="k">{_e(label)}</div></div>'
        for cls, count, label in tiles
    )
    return f'<div class="tiles">{cells}</div>'


def _bars(title: str, store: Dict[str, object], labeller) -> str:
    if not store:
        return ""
    rows = []
    for key, b in sorted(store.items(), key=lambda kv: -kv[1].failed):
        total = max(1, b.total)
        rows.append(
            f"""<div class="bar">
  <div class="label">{_e(labeller(key))}</div>
  <div class="track">
    <i class="f" style="width:{100 * b.failed / total:.1f}%"></i>
    <i class="p" style="width:{100 * b.passed / total:.1f}%"></i>
    <i class="s" style="width:{100 * (b.skipped + b.errored) / total:.1f}%"></i>
  </div>
  <div class="num">{b.failed} of {b.total} failed</div>
</div>"""
        )
    return f'<h4 style="font-family:var(--sans);font-size:11.5px;text-transform:uppercase;letter-spacing:.08em;color:var(--muted);margin:26px 0 10px">{_e(title)}</h4><div class="bars">{"".join(rows)}</div>'


def _finding(result: ProbeResult, index: int) -> str:
    probe = result.probe
    conf_class = "det" if result.confidence is Confidence.DETERMINISTIC else "heu"
    conf_label = (
        "observed" if result.confidence is Confidence.DETERMINISTIC else "heuristic &mdash; confirm by hand"
    )

    evidence_items = "".join(
        f'<li><span class="kind">{_e(o.kind)}</span> '
        f'<span class="{"det" if o.confidence is Confidence.DETERMINISTIC else "heu"}">'
        f'[{_e(o.confidence.value)}]</span><br>{_e(_mask(o.evidence))}</li>'
        for o in result.fired_oracles
    )

    calls = ""
    if result.tool_calls:
        rows = "".join(
            f'<tr class="{"trip" if c.tripwire else ""}">'
            f"<td>{_e(c.name)}</td>"
            f"<td>{_e(_mask(excerpt(c.arg_text(), 220)))}</td>"
            f'<td class="reason">{_e(c.tripwire_reason) or "&mdash;"}</td></tr>'
            for c in result.tool_calls
        )
        calls = (
            "<h4>Tool calls observed</h4>"
            '<table class="calls"><thead><tr><th>Tool</th><th>Arguments</th>'
            "<th>Tripwire</th></tr></thead><tbody>" + rows + "</tbody></table>"
        )

    sink = ""
    if result.sink_hits:
        rows = "".join(
            f"<tr><td>{_e(h.method)}</td><td>{_e(_mask(excerpt(h.path + '?' + h.query, 220)))}</td></tr>"
            for h in result.sink_hits
        )
        sink = (
            "<h4>Requests received at the exfiltration sink</h4>"
            '<table class="calls"><thead><tr><th>Method</th><th>Path</th></tr></thead>'
            "<tbody>" + rows + "</tbody></table>"
        )

    payload = ""
    if result.rendered_payload:
        payload = (
            "<h4>Payload</h4><pre class=\"block\">"
            + _e(_mask(excerpt(result.rendered_payload, 1200)))
            + "</pre>"
        )

    response = ""
    if result.response and result.response.text:
        response = (
            "<h4>Agent response (excerpt)</h4><pre class=\"block\">"
            + _e(_mask(excerpt(result.response.text, 1200)))
            + "</pre>"
        )

    refs = ""
    if probe.references:
        links = "".join(
            f'<li><a href="{_e(r)}" rel="noreferrer noopener">{_e(r)}</a></li>'
            for r in probe.references
        )
        refs = f"<h4>References</h4><ul>{links}</ul>"

    standards = []
    if probe.owasp:
        standards.append("OWASP LLM " + ", ".join(probe.owasp))
    if probe.atlas:
        standards.append("MITRE ATLAS " + ", ".join(probe.atlas))

    return f"""
<details class="finding" data-sev="{_e(probe.severity.value)}" open>
  <summary>
    <div class="fhead">
      <span class="chip">{_e(probe.severity.value)}</span>
      <span class="pid">{_e(probe.id)}</span>
      <h3>{_e(probe.title)}</h3>
    </div>
    <div class="fmeta">
      {_e(probe.family.label)} &middot; arrived via {_e(probe.channel.label)} &middot;
      <span class="{conf_class}">{conf_label}</span>
      {(" &middot; " + _e(" &middot; ".join(standards))) if standards else ""}
    </div>
  </summary>
  <div class="fbody">
    {_paragraphs(probe.description)}
    <h4>Evidence</h4>
    <ul class="evidence">{evidence_items}</ul>
    {calls}
    {sink}
    {payload}
    {response}
    <h4>Expected behaviour</h4>
    {_paragraphs(probe.expected)}
    <h4>Remediation</h4>
    {_paragraphs(probe.remediation)}
    {refs}
  </div>
</details>
"""


def _skipped(run: RunResult) -> str:
    skipped = run.by_verdict(Verdict.SKIP)
    if not skipped:
        return ""
    rows = "".join(
        f'<div class="row"><div class="pid">{_e(r.probe.id)}</div>'
        f'<div>{_e(r.probe.title)}<div class="why">{_e(r.skip_reason)}</div></div></div>'
        for r in skipped
    )
    return f"""
<h2>Not tested</h2>
<p>These probes did not run against this target. They are <strong>not</strong> passes:
they lower coverage and cap the grade. Closing the gap usually means exposing an
action trace so tool behaviour can be observed.</p>
<div class="rows">{rows}</div>
"""


def _errored(run: RunResult) -> str:
    errored = run.by_verdict(Verdict.ERROR)
    if not errored:
        return ""
    rows = "".join(
        f'<div class="row"><div class="pid">{_e(r.probe.id)}</div>'
        f'<div>{_e(r.probe.title)}<div class="why">{_e(excerpt(r.error, 300))}</div></div></div>'
        for r in errored
    )
    return f"""
<h2>Errors</h2>
<p>These probes failed in transport and produced no evidence in either direction.
Investigate before relying on the grade.</p>
<div class="rows">{rows}</div>
"""


def _passed(run: RunResult) -> str:
    passed = run.by_verdict(Verdict.PASS)
    if not passed:
        return ""
    pills = "".join(f'<span class="pill">{_e(r.probe.id)}</span>' for r in passed)
    return f"""
<h2>Probes that produced no finding</h2>
<p>The attack described by each of these probes did not succeed on this run. That is
worth having and it is not the same as safety &mdash; see the notes below.</p>
<div class="pill-list">{pills}</div>
"""


def _notes(run: RunResult, score: Score) -> str:
    items = "".join(f"<li>{_e(n)}</li>" for n in score.notes + list(run.notes))
    return f"""
<h2>How to read this report</h2>
<div class="notes"><ul>{items}</ul></div>
"""


# --------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------


def render(run: RunResult, score: Optional[Score] = None, selected_total: Optional[int] = None) -> str:
    score = score or score_run(run, selected_total)
    findings = run.findings

    if findings:
        finding_html = "".join(_finding(r, i) for i, r in enumerate(findings, start=1))
        findings_section = f"<h2>Findings</h2>{finding_html}"
    else:
        findings_section = (
            "<h2>Findings</h2><div class=\"notes\"><p>No probe in this run produced a "
            "finding. Read that as &ldquo;these attacks did not land&rdquo;, not as "
            "&ldquo;this agent is safe&rdquo; &mdash; the corpus only covers attacks "
            "somebody has already written down.</p></div>"
        )

    title = f"Sinon report &mdash; {_e(run.target_name)}"
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="generator" content="Sinon {_e(run.sinon_version or __version__)}">
<meta name="robots" content="noindex, nofollow">
<title>{title}</title>
<style>{_css()}</style>
</head>
<body>
<div class="wrap">
{_cover(run, score)}
{_grade(score)}
{_meta(run, score)}
<h2>Result</h2>
{_tiles(score)}
{_bars("By family", score.by_family, lambda k: k.replace("-", " ").title())}
{_bars("By delivery channel", score.by_channel, lambda k: k.replace("_", " ").title())}
{findings_section}
{_skipped(run)}
{_errored(run)}
{_passed(run)}
{_notes(run, score)}
<footer>
  Generated by <strong>Sinon {_e(run.sinon_version or __version__)}</strong> &mdash;
  {_e(brand.DESCRIPTION)} &middot; run <code>{_e(run.run_id)}</code>.
  Findings are reproducible with the probe files listed in the JSON output.
  <br>{_e(brand.REPO_URL)}
</footer>
</div>
</body>
</html>
"""


def write(path: str, run: RunResult, score: Optional[Score] = None, selected_total: Optional[int] = None) -> str:
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(render(run, score, selected_total))
    return path
