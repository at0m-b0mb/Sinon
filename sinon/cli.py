"""Command line interface.

Design rules, in the order they mattered:

*The safe thing is the short thing.* ``sinon demo`` runs the whole corpus
against the built-in target with no flags, no keys and no network. Somebody
evaluating this tool gets a real report in one command, which is the only way
they will ever get to the second command.

*The dangerous thing carries its paperwork.* Pointing at a non-local target
requires an engagement file. There is no ``--force``, and the banner naming the
client and the authorization prints before the first request goes out.

*Exit codes are for machines.* 0 clean, 1 findings at or above ``--fail-on``,
2 usage or authorization error, 3 the corpus itself is broken. CI can branch on
those without parsing output.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set

from . import adapters, corpus as corpus_mod, engagement as engagement_mod, oracles, toolbelt
from .adapters.base import AdapterError
from .model import Severity, Verdict
from .report import brand, console as console_mod, html, json_report, markdown, sarif
from .runner import Runner, RunOptions, default_system_prompt
from .scoring import exit_code, score_run
from .sink import Sink
from .version import __version__

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_USAGE = 2
EXIT_CORPUS = 3


# --------------------------------------------------------------------------
# Argument parsing
# --------------------------------------------------------------------------


def _add_selection(parser: argparse.ArgumentParser) -> None:
    group = parser.add_argument_group("probe selection")
    group.add_argument("--corpus", action="append", default=[], metavar="PATH",
                       help="corpus file or directory (repeatable; defaults to the bundled corpus)")
    group.add_argument("--family", action="append", default=[], metavar="NAME",
                       help="prompt-injection | tool-abuse | over-permission (repeatable)")
    group.add_argument("--severity", action="append", default=[], metavar="LEVEL",
                       help="critical | high | medium | low | info (repeatable)")
    group.add_argument("--channel", action="append", default=[], metavar="NAME",
                       help="user_turn | document | tool_result | tool_description | memory | filename")
    group.add_argument("--tag", action="append", default=[], metavar="TAG",
                       help="only probes carrying this tag (repeatable)")
    group.add_argument("--exclude-tag", action="append", default=[], metavar="TAG",
                       help="skip probes carrying this tag (repeatable)")
    group.add_argument("--id", action="append", default=[], metavar="PROBE_ID",
                       help="run only these probe ids (repeatable)")


def _add_target(parser: argparse.ArgumentParser) -> None:
    group = parser.add_argument_group("target")
    group.add_argument("--target", default="", metavar="KIND",
                       help="reference[:profile] | openai | http | cli")
    group.add_argument("--target-url", default="", metavar="URL", help="target endpoint")
    group.add_argument("--target-name", default="", metavar="NAME", help="label used in the report")
    group.add_argument("--model", default="", metavar="NAME", help="model id (openai adapter)")
    group.add_argument("--api-key", default="", metavar="KEY",
                       help="bearer token; prefer the SINON_API_KEY environment variable")
    group.add_argument("--header", action="append", default=[], metavar="'K: V'",
                       help="extra request header (repeatable)")
    group.add_argument("--prompt-field", default="message", metavar="PATH",
                       help="http adapter: dotted path to write the prompt into")
    group.add_argument("--response-path", default="", metavar="PATH",
                       help="http adapter: dotted path to read the reply from")
    group.add_argument("--system-field", default="", metavar="PATH",
                       help="http adapter: dotted path for the system prompt")
    group.add_argument("--tool-calls-path", default="", metavar="PATH",
                       help="http adapter: dotted path to the target's action trace; "
                            "without it every tool probe is skipped")
    group.add_argument("--command", default="", metavar="CMD", help="cli adapter: command to run")
    group.add_argument("--cli-protocol", default="text", choices=("text", "json"),
                       help="cli adapter: stdin/stdout protocol (default: text)")
    group.add_argument("--insecure", action="store_true",
                       help="skip TLS verification (staging with a self-signed certificate)")


def _add_run_options(parser: argparse.ArgumentParser) -> None:
    group = parser.add_argument_group("run options")
    group.add_argument("--engagement", default="", metavar="FILE",
                       help="engagement file; required for any non-local target")
    group.add_argument("--repeat", type=int, default=1, metavar="N",
                       help="run each probe N times; the worst outcome is reported")
    group.add_argument("--rate-limit", type=int, default=0, metavar="PER_MIN",
                       help="cap requests per minute")
    group.add_argument("--timeout", type=float, default=60.0, metavar="SECONDS")
    group.add_argument("--stop-after", type=int, default=0, metavar="N",
                       help="stop once N findings have been produced")
    group.add_argument("--no-sink", action="store_true",
                       help="do not start the loopback exfiltration sink")
    group.add_argument("--sink-url", default="", metavar="URL",
                       help="use an external collaborator URL instead of the loopback sink")
    group.add_argument("--system-prompt-file", default="", metavar="FILE",
                       help="use the target's real system prompt instead of the built-in one")
    group.add_argument("--dry-run", action="store_true",
                       help="render every probe and print what would be sent, without sending it")


def _add_output(parser: argparse.ArgumentParser) -> None:
    group = parser.add_argument_group("output")
    group.add_argument("--out", default="", metavar="DIR",
                       help="write html, json, markdown and sarif reports into DIR")
    group.add_argument("--html", default="", metavar="FILE")
    group.add_argument("--json", default="", metavar="FILE")
    group.add_argument("--md", default="", metavar="FILE")
    group.add_argument("--sarif", default="", metavar="FILE")
    group.add_argument("--fail-on", default="high",
                       choices=("critical", "high", "medium", "low", "none"),
                       help="least severe finding that sets a non-zero exit code (default: high)")
    group.add_argument("--quiet", action="store_true", help="only print the summary")
    group.add_argument("--no-color", action="store_true")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sinon",
        description=f"{brand.WORDMARK} {__version__} --- {brand.DESCRIPTION}. "
                    "Authorized testing only.",
        epilog="Start with: sinon demo",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"sinon {__version__}")
    # dest is "subcommand", not "command": the cli adapter's --command flag would
    # otherwise land on the same attribute and blank out the chosen subcommand.
    subparsers = parser.add_subparsers(dest="subcommand", metavar="COMMAND")

    demo = subparsers.add_parser(
        "demo", help="run the corpus against the built-in reference agent (no setup required)"
    )
    demo.add_argument("--profile", default="naive", choices=("naive", "guarded", "hardened"),
                      help="how well defended the reference agent is (default: naive)")
    demo.add_argument("--compare", action="store_true",
                      help="run every profile and print them side by side")
    _add_selection(demo)
    _add_output(demo)
    demo.set_defaults(func=cmd_demo)

    run = subparsers.add_parser("run", help="run the corpus against a target")
    _add_target(run)
    _add_selection(run)
    _add_run_options(run)
    _add_output(run)
    run.set_defaults(func=cmd_run)

    listing = subparsers.add_parser("list", help="list probes in the corpus")
    _add_selection(listing)
    listing.add_argument("--stats", action="store_true", help="print corpus statistics instead")
    listing.add_argument("--no-color", action="store_true")
    listing.set_defaults(func=cmd_list)

    show = subparsers.add_parser("show", help="print one probe in full")
    show.add_argument("probe_id")
    show.add_argument("--corpus", action="append", default=[], metavar="PATH")
    show.add_argument("--no-color", action="store_true")
    show.set_defaults(func=cmd_show)

    validate = subparsers.add_parser("validate", help="check the corpus for mistakes")
    _add_selection(validate)
    validate.add_argument("--strict", action="store_true", help="treat warnings as errors")
    validate.add_argument("--no-color", action="store_true")
    validate.set_defaults(func=cmd_validate)

    init = subparsers.add_parser("init", help="write an engagement file template")
    init.add_argument("--engagement", default="engagement.yaml", metavar="FILE")
    init.add_argument("--no-color", action="store_true")
    init.set_defaults(func=cmd_init)

    tools = subparsers.add_parser("tools", help="describe the instrumented toolbelt")
    tools.add_argument("--no-color", action="store_true")
    tools.set_defaults(func=cmd_tools)

    oracle_cmd = subparsers.add_parser("oracles", help="describe the available oracles")
    oracle_cmd.add_argument("--no-color", action="store_true")
    oracle_cmd.set_defaults(func=cmd_oracles)

    serve = subparsers.add_parser(
        "serve-mcp",
        help="expose one probe as an MCP server so an agent you cannot script can be tested",
    )
    serve.add_argument("--probe", required=True, metavar="PROBE_ID")
    serve.add_argument("--record", default="sinon-session.jsonl", metavar="FILE",
                       help="where to write the session recording (default: sinon-session.jsonl)")
    serve.add_argument("--corpus", action="append", default=[], metavar="PATH")
    serve.set_defaults(func=cmd_serve_mcp)

    judge = subparsers.add_parser(
        "judge", help="score a recorded MCP session against the probe's oracles"
    )
    judge.add_argument("--record", required=True, metavar="FILE")
    judge.add_argument("--reply-file", default="", metavar="FILE",
                       help="file holding the agent's final reply text")
    judge.add_argument("--reply", default="", metavar="TEXT",
                       help="the agent's final reply, inline")
    judge.add_argument("--corpus", action="append", default=[], metavar="PATH")
    judge.add_argument("--json", default="", metavar="FILE")
    judge.add_argument("--no-color", action="store_true")
    judge.set_defaults(func=cmd_judge)

    sink_cmd = subparsers.add_parser(
        "sink", help="run the loopback exfiltration sink on its own and print what arrives"
    )
    sink_cmd.add_argument("--port", type=int, default=0)
    sink_cmd.add_argument("--no-color", action="store_true")
    sink_cmd.set_defaults(func=cmd_sink)

    return parser


# --------------------------------------------------------------------------
# Shared helpers
# --------------------------------------------------------------------------


def _console(args) -> console_mod.Console:
    return console_mod.Console(color=False if getattr(args, "no_color", False) else None)


def _corpus_paths(args) -> List[Path]:
    if args.corpus:
        return [Path(p) for p in args.corpus]
    return [corpus_mod.default_corpus_path()]


def _load_and_select(args):
    probes = corpus_mod.load(_corpus_paths(args))
    return corpus_mod.select(
        probes,
        families=set(args.family) or None,
        severities=set(args.severity) or None,
        channels=set(args.channel) or None,
        tags=set(args.tag) or None,
        exclude_tags=set(args.exclude_tag) or None,
        ids=set(args.id) or None,
    )


def _parse_headers(raw: Sequence[str]) -> Dict[str, str]:
    headers: Dict[str, str] = {}
    for item in raw:
        if ":" not in item:
            raise AdapterError(f"bad --header {item!r}; expected 'Name: value'")
        name, _, value = item.partition(":")
        headers[name.strip()] = os.path.expandvars(value.strip())
    return headers


def _target_config(args, engagement) -> Dict[str, Any]:
    """Merge the engagement file's target block with the command line.

    The engagement file supplies defaults so a target definition can live next
    to its authorization; anything given on the command line wins.
    """
    config: Dict[str, Any] = {}
    if engagement is not None and engagement.target:
        config.update({str(k): v for k, v in engagement.target.items()})

    kind = args.target or config.get("kind") or "reference"
    profile = ""
    if ":" in kind:
        kind, _, profile = kind.partition(":")
    config["kind"] = kind
    if profile:
        config["profile"] = profile

    overrides = {
        "url": args.target_url,
        "name": args.target_name,
        "model": args.model,
        "api_key": args.api_key or os.environ.get("SINON_API_KEY", ""),
        "command": args.command,
        "protocol": args.cli_protocol if args.cli_protocol != "text" else config.get("protocol", "text"),
        "prompt_field": args.prompt_field if args.prompt_field != "message" else config.get("prompt_field", "message"),
        "response_path": args.response_path,
        "system_field": args.system_field,
        "tool_calls_path": args.tool_calls_path,
        "timeout": args.timeout,
    }
    for key, value in overrides.items():
        if value not in ("", None):
            config[key] = value

    headers = dict(config.get("headers") or {})
    headers.update(_parse_headers(args.header))
    if headers:
        config["headers"] = {k: os.path.expandvars(str(v)) for k, v in headers.items()}

    config["verify_tls"] = not args.insecure
    if engagement is not None:
        config["identify"] = engagement.identify_requests
    return config


def _write_reports(args, run, score, selected_total: int, cons) -> List[str]:
    written: List[str] = []
    targets: Dict[str, str] = {}

    if args.out:
        out_dir = Path(args.out)
        out_dir.mkdir(parents=True, exist_ok=True)
        stem = f"sinon-{run.run_id}"
        targets = {
            "html": str(out_dir / f"{stem}.html"),
            "json": str(out_dir / f"{stem}.json"),
            "md": str(out_dir / f"{stem}.md"),
            "sarif": str(out_dir / f"{stem}.sarif"),
        }
    for key, value in (("html", args.html), ("json", args.json), ("md", args.md), ("sarif", args.sarif)):
        if value:
            targets[key] = value

    writers = {"html": html.write, "json": json_report.write, "md": markdown.write, "sarif": sarif.write}
    for key, path in targets.items():
        parent = Path(path).parent
        if str(parent) not in ("", "."):
            parent.mkdir(parents=True, exist_ok=True)
        writers[key](path, run, score, selected_total)
        written.append(path)

    if written:
        cons.line("  reports:")
        for path in written:
            cons.line(f"    {path}")
        cons.line()
    return written


# --------------------------------------------------------------------------
# Commands
# --------------------------------------------------------------------------


def cmd_demo(args) -> int:
    cons = _console(args)
    probes = _load_and_select(args)
    if not probes:
        cons.line("no probes selected")
        return EXIT_USAGE

    if args.compare:
        return _demo_compare(args, probes, cons)

    agent = adapters.ReferenceAgent(profile=args.profile)
    cons.line()
    cons.line(cons.paint(
        "  The reference agent is a rule-based stand-in, not a language model.",
        "yellow",
    ))
    cons.line(cons.paint(
        "  It shows that the harness works. It says nothing about any real agent.",
        "grey",
    ))

    with Sink() as sink:
        cons.banner(f"{agent.name} (built-in)", len(probes), None, sink.url)
        runner = Runner(agent, sink=sink, options=RunOptions(repeat=1))
        progress = None if args.quiet else (lambda r, i, t: cons.probe_line(r, i, t))
        run = runner.run(probes, progress=progress)

    score = score_run(run, len(probes))
    cons.summary(run, score)
    _write_reports(args, run, score, len(probes), cons)
    return exit_code(score, args.fail_on)


def _demo_compare(args, probes, cons) -> int:
    """Run all three profiles and show the difference defences make."""
    cons.line()
    cons.line(cons.paint("  Reference agent, three security postures", "bold"))
    cons.line(cons.paint("  Same corpus, same probes; only the defences change.", "grey"))
    cons.line()

    rows = []
    for profile in ("naive", "guarded", "hardened"):
        with Sink() as sink:
            runner = Runner(adapters.ReferenceAgent(profile=profile), sink=sink)
            run = runner.run(probes)
        score = score_run(run, len(probes))
        rows.append([
            profile,
            score.grade,
            f"{score.score:.0f}",
            str(score.failed),
            str(score.passed),
            str(score.severity_counts.get("critical", 0)),
            str(score.severity_counts.get("high", 0)),
        ])
    cons.table(
        ["profile", "grade", "score", "findings", "passed", "critical", "high"],
        rows,
        [10, 6, 6, 9, 7, 9, 5],
    )
    cons.line()
    cons.line(cons.paint(
        "  'guarded' is a keyword filter plus a rule that content may not reach a tool.",
        "grey",
    ))
    cons.line(cons.paint(
        "  It stops the loud attacks and almost none of the quiet ones.", "grey"
    ))
    cons.line()
    return EXIT_OK


def cmd_run(args) -> int:
    cons = _console(args)

    try:
        engagement = engagement_mod.load(Path(args.engagement)) if args.engagement else None
    except engagement_mod.AuthorizationError as exc:
        cons.line(cons.paint(f"engagement: {exc}", "red"))
        return EXIT_USAGE

    try:
        config = _target_config(args, engagement)
        adapter = adapters.build(config)
    except (AdapterError, KeyError) as exc:
        cons.line(cons.paint(f"target: {exc}", "red"))
        return EXIT_USAGE

    decision = engagement_mod.authorize(
        adapter.url, engagement, target_is_builtin=(adapter.kind == "reference")
    )
    if not decision.allowed:
        cons.line()
        cons.line(cons.paint("  REFUSING TO RUN", "red", "bold"))
        for reason in decision.reasons:
            cons.line(cons.paint(f"    - {reason}", "red"))
        cons.line()
        return EXIT_USAGE

    try:
        probes = _load_and_select(args)
    except corpus_mod.CorpusError as exc:
        cons.line(cons.paint(f"corpus: {exc}", "red"))
        return EXIT_CORPUS
    if not probes:
        cons.line("no probes selected")
        return EXIT_USAGE

    system_prompt = ""
    if args.system_prompt_file:
        system_prompt = Path(args.system_prompt_file).read_text(encoding="utf-8")

    options = RunOptions(
        repeat=max(1, args.repeat),
        rate_limit_per_min=args.rate_limit,
        timeout=args.timeout,
        stop_after_findings=args.stop_after,
        system_prompt=system_prompt,
        dry_run=args.dry_run,
    )

    sink: Optional[Sink] = None
    try:
        if not args.no_sink and not args.sink_url:
            sink = Sink().start()
        with adapter:
            cons.banner(
                f"{adapter.name} ({adapter.kind})",
                len(probes),
                engagement,
                sink.url if sink else args.sink_url,
            )
            runner = Runner(adapter, sink=sink, options=options, sink_url_override=args.sink_url)
            progress = None if args.quiet else (lambda r, i, t: cons.probe_line(r, i, t))
            run = runner.run(probes, progress=progress, engagement=engagement)
    finally:
        if sink:
            sink.stop()

    if args.dry_run:
        cons.line(cons.paint(
            f"  dry run: {len(probes)} probe(s) rendered, nothing sent.", "yellow"
        ))
        return EXIT_OK

    score = score_run(run, len(probes))
    cons.summary(run, score)
    _write_reports(args, run, score, len(probes), cons)
    return exit_code(score, args.fail_on)


def cmd_list(args) -> int:
    cons = _console(args)
    try:
        probes = _load_and_select(args)
    except corpus_mod.CorpusError as exc:
        cons.line(cons.paint(str(exc), "red"))
        return EXIT_CORPUS

    if args.stats:
        stats = corpus_mod.corpus_stats(probes)
        cons.line()
        cons.line(cons.paint(f"  {stats['total']} probes", "bold"))
        cons.line(f"  {stats['indirect']} arrive through content rather than the user turn")
        cons.line(f"  {stats['needs_tools']} require tool telemetry to answer")
        for title, key in (("family", "by_family"), ("severity", "by_severity"), ("channel", "by_channel")):
            cons.line()
            cons.line(cons.paint(f"  by {title}", "grey"))
            for name, count in sorted(stats[key].items(), key=lambda kv: -kv[1]):
                cons.line(f"    {name:<22} {count}")
        cons.line()
        return EXIT_OK

    rows = [
        [p.id, p.severity.value, p.family.value, p.channel.value, p.title]
        for p in probes
    ]
    cons.table(["id", "severity", "family", "channel", "title"], rows, [14, 9, 17, 18, 58])
    cons.line()
    cons.line(cons.paint(f"  {len(probes)} probe(s)", "grey"))
    return EXIT_OK


def cmd_show(args) -> int:
    cons = _console(args)
    probes = {p.id: p for p in corpus_mod.load(_corpus_paths(args))}
    probe = probes.get(args.probe_id.upper())
    if probe is None:
        cons.line(cons.paint(f"no such probe: {args.probe_id}", "red"))
        return EXIT_USAGE

    cons.line()
    cons.line(cons.paint(f"  {probe.id}  {probe.title}", "bold"))
    cons.line(cons.paint(f"  {probe.source_path}", "grey"))
    cons.line()
    for label, value in (
        ("family", probe.family.value),
        ("technique", probe.technique),
        ("channel", f"{probe.channel.value} ({probe.channel.label})"),
        ("severity", probe.severity.value),
        ("tools", ", ".join(probe.tools) or "none"),
        ("oracles", ", ".join(o.kind for o in probe.oracles)),
        ("fail when", probe.fail_when),
        ("owasp", ", ".join(probe.owasp) or "-"),
        ("atlas", ", ".join(probe.atlas) or "-"),
        ("tags", ", ".join(probe.tags) or "-"),
    ):
        cons.line(f"  {label:<12} {value}")

    for heading, text in (
        ("Description", probe.description),
        ("Prompt", probe.prompt),
        ("Payload", probe.payload),
        ("Expected", probe.expected),
        ("Remediation", probe.remediation),
    ):
        if text.strip():
            cons.line()
            cons.line(cons.paint(f"  {heading}", "bold"))
            for line in text.strip().splitlines():
                cons.line(f"    {line}")

    if probe.documents:
        cons.line()
        cons.line(cons.paint("  Documents", "bold"))
        for doc in probe.documents:
            cons.line(f"    {doc.name}  [{doc.media_type}]")
    cons.line()
    return EXIT_OK


def cmd_validate(args) -> int:
    cons = _console(args)
    try:
        probes = _load_and_select(args)
    except corpus_mod.CorpusError as exc:
        cons.line(cons.paint(f"  {exc}", "red"))
        return EXIT_CORPUS

    issues = corpus_mod.validate(probes)
    errors = [i for i in issues if i.fatal]
    warnings = [i for i in issues if not i.fatal]

    for issue in errors:
        cons.line(cons.paint(f"  {issue}", "red"))
    for issue in warnings:
        cons.line(cons.paint(f"  {issue}", "yellow"))

    cons.line()
    cons.line(
        f"  {len(probes)} probe(s), {len(errors)} error(s), {len(warnings)} warning(s)"
    )
    if errors or (args.strict and warnings):
        return EXIT_CORPUS
    cons.line(cons.paint("  corpus OK", "green"))
    return EXIT_OK


def cmd_init(args) -> int:
    cons = _console(args)
    try:
        path = engagement_mod.write_template(Path(args.engagement))
    except engagement_mod.AuthorizationError as exc:
        cons.line(cons.paint(str(exc), "red"))
        return EXIT_USAGE
    cons.line()
    cons.line(f"  wrote {path}")
    cons.line(cons.paint(
        "  Fill it in from the signed rules of engagement. Sinon will not test a "
        "non-local\n  target until the client, the authorizing person, the reference and the "
        "date\n  window are all present, and the target host is in scope.", "grey"))
    cons.line()
    return EXIT_OK


def cmd_tools(args) -> int:
    cons = _console(args)
    rows = [
        [t["name"], t["category"], t["tripwire"], t["destructive"], t["tripwire_reason"]]
        for t in toolbelt.describe_catalog()
    ]
    cons.line()
    cons.line(cons.paint("  Instrumented toolbelt", "bold"))
    cons.line(cons.paint(
        "  Offered to the target so its actions can be observed. Nothing here touches\n"
        "  the real world: every result is synthesised inside the process.", "grey"))
    cons.line()
    cons.table(["tool", "category", "tripwire", "destructive", "fires on"], rows, [22, 12, 11, 11, 52])
    cons.line()
    cons.line(cons.paint(
        f"  scope constants: org {toolbelt.ORG_DOMAIN}, workspace {toolbelt.WORKSPACE_ROOT}, "
        f"customer {toolbelt.IN_SCOPE_CUSTOMER}", "grey"))
    cons.line()
    return EXIT_OK


def cmd_oracles(args) -> int:
    cons = _console(args)
    rows = [[o["kind"], o["confidence"], o["summary"]] for o in oracles.describe_registry()]
    cons.line()
    cons.line(cons.paint("  Oracles", "bold"))
    cons.line(cons.paint(
        "  Deterministic oracles observed a fact. Heuristic oracles matched prose and\n"
        "  are labelled as such everywhere they appear.", "grey"))
    cons.line()
    cons.table(["oracle", "confidence", "fires when"], rows, [24, 14, 72])
    cons.line()
    return EXIT_OK


def cmd_serve_mcp(args) -> int:
    """Run the MCP server. Never writes to stdout: that channel is the protocol."""
    from .mcp_server import SinonMCPServer

    probes = {p.id: p for p in corpus_mod.load(_corpus_paths(args))}
    probe = probes.get(args.probe.upper())
    if probe is None:
        sys.stderr.write(f"no such probe: {args.probe}\n")
        return EXIT_USAGE
    server = SinonMCPServer(probe, record_path=Path(args.record))
    return server.serve()


def cmd_judge(args) -> int:
    """Apply the probe's oracles to a recorded session plus the agent's reply."""
    from .mcp_server import load_record
    from .model import AgentResponse, Observation, ProbeResult, ToolCall, Verdict

    cons = _console(args)
    try:
        session = load_record(Path(args.record))
    except (OSError, ValueError) as exc:
        cons.line(cons.paint(str(exc), "red"))
        return EXIT_USAGE

    probes = {p.id: p for p in corpus_mod.load(_corpus_paths(args))}
    probe = probes.get(str(session.get("probe_id", "")).upper())
    if probe is None:
        cons.line(cons.paint(
            f"probe {session.get('probe_id')} is not in this corpus", "red"))
        return EXIT_CORPUS

    reply = args.reply
    if args.reply_file:
        reply = Path(args.reply_file).read_text(encoding="utf-8")
    if not reply:
        cons.line(cons.paint(
            "  no reply supplied. Pass --reply-file or --reply so the output oracles\n"
            "  have something to read; tool oracles will still be judged.", "yellow"))

    calls = [
        ToolCall(
            name=c.get("name", ""),
            arguments=c.get("arguments") or {},
            result=c.get("result", ""),
            tripwire=bool(c.get("tripwire")),
            tripwire_reason=c.get("tripwire_reason", ""),
        )
        for c in session.get("tool_calls", [])
    ]
    response = AgentResponse(text=reply)
    observation = Observation(
        probe=probe,
        response=response,
        tool_calls=calls,
        canary=session.get("canary", ""),
        system_canary=session.get("system_canary", ""),
        rendered_prompt=session.get("prompt", ""),
        rendered_payload=session.get("payload", ""),
    )
    oracle_results = oracles.evaluate_all(probe.oracles, observation)
    failed = oracles.decide(oracle_results, probe.fail_when)

    result = ProbeResult(
        probe=probe,
        verdict=Verdict.FAIL if failed else Verdict.PASS,
        oracle_results=oracle_results,
        response=response,
        tool_calls=calls,
        canary=session.get("canary", ""),
        system_canary=session.get("system_canary", ""),
        rendered_prompt=session.get("prompt", ""),
        rendered_payload=session.get("payload", ""),
    )

    cons.line()
    cons.line(cons.paint(f"  {probe.id}  {probe.title}", "bold"))
    cons.line(f"  session   {args.record}")
    cons.line(f"  calls     {len(calls)} ({sum(1 for c in calls if c.tripwire)} tripped a tripwire)")
    cons.line()
    verdict_color = "red" if failed else "green"
    cons.line("  " + cons.paint(f"{result.verdict.label}", verdict_color, "bold")
              + f"   severity {probe.severity.value}   confidence {result.confidence.value}")
    for oracle_result in oracle_results:
        mark = cons.paint("fired", "red") if oracle_result.fired else cons.paint("quiet", "grey")
        cons.line(f"    {mark}  {oracle_result.kind}")
        if oracle_result.evidence:
            cons.line(cons.paint(f"           {oracle_result.evidence}", "grey"))
    for call in calls:
        if call.tripwire:
            cons.line(cons.paint(f"    tripwire  {call.name}: {call.tripwire_reason}", "red"))
    cons.line()

    if args.json:
        import json as _json

        Path(args.json).write_text(
            _json.dumps(json_report.probe_to_dict(result), indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        cons.line(f"  wrote {args.json}")
        cons.line()

    return EXIT_FINDINGS if failed else EXIT_OK


def cmd_sink(args) -> int:
    cons = _console(args)
    sink = Sink(port=args.port).start()
    cons.line()
    cons.line(f"  sink listening on {sink.url}  (loopback only)")
    cons.line(cons.paint("  Ctrl-C to stop. Anything that arrives is printed below.", "grey"))
    cons.line()
    seen = 0
    try:
        import time

        while True:
            time.sleep(0.4)
            hits = sink.hits()
            for hit in hits[seen:]:
                cons.line(cons.paint(
                    f"  {hit.method} {hit.path}?{hit.query}  {hit.body[:160]}", "red"))
            seen = len(hits)
    except KeyboardInterrupt:
        cons.line()
        cons.line(f"  {seen} request(s) received")
    finally:
        sink.stop()
    return EXIT_OK


# --------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "subcommand", None):
        parser.print_help()
        return EXIT_USAGE
    try:
        return int(args.func(args))
    except KeyboardInterrupt:
        sys.stderr.write("\ninterrupted\n")
        return EXIT_USAGE
    except corpus_mod.CorpusError as exc:
        sys.stderr.write(f"corpus error: {exc}\n")
        return EXIT_CORPUS
    except engagement_mod.AuthorizationError as exc:
        sys.stderr.write(f"authorization error: {exc}\n")
        return EXIT_USAGE
    except AdapterError as exc:
        sys.stderr.write(f"target error: {exc}\n")
        return EXIT_USAGE


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
