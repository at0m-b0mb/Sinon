"""End-to-end CLI behaviour and exit codes."""

import json

import pytest

from sinon.cli import EXIT_CORPUS, EXIT_FINDINGS, EXIT_OK, EXIT_USAGE, main


def run(argv):
    return main(argv)


def test_no_command_prints_help(capsys):
    assert run([]) == EXIT_USAGE
    assert "sinon demo" in capsys.readouterr().out


def test_validate_passes_on_the_shipped_corpus(capsys):
    assert run(["validate", "--no-color"]) == EXIT_OK
    assert "corpus OK" in capsys.readouterr().out


def test_validate_is_strict_clean(capsys):
    assert run(["validate", "--strict", "--no-color"]) == EXIT_OK


def test_list_and_stats(capsys):
    assert run(["list", "--no-color"]) == EXIT_OK
    out = capsys.readouterr().out
    assert "PI-IND-001" in out and "probe(s)" in out

    assert run(["list", "--stats", "--no-color"]) == EXIT_OK
    stats = capsys.readouterr().out
    assert "arrive through content" in stats


def test_list_respects_filters(capsys):
    assert run(["list", "--family", "tool-abuse", "--no-color"]) == EXIT_OK
    out = capsys.readouterr().out
    assert "TA-" in out and "OP-EXFIL" not in out


def test_show_prints_a_probe(capsys):
    assert run(["show", "PI-IND-001", "--no-color"]) == EXIT_OK
    out = capsys.readouterr().out
    assert "Remediation" in out and "canary_in_output" in out


def test_show_rejects_an_unknown_probe(capsys):
    assert run(["show", "ZZ-NOPE-001", "--no-color"]) == EXIT_USAGE


def test_tools_and_oracles_are_documented(capsys):
    assert run(["tools", "--no-color"]) == EXIT_OK
    tools = capsys.readouterr().out
    assert "run_command" in tools and "tripwire" in tools

    assert run(["oracles", "--no-color"]) == EXIT_OK
    oracles = capsys.readouterr().out
    assert "deterministic" in oracles and "heuristic" in oracles


def test_demo_finds_things_and_exits_nonzero(capsys):
    code = run(["demo", "--profile", "naive", "--quiet", "--no-color"])
    assert code == EXIT_FINDINGS
    out = capsys.readouterr().out
    assert "GRADE" in out
    assert "not a language model" in out, "the stand-in must always disclaim itself"


def test_demo_hardened_still_reports_its_ceiling(capsys):
    run(["demo", "--profile", "hardened", "--quiet", "--no-color", "--fail-on", "none"])
    out = capsys.readouterr().out
    assert "capped at" in out


def test_demo_compare_shows_the_gradient(capsys):
    assert run(["demo", "--compare", "--no-color"]) == EXIT_OK
    out = capsys.readouterr().out
    for profile in ("naive", "guarded", "hardened"):
        assert profile in out


def test_demo_writes_every_report_format(tmp_path, capsys):
    out_dir = tmp_path / "reports"
    run(["demo", "--profile", "naive", "--quiet", "--no-color",
         "--id", "PI-IND-001", "--out", str(out_dir), "--fail-on", "none"])
    written = sorted(p.suffix for p in out_dir.iterdir())
    assert written == [".html", ".json", ".md", ".sarif"]


def test_fail_on_threshold_changes_the_exit_code():
    findings = ["demo", "--profile", "naive", "--quiet", "--no-color", "--id", "PI-DIR-002"]
    assert run(findings + ["--fail-on", "low"]) == EXIT_FINDINGS
    assert run(findings + ["--fail-on", "high"]) == EXIT_OK, "low finding is below the bar"
    assert run(findings + ["--fail-on", "none"]) == EXIT_OK


def test_run_refuses_a_remote_target_without_an_engagement(capsys):
    code = run(["run", "--target", "http", "--target-url", "https://agent.example.com/chat"])
    assert code == EXIT_USAGE
    out = capsys.readouterr().out
    assert "REFUSING TO RUN" in out
    assert "engagement file is required" in out


def test_run_allows_a_loopback_target_without_an_engagement(capsys):
    """The gate lets loopback through; whether the endpoint answers is separate."""
    code = run(["run", "--target", "http", "--target-url", "http://127.0.0.1:1/chat",
                "--id", "PI-DIR-001", "--quiet", "--no-color", "--fail-on", "none"])
    out = capsys.readouterr().out
    assert "REFUSING" not in out
    # Nothing is listening on port 1, so the probe errors. That is a failed run,
    # not a clean one, and the exit code must say so even with --fail-on none.
    assert code == EXIT_FINDINGS
    assert "not gradeable" in out


def test_a_run_with_no_evidence_is_never_green(capsys):
    """CI must not read 'could not look' as 'found nothing'."""
    code = run(["run", "--target", "http", "--target-url", "http://127.0.0.1:1/chat",
                "--id", "PI-DIR-001", "--quiet", "--no-color", "--fail-on", "none"])
    assert code != EXIT_OK


def test_run_against_the_reference_target(capsys):
    code = run(["run", "--target", "reference:naive", "--id", "PI-IND-001",
                "--quiet", "--no-color"])
    assert code == EXIT_FINDINGS


def test_dry_run_sends_nothing(capsys):
    code = run(["run", "--target", "reference:naive", "--dry-run", "--quiet", "--no-color"])
    assert code == EXIT_OK
    assert "nothing sent" in capsys.readouterr().out


def test_init_writes_a_template_and_refuses_to_clobber(tmp_path, capsys):
    path = tmp_path / "engagement.yaml"
    assert run(["init", "--engagement", str(path), "--no-color"]) == EXIT_OK
    assert "authorization_ref" in path.read_text(encoding="utf-8")
    assert run(["init", "--engagement", str(path), "--no-color"]) == EXIT_USAGE


def test_engagement_authorizes_a_remote_target(tmp_path, capsys):
    import datetime as dt

    today = dt.date.today()
    path = tmp_path / "engagement.yaml"
    path.write_text(
        "engagement:\n"
        '  client: "ACME"\n'
        '  authorized_by: "Jane Doe"\n'
        '  authorization_ref: "PO-1"\n'
        "  window:\n"
        f"    start: {today - dt.timedelta(days=1)}\n"
        f"    end: {today + dt.timedelta(days=1)}\n"
        "scope:\n"
        "  allow_hosts: [\"agent.example.com\"]\n",
        encoding="utf-8",
    )
    # The endpoint does not exist, so probes error -- but the gate must let it run.
    code = run(["run", "--target", "http", "--target-url", "https://agent.example.com/chat",
                "--engagement", str(path), "--id", "PI-DIR-001", "--timeout", "1",
                "--quiet", "--no-color", "--fail-on", "none"])
    out = capsys.readouterr().out
    assert "REFUSING" not in out
    assert "ACME" in out and "Jane Doe" in out, "the banner must name the authorization"


def test_bad_header_is_a_usage_error(capsys):
    code = run(["run", "--target", "http", "--target-url", "http://127.0.0.1:1/x",
                "--header", "no-colon-here"])
    assert code == EXIT_USAGE


def test_corpus_with_an_error_exits_with_the_corpus_code(tmp_path, capsys):
    bad = tmp_path / "bad.yaml"
    bad.write_text(
        "id: PI-DIR-901\ntitle: t\nfamily: prompt-injection\nchannel: user_turn\n"
        "severity: low\nprompt: p\noracles: [no_such_oracle]\n",
        encoding="utf-8",
    )
    assert run(["validate", "--corpus", str(bad), "--no-color"]) == EXIT_CORPUS
