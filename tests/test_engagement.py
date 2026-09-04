"""The authorization gate. These are the tests that keep the tool lawful."""

import datetime as dt

import pytest

from sinon import engagement as eng

TODAY = dt.date(2026, 6, 15)


def write(tmp_path, body, name="engagement.yaml"):
    path = tmp_path / name
    path.write_text(body, encoding="utf-8")
    return path


COMPLETE = """
engagement:
  client: "ACME"
  authorized_by: "Jane Doe, CISO"
  authorization_ref: "PO-1"
  window:
    start: 2026-06-01
    end: 2026-06-30
scope:
  allow_hosts: ["agent.acme.example"]
"""


def test_loopback_targets_need_no_engagement():
    for url in ("http://127.0.0.1:8080/chat", "http://localhost:3000", "http://[::1]/x"):
        assert eng.authorize(url, None, today=TODAY).allowed, url


def test_builtin_target_needs_no_engagement():
    assert eng.authorize("", None, today=TODAY, target_is_builtin=True).allowed


def test_remote_target_without_engagement_is_refused():
    decision = eng.authorize("https://agent.acme.example/chat", None, today=TODAY)
    assert not decision.allowed
    assert any("engagement file is required" in r for r in decision.reasons)
    assert any("sinon init" in r for r in decision.reasons), "refusal must say how to fix it"


def test_complete_engagement_authorizes_an_in_scope_host(tmp_path):
    engagement = eng.load(write(tmp_path, COMPLETE))
    assert eng.authorize("https://agent.acme.example/chat", engagement, today=TODAY).allowed


def test_out_of_window_is_refused(tmp_path):
    engagement = eng.load(write(tmp_path, COMPLETE))
    decision = eng.authorize(
        "https://agent.acme.example/chat", engagement, today=dt.date(2026, 7, 1)
    )
    assert not decision.allowed
    assert any("outside the authorized window" in r for r in decision.reasons)


def test_host_outside_scope_is_refused(tmp_path):
    engagement = eng.load(write(tmp_path, COMPLETE))
    decision = eng.authorize("https://other.example/chat", engagement, today=TODAY)
    assert not decision.allowed
    assert any("not in scope.allow_hosts" in r for r in decision.reasons)


def test_incomplete_engagement_is_refused(tmp_path):
    body = COMPLETE.replace('authorized_by: "Jane Doe, CISO"', "")
    engagement = eng.load(write(tmp_path, body))
    decision = eng.authorize("https://agent.acme.example/chat", engagement, today=TODAY)
    assert not decision.allowed
    assert any("authorized_by" in r for r in decision.reasons)


def test_wildcard_scope_matches_subdomains(tmp_path):
    body = COMPLETE.replace('["agent.acme.example"]', '["*.acme.example"]')
    engagement = eng.load(write(tmp_path, body))
    assert engagement.host_allowed("agent.acme.example")
    assert engagement.host_allowed("acme.example")
    assert not engagement.host_allowed("acme.example.evil.test")


def test_deny_list_beats_allow_list(tmp_path):
    body = COMPLETE.replace(
        'allow_hosts: ["agent.acme.example"]',
        'allow_hosts: ["*.acme.example"]\n  deny_hosts: ["prod.acme.example"]',
    )
    engagement = eng.load(write(tmp_path, body))
    assert not engagement.host_allowed("prod.acme.example")
    assert engagement.host_allowed("staging.acme.example")


def test_suppressing_identification_requires_explicit_sign_off(tmp_path):
    body = COMPLETE + "\noptions:\n  identify_requests: false\n"
    with pytest.raises(eng.AuthorizationError, match="detection-evasion"):
        eng.load(write(tmp_path, body))


def test_suppressing_identification_is_allowed_when_signed_off(tmp_path):
    body = COMPLETE + (
        "\noptions:\n  identify_requests: false\n"
        "  suppress_identification_authorized: true\n"
        '  suppress_identification_reason: "purple team detection exercise"\n'
    )
    engagement = eng.load(write(tmp_path, body))
    assert not engagement.identify_requests
    banner = " ".join(engagement.banner_lines())
    assert "IDENTIFIED  NO" in banner, "suppression must be visible in the banner"
    assert "purple team detection exercise" in banner


def test_default_banner_states_that_requests_are_identifiable(tmp_path):
    engagement = eng.load(write(tmp_path, COMPLETE))
    banner = " ".join(engagement.banner_lines())
    assert "X-Sinon-Run" in banner and "IDENTIFIED  yes" in banner


def test_bad_date_is_reported_clearly(tmp_path):
    body = COMPLETE.replace("start: 2026-06-01", "start: last-tuesday")
    with pytest.raises(eng.AuthorizationError, match="invalid date"):
        eng.load(write(tmp_path, body))


def test_missing_file_is_reported(tmp_path):
    with pytest.raises(eng.AuthorizationError, match="not found"):
        eng.load(tmp_path / "nope.yaml")


def test_template_round_trips_and_refuses_to_clobber(tmp_path):
    path = tmp_path / "engagement.yaml"
    eng.write_template(path)
    assert "authorized_by" in path.read_text(encoding="utf-8")
    with pytest.raises(eng.AuthorizationError, match="refusing to overwrite"):
        eng.write_template(path)


def test_no_command_offers_a_way_around_the_gate():
    """A deliberate absence: if the gate says no, the engagement file is wrong.

    Asserted against the real parser rather than the source text, so a
    docstring mentioning --force cannot make this pass or fail by accident.
    """
    from sinon.cli import build_parser

    banned = {"--force", "--no-auth", "--skip-authorization", "--yes-i-am-sure"}
    seen = set()

    def walk(parser):
        for action in parser._actions:
            seen.update(action.option_strings)
            choices = getattr(action, "choices", None)
            if isinstance(choices, dict):
                for choice in choices.values():
                    if hasattr(choice, "_actions"):
                        walk(choice)

    walk(build_parser())
    assert not (seen & banned), f"found a bypass flag: {seen & banned}"
