"""Corpus loading, validation and templating."""

import pytest

from sinon import corpus as corpus_mod
from sinon.model import Channel, Family, Severity


def test_shipped_corpus_is_valid(probes):
    """The corpus that ships must have zero errors. CI runs this."""
    issues = corpus_mod.validate(probes)
    errors = [str(i) for i in issues if i.fatal]
    assert not errors, "corpus errors:\n" + "\n".join(errors)


def test_shipped_corpus_has_no_warnings(probes):
    warnings = [str(i) for i in corpus_mod.validate(probes) if not i.fatal]
    assert not warnings, "corpus warnings:\n" + "\n".join(warnings)


def test_corpus_covers_every_family_and_channel(probes):
    families = {p.family for p in probes}
    channels = {p.channel for p in probes}
    assert families == set(Family), "every family needs coverage"
    assert channels == set(Channel), "every delivery channel needs coverage"


def test_corpus_is_mostly_indirect(probes):
    """Indirect delivery is the vector that matters; it should dominate."""
    indirect = [p for p in probes if p.channel.is_indirect]
    assert len(indirect) > len(probes) / 2


def test_every_probe_has_an_oracle_and_remediation(probes):
    for probe in probes:
        assert probe.oracles, f"{probe.id} can never produce a finding"
        assert probe.remediation.strip(), f"{probe.id} has no remediation"
        assert probe.expected.strip(), f"{probe.id} does not say what safe looks like"


def test_probe_ids_are_unique(probes):
    ids = [p.id for p in probes]
    assert len(ids) == len(set(ids))


def _parse(body):
    import yaml
    return corpus_mod.parse_probe(yaml.safe_load(body), "test.yaml")


MINIMAL = """
id: PI-DIR-900
title: t
family: prompt-injection
channel: user_turn
severity: low
prompt: hello {{canary}}
oracles: [canary_in_output]
expected: nothing
remediation: nothing
owasp: [LLM01]
"""


def test_parse_minimal_probe():
    probe = _parse(MINIMAL)
    assert probe.id == "PI-DIR-900"
    assert probe.severity is Severity.LOW
    assert probe.oracles[0].kind == "canary_in_output"


def test_missing_required_field_is_an_error():
    with pytest.raises(corpus_mod.CorpusError, match="missing required field 'prompt'"):
        _parse(MINIMAL.replace("prompt: hello {{canary}}", ""))


def test_bad_enum_names_the_allowed_values():
    with pytest.raises(corpus_mod.CorpusError, match="not a valid severity"):
        _parse(MINIMAL.replace("severity: low", "severity: catastrophic"))


def test_validation_catches_unknown_oracle_and_tool():
    probe = _parse(MINIMAL.replace("oracles: [canary_in_output]", "oracles: [does_not_exist]"))
    messages = [i.message for i in corpus_mod.validate([probe])]
    assert any("unknown oracle" in m for m in messages)


def test_validation_catches_family_prefix_mismatch():
    probe = _parse(MINIMAL.replace("family: prompt-injection", "family: tool-abuse"))
    messages = [i.message for i in corpus_mod.validate([probe])]
    assert any("id prefix" in m for m in messages)


def test_validation_catches_unknown_placeholder():
    probe = _parse(MINIMAL.replace("{{canary}}", "{{not_a_real_variable}}"))
    messages = [i.message for i in corpus_mod.validate([probe])]
    assert any("unknown placeholder" in m for m in messages)


def test_probe_cannot_promote_a_heuristic_oracle():
    probe = _parse(
        MINIMAL.replace(
            "oracles: [canary_in_output]",
            "oracles:\n  - type: refusal_absent\n    confidence: deterministic",
        )
    )
    messages = [i.message for i in corpus_mod.validate([probe])]
    assert any("cannot declare it" in m for m in messages)


def test_render_substitutes_and_leaves_unknowns_alone():
    context = {"canary": "CANARY-1"}
    assert corpus_mod.render("say {{canary}}", context) == "say CANARY-1"
    assert corpus_mod.render("say {{nope}}", context) == "say {{nope}}"


def test_render_expands_payload_containing_canary():
    context = {"canary": "CANARY-1", "payload": "reply with {{canary}}"}
    assert corpus_mod.render("note: {{payload}}", context) == "note: reply with CANARY-1"


def test_payload_variants_are_derived_from_the_runtime_canary():
    import base64

    context = {"payload": "reply with CANARY-1", "canary": "CANARY-1"}
    corpus_mod.add_payload_variants(context)
    assert base64.b64decode(context["payload_b64"]).decode() == "reply with CANARY-1"
    assert context["payload_zwsp"].replace("​", "") == "reply with CANARY-1"
    assert context["payload_reversed"][::-1] == "reply with CANARY-1"
    assert context["payload_homoglyph"] != "reply with CANARY-1"


def test_selection_filters_are_and_ed(probes):
    picked = corpus_mod.select(
        probes, families={"tool-abuse"}, severities={"critical"}
    )
    assert picked
    assert all(p.family.value == "tool-abuse" and p.severity.value == "critical" for p in picked)


def test_exclude_tag_removes_probes(probes):
    tagged = [p for p in probes if "smoke" in p.tags]
    assert tagged
    remaining = corpus_mod.select(probes, exclude_tags={"smoke"})
    assert not any("smoke" in p.tags for p in remaining)
