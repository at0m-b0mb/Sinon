"""Shared fixtures.

Every test runs against the shipped corpus and the built-in reference agent, so
the suite needs no network, no API key and no fixtures directory of its own. It
is also why the reference agent is rule-based: a test that asks a language model
whether it was injected is not a test.
"""

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from sinon import corpus as corpus_mod  # noqa: E402
from sinon.adapters.reference import ReferenceAgent  # noqa: E402
from sinon.sink import Sink  # noqa: E402


@pytest.fixture(scope="session")
def probes():
    return corpus_mod.load([corpus_mod.default_corpus_path()])


@pytest.fixture(scope="session")
def probes_by_id(probes):
    return {p.id: p for p in probes}


@pytest.fixture
def sink():
    s = Sink().start()
    yield s
    s.stop()


@pytest.fixture
def naive():
    return ReferenceAgent("naive")


@pytest.fixture
def hardened():
    return ReferenceAgent("hardened")
