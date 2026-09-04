"""The loopback exfiltration sink."""

import json
import urllib.request

from sinon.sink import BIND_HOST, MAX_HITS, Sink


def get(url, data=None):
    request = urllib.request.Request(url, data=data, method="POST" if data else "GET")
    with urllib.request.urlopen(request, timeout=5) as response:
        return response.status


def test_binds_to_loopback_only(sink):
    assert sink.url.startswith(f"http://{BIND_HOST}:")
    assert BIND_HOST == "127.0.0.1", "the bind address is not configurable, on purpose"


def test_records_a_get_with_its_query(sink):
    assert get(f"{sink.url}/report?ref=CANARY-1") == 204
    hits = sink.hits()
    assert len(hits) == 1
    assert hits[0].path == "/report" and "CANARY-1" in hits[0].query


def test_records_a_post_body(sink):
    assert get(f"{sink.url}/collect", data=json.dumps({"d": "CANARY-2"}).encode()) == 204
    assert "CANARY-2" in sink.hits()[0].body


def test_hits_containing_filters(sink):
    get(f"{sink.url}/a?ref=CANARY-1")
    get(f"{sink.url}/b?ref=OTHER")
    assert len(sink.hits_containing("CANARY-1")) == 1
    assert sink.hits_containing("") == []


def test_clear_resets_between_probes(sink):
    get(f"{sink.url}/a")
    sink.clear()
    assert sink.hits() == []


def test_serves_no_attacker_controlled_content(sink):
    """It records; it never reflects. A 204 has no body to poison anything with."""
    request = urllib.request.Request(f"{sink.url}/x?html=<script>alert(1)</script>")
    with urllib.request.urlopen(request, timeout=5) as response:
        assert response.status == 204
        assert response.read() == b""


def test_stop_is_idempotent():
    sink = Sink().start()
    sink.stop()
    sink.stop()
    assert not sink.running and sink.url == ""


def test_context_manager_starts_and_stops():
    with Sink() as sink:
        assert sink.running and sink.port > 0
    assert not sink.running


def test_hit_list_is_bounded():
    """A looping agent must not be able to exhaust the tester's memory."""
    assert MAX_HITS > 0 and MAX_HITS <= 5000
