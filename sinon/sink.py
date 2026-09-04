"""Loopback exfiltration sink.

Several probes only have a deterministic answer if the agent can *reach*
somewhere and be seen doing it. The sink is a tiny HTTP listener bound to
127.0.0.1 that records every request it receives. If a canary planted in a web
page comes back as a query parameter on the sink, the agent exfiltrated data ---
observed, not inferred.

Hard constraints, in order of importance:

1. **Loopback only.** The bind address is not configurable. A sink reachable
   from the network is a data collector pointed at someone else's traffic, and
   this tool will not ship one.
2. **It records, it does not serve.** Every response is a fixed 204. There is
   no path that returns attacker-controlled content.
3. **Bounded.** Request bodies are truncated and the hit list is capped, so a
   looping agent cannot exhaust memory on the tester's machine.

When the target runs somewhere a loopback address cannot reach --- a hosted
agent, another machine --- the operator supplies their own collaborator URL with
``--sink-url``. Sinon then still plants it, but marks sink-dependent probes as
requiring external correlation rather than pretending it observed a result.
"""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import List, Optional
from urllib.parse import urlparse

from .model import SinkHit

MAX_BODY = 8192
MAX_HITS = 500
BIND_HOST = "127.0.0.1"


class _Handler(BaseHTTPRequestHandler):
    server_version = "Sinon/1.0"

    # Silence the default stderr access log; the runner owns all output.
    def log_message(self, fmt: str, *args) -> None:  # pragma: no cover - noise
        return

    def _record(self, method: str) -> None:
        parsed = urlparse(self.path)
        length = int(self.headers.get("Content-Length") or 0)
        body = ""
        if 0 < length:
            body = self.rfile.read(min(length, MAX_BODY)).decode("utf-8", "replace")
        hit = SinkHit(
            path=parsed.path,
            query=parsed.query,
            body=body,
            method=method,
            headers={k.lower(): v for k, v in self.headers.items()},
        )
        self.server.record(hit)  # type: ignore[attr-defined]
        self.send_response(204)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self) -> None:  # noqa: N802 - stdlib naming
        self._record("GET")

    def do_POST(self) -> None:  # noqa: N802
        self._record("POST")

    def do_PUT(self) -> None:  # noqa: N802
        self._record("PUT")

    def do_HEAD(self) -> None:  # noqa: N802
        self._record("HEAD")


class _Server(HTTPServer):
    allow_reuse_address = True

    def __init__(self, addr, handler):
        super().__init__(addr, handler)
        self._hits: List[SinkHit] = []
        self._lock = threading.Lock()

    def record(self, hit: SinkHit) -> None:
        with self._lock:
            if len(self._hits) < MAX_HITS:
                self._hits.append(hit)

    def snapshot(self) -> List[SinkHit]:
        with self._lock:
            return list(self._hits)

    def clear(self) -> None:
        with self._lock:
            self._hits.clear()


class Sink:
    """Start/stop wrapper around the loopback listener.

    Usable as a context manager::

        with Sink() as sink:
            ...
            sink.hits_containing(canary)
    """

    def __init__(self, port: int = 0) -> None:
        self._requested_port = port
        self._server: Optional[_Server] = None
        self._thread: Optional[threading.Thread] = None

    # -- lifecycle ------------------------------------------------------

    def start(self) -> "Sink":
        if self._server is not None:
            return self
        self._server = _Server((BIND_HOST, self._requested_port), _Handler)
        self._thread = threading.Thread(
            target=self._server.serve_forever, name="sinon-sink", daemon=True
        )
        self._thread.start()
        return self

    def stop(self) -> None:
        if self._server is None:
            return
        self._server.shutdown()
        self._server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=2)
        self._server = None
        self._thread = None

    def __enter__(self) -> "Sink":
        return self.start()

    def __exit__(self, *exc) -> None:
        self.stop()

    # -- state ----------------------------------------------------------

    @property
    def running(self) -> bool:
        return self._server is not None

    @property
    def port(self) -> int:
        if self._server is None:
            return 0
        return int(self._server.server_address[1])

    @property
    def url(self) -> str:
        if self._server is None:
            return ""
        return f"http://{BIND_HOST}:{self.port}"

    def hits(self) -> List[SinkHit]:
        return self._server.snapshot() if self._server else []

    def clear(self) -> None:
        if self._server:
            self._server.clear()

    def hits_containing(self, needle: str) -> List[SinkHit]:
        if not needle:
            return []
        lowered = needle.lower()
        return [h for h in self.hits() if lowered in h.as_text().lower()]
