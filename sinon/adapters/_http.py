"""Minimal HTTP helper shared by the network adapters.

Uses ``urllib`` from the standard library rather than ``requests`` so the whole
kit installs with one dependency (PyYAML) and drops into a locked-down CI image
without an egress-approved wheel list.
"""

from __future__ import annotations

import json
import ssl
import time
import urllib.error
import urllib.request
from typing import Any, Dict, Optional, Tuple

DEFAULT_TIMEOUT = 60.0
USER_AGENT = "Sinon/1.0 (+https://github.com/at0m-b0mb/Sinon)"


class HttpError(Exception):
    def __init__(self, message: str, status: int = 0, body: str = ""):
        super().__init__(message)
        self.status = status
        self.body = body


def identification_headers(run_id: str, probe_id: str) -> Dict[str, str]:
    """Headers that let a defender tell an authorized test from an attack.

    Sent by default on every request. See :mod:`sinon.engagement` for the rules
    around turning them off.
    """
    return {
        "X-Sinon-Run": run_id,
        "X-Sinon-Probe": probe_id,
        "X-Sinon-Purpose": "authorized-security-test",
    }


def post_json(
    url: str,
    payload: Dict[str, Any],
    headers: Optional[Dict[str, str]] = None,
    timeout: float = DEFAULT_TIMEOUT,
    retries: int = 2,
    verify_tls: bool = True,
) -> Tuple[int, Any]:
    """POST JSON, return ``(status, parsed_body)``.

    Retries only on transport errors and 5xx, never on 4xx --- a 401 will not
    fix itself and retrying it just makes noise in the client's logs.
    """
    body = json.dumps(payload).encode("utf-8")
    all_headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "User-Agent": USER_AGENT,
    }
    all_headers.update(headers or {})

    context = None
    if not verify_tls:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

    last_error: Optional[Exception] = None
    for attempt in range(retries + 1):
        request = urllib.request.Request(url, data=body, headers=all_headers, method="POST")
        try:
            with urllib.request.urlopen(request, timeout=timeout, context=context) as response:
                raw = response.read().decode("utf-8", "replace")
                return response.status, _parse(raw)
        except urllib.error.HTTPError as exc:
            raw = exc.read().decode("utf-8", "replace") if exc.fp else ""
            if exc.code < 500 or attempt == retries:
                raise HttpError(f"HTTP {exc.code} from {url}", exc.code, raw) from exc
            last_error = exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            if attempt == retries:
                raise HttpError(f"could not reach {url}: {exc}") from exc
            last_error = exc
        time.sleep(0.5 * (2 ** attempt))

    raise HttpError(f"could not reach {url}: {last_error}")


def _parse(raw: str) -> Any:
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return raw


def dig(data: Any, path: str, default: Any = None) -> Any:
    """Read a dotted path out of nested JSON, e.g. ``choices.0.message.content``."""
    if not path:
        return data
    current = data
    for part in path.split("."):
        if isinstance(current, list):
            try:
                current = current[int(part)]
                continue
            except (ValueError, IndexError):
                return default
        if isinstance(current, dict):
            if part not in current:
                return default
            current = current[part]
            continue
        return default
    return current
