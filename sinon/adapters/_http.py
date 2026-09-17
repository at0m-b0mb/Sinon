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

# A hostile or simply broken target must not be able to exhaust the tester's
# memory. Anything past this is discarded and the truncation is reported, which
# is still plenty of evidence: no oracle needs eight megabytes of reply.
MAX_RESPONSE_BYTES = 8 * 1024 * 1024


class HttpError(Exception):
    def __init__(self, message: str, status: int = 0, body: str = ""):
        super().__init__(message)
        self.status = status
        self.body = body


class _NoRedirects(urllib.request.HTTPRedirectHandler):
    """Refuse to follow redirects.

    This is a security control, not a convenience setting. Sinon's authorization
    gate checks the host of the URL the operator named; if a target answered 302
    and urllib chased it, probe traffic --- and the ``Authorization`` header that
    goes with it --- would reach a host nobody authorized and nobody would see it
    happen. urllib forwards request headers across hosts on redirect, so this is
    a credential-disclosure path as well as a scope escape.

    Returning ``None`` stops the chase; the 3xx then surfaces as an HTTPError and
    :func:`post_json` turns it into a message that names the destination, so the
    operator can decide whether that host is in scope and point at it directly.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _build_opener(verify_tls: bool) -> urllib.request.OpenerDirector:
    handlers = [_NoRedirects()]
    if not verify_tls:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        handlers.append(urllib.request.HTTPSHandler(context=context))
    return urllib.request.build_opener(*handlers)


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

    opener = _build_opener(verify_tls)

    last_error: Optional[Exception] = None
    for attempt in range(retries + 1):
        request = urllib.request.Request(url, data=body, headers=all_headers, method="POST")
        try:
            with opener.open(request, timeout=timeout) as response:
                raw = _read_capped(response)
                return response.status, _parse(raw)
        except urllib.error.HTTPError as exc:
            if 300 <= exc.code < 400:
                destination = exc.headers.get("Location", "an undisclosed location") if exc.headers else "?"
                raise HttpError(
                    f"HTTP {exc.code} from {url}: the target redirected to {destination}. "
                    "Sinon does not follow redirects, because the authorization gate "
                    "checked the host you named and request headers would travel to the "
                    "new one. Confirm that host is in scope and point --target-url at it.",
                    exc.code,
                ) from exc
            raw = _read_capped(exc) if exc.fp else ""
            if exc.code < 500 or attempt == retries:
                raise HttpError(f"HTTP {exc.code} from {url}", exc.code, raw) from exc
            last_error = exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            if attempt == retries:
                raise HttpError(f"could not reach {url}: {exc}") from exc
            last_error = exc
        time.sleep(0.5 * (2 ** attempt))

    raise HttpError(f"could not reach {url}: {last_error}")


def _read_capped(response: Any) -> str:
    """Read a response body, stopping at :data:`MAX_RESPONSE_BYTES`."""
    raw = response.read(MAX_RESPONSE_BYTES + 1)
    if len(raw) > MAX_RESPONSE_BYTES:
        raw = raw[:MAX_RESPONSE_BYTES]
        return raw.decode("utf-8", "replace") + (
            f"\n[sinon: response truncated at {MAX_RESPONSE_BYTES} bytes]"
        )
    return raw.decode("utf-8", "replace")


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
