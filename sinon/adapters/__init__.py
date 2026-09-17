"""Target adapters and the factory that builds them from configuration."""

from __future__ import annotations

from typing import Any, Dict

from .base import Adapter, AdapterError, ToolRunner, inline_documents
from .cli import CliAdapter
from .http_json import HttpJsonAdapter
from .openai_compat import OpenAICompatAdapter
from .reference import ReferenceAgent

KINDS = ("reference", "openai", "http", "cli")

__all__ = [
    "Adapter",
    "AdapterError",
    "ToolRunner",
    "CliAdapter",
    "HttpJsonAdapter",
    "OpenAICompatAdapter",
    "ReferenceAgent",
    "build",
    "KINDS",
]


def build(config: Dict[str, Any]) -> Adapter:
    """Construct an adapter from a plain dict.

    The dict is assembled by the CLI from flags and, where present, the
    ``target:`` block of the engagement file --- so an operator can keep the
    whole target definition next to its authorization and run with one flag.

    Every construction fault surfaces as :class:`AdapterError`, which is what
    the CLI turns into a usage message. Adapters are free to raise ``ValueError``
    for a bad argument as a library would; translating it here means a typo in
    ``--target`` prints one line rather than a traceback.
    """
    try:
        return _build(config)
    except ValueError as exc:
        raise AdapterError(str(exc)) from exc


def _build(config: Dict[str, Any]) -> Adapter:
    kind = str(config.get("kind", "reference")).lower()

    if kind == "reference":
        return ReferenceAgent(profile=str(config.get("profile", "naive")))

    if kind == "openai":
        return OpenAICompatAdapter(
            base_url=str(config.get("url") or config.get("base_url") or ""),
            model=str(config.get("model", "")),
            api_key=str(config.get("api_key", "")),
            name=str(config.get("name", "")),
            temperature=float(config.get("temperature", 0.0)),
            timeout=float(config.get("timeout", 60.0)),
            extra_headers=config.get("headers") or {},
            identify=bool(config.get("identify", True)),
            verify_tls=bool(config.get("verify_tls", True)),
        )

    if kind == "http":
        return HttpJsonAdapter(
            url=str(config.get("url", "")),
            prompt_field=str(config.get("prompt_field", "message")),
            response_path=str(config.get("response_path", "")),
            system_field=str(config.get("system_field", "")),
            headers=config.get("headers") or {},
            extra_body=config.get("body") or {},
            tool_calls_path=str(config.get("tool_calls_path", "")),
            name=str(config.get("name", "")),
            timeout=float(config.get("timeout", 60.0)),
            identify=bool(config.get("identify", True)),
            verify_tls=bool(config.get("verify_tls", True)),
        )

    if kind == "cli":
        return CliAdapter(
            command=str(config.get("command", "")),
            protocol=str(config.get("protocol", "text")),
            name=str(config.get("name", "")),
            timeout=float(config.get("timeout", 60.0)),
            cwd=str(config.get("cwd", "")),
        )

    raise AdapterError(f"unknown target kind '{kind}'; expected one of: {', '.join(KINDS)}")
