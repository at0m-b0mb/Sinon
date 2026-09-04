"""Adapter interface --- how Sinon talks to a target.

An adapter has one job: take an :class:`~sinon.model.AgentRequest`, get the
target to act on it, and report back what happened, including every tool call it
made. Everything else --- canaries, oracles, scoring --- is target-agnostic.

The capability flags are load-bearing. If an adapter cannot observe tool calls,
it must say ``supports_tools = False`` so the runner skips tool probes and the
coverage penalty applies. Returning an empty tool-call list from a target you
cannot actually see would turn every tool-abuse probe into a silent pass, which
is the single most dangerous thing a kit like this could do.
"""

from __future__ import annotations

import abc
from typing import Callable, Dict, Optional

from ..model import AgentRequest, AgentResponse, ToolCall

ToolRunner = Callable[[str, Dict], ToolCall]


class AdapterError(Exception):
    """Raised for configuration problems, not for target misbehaviour."""


class Adapter(abc.ABC):
    """Base class for every target type."""

    kind: str = "base"

    #: Can this adapter offer tools and observe the resulting calls?
    supports_tools: bool = False
    #: Can a system prompt be set on the target?
    supports_system_prompt: bool = True
    #: Can the target hold context across turns within one probe?
    supports_multi_turn: bool = False

    def __init__(self, name: str = "", url: str = "") -> None:
        self.name = name or self.kind
        self.url = url

    @abc.abstractmethod
    def send(
        self, request: AgentRequest, tool_runner: Optional[ToolRunner] = None
    ) -> AgentResponse:
        """Run one probe against the target and return what it did."""

    # -- lifecycle -------------------------------------------------------

    def open(self) -> None:
        """Optional set-up (start a process, open a session)."""

    def close(self) -> None:
        """Optional tear-down. Always called, even after errors."""

    # -- description -----------------------------------------------------

    def describe(self) -> Dict[str, str]:
        return {
            "kind": self.kind,
            "name": self.name,
            "url": self.url,
            "supports_tools": "yes" if self.supports_tools else "no",
        }

    def __enter__(self) -> "Adapter":
        self.open()
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def __str__(self) -> str:  # pragma: no cover - trivial
        return f"{self.kind}:{self.name}"


def inline_documents(request: AgentRequest) -> str:
    """Render a request's documents into the prompt for tool-less targets.

    The delimiters matter more than they look. Real agents receive retrieved
    content wrapped in something like this, and a defence that only works when
    the content is unwrapped is not a defence. The wrapper here is neutral: it
    labels the content as retrieved and untrusted without also telling the model
    what to do about it, so the probe measures the target's own handling.
    """
    if not request.documents:
        return request.prompt
    blocks = []
    for doc in request.documents:
        blocks.append(
            f"<retrieved_document name=\"{doc.name}\" source=\"{doc.url or 'local'}\" "
            f"media-type=\"{doc.media_type}\">\n{doc.content}\n</retrieved_document>"
        )
    return request.prompt + "\n\n" + "\n\n".join(blocks)
