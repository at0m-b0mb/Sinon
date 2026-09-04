"""Terminal output.

Colour when the terminal supports it, plain text when it does not, and never
anything that turns into mojibake in a CI log --- no box-drawing, no emoji, no
characters outside ASCII. Redirect the output to a file and it stays readable.
"""

from __future__ import annotations

import os
import sys
from typing import List, Optional

from ..model import Confidence, ProbeResult, RunResult, Verdict, excerpt
from ..scoring import Score
from . import brand

_ANSI = {
    "reset": "\033[0m",
    "bold": "\033[1m",
    "dim": "\033[2m",
    "red": "\033[31m",
    "green": "\033[32m",
    "yellow": "\033[33m",
    "blue": "\033[34m",
    "magenta": "\033[35m",
    "cyan": "\033[36m",
    "grey": "\033[90m",
    "orange": "\033[38;5;173m",
}

_VERDICT_COLOR = {
    Verdict.FAIL: "red",
    Verdict.PASS: "green",
    Verdict.SKIP: "grey",
    Verdict.ERROR: "yellow",
}

_SEVERITY_COLOR = {
    "critical": "red",
    "high": "orange",
    "medium": "yellow",
    "low": "blue",
    "info": "grey",
}

_GRADE_COLOR = {"A": "green", "B": "cyan", "C": "yellow", "D": "orange", "F": "red"}


def supports_color(stream=None) -> bool:
    stream = stream or sys.stdout
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    return bool(getattr(stream, "isatty", lambda: False)())


class Console:
    """Thin writer that knows whether it may use colour."""

    def __init__(self, stream=None, color: Optional[bool] = None):
        self.stream = stream or sys.stdout
        self.color = supports_color(self.stream) if color is None else color

    def paint(self, text: str, *styles: str) -> str:
        if not self.color or not styles:
            return text
        prefix = "".join(_ANSI.get(s, "") for s in styles)
        return f"{prefix}{text}{_ANSI['reset']}"

    def line(self, text: str = "") -> None:
        self.stream.write(text + "\n")

    def flush(self) -> None:
        try:
            self.stream.flush()
        except (ValueError, OSError):
            pass

    # -- run banner ------------------------------------------------------

    def banner(self, target: str, probe_count: int, engagement, sink_url: str = "") -> None:
        """The pre-flight banner. Always printed, never suppressible.

        A tester should never be able to forget which target they pointed this
        at, and a client reading over their shoulder should be able to see the
        authorization it is running under.
        """
        rule = "=" * 66
        self.line()
        self.line(self.paint(rule, "grey"))
        self.line(
            self.paint(f"  {brand.WORDMARK}", "bold")
            + self.paint(f"  {brand.DESCRIPTION}", "grey")
        )
        self.line(self.paint(f'  "{brand.TAGLINE}"', "dim"))
        self.line(self.paint(rule, "grey"))
        self.line(f"  TARGET      {target}")
        self.line(f"  PROBES      {probe_count}")
        if sink_url:
            self.line(f"  SINK        {sink_url}  (loopback only)")
        if engagement is not None:
            for entry in engagement.banner_lines():
                self.line(f"  {entry}")
        self.line(self.paint(rule, "grey"))
        self.line()
        self.flush()

    # -- per-probe progress ----------------------------------------------

    def probe_line(self, result: ProbeResult, index: int, total: int) -> None:
        verdict = result.verdict
        mark = self.paint(f"{verdict.label:<5}", _VERDICT_COLOR.get(verdict, "grey"), "bold")
        counter = self.paint(f"[{index:>3}/{total}]", "grey")
        severity = ""
        if verdict is Verdict.FAIL:
            severity = self.paint(
                f" {result.probe.severity.value}",
                _SEVERITY_COLOR.get(result.probe.severity.value, "grey"),
            )
            if result.confidence is Confidence.HEURISTIC:
                severity += self.paint(" (heuristic)", "dim")

        detail = ""
        if verdict is Verdict.FAIL and result.evidence:
            detail = self.paint("  " + excerpt(result.evidence, 96), "grey")
        elif verdict is Verdict.SKIP and result.skip_reason:
            detail = self.paint("  " + excerpt(result.skip_reason, 96), "grey")
        elif verdict is Verdict.ERROR and result.error:
            detail = self.paint("  " + excerpt(result.error, 96), "grey")

        self.line(
            f"{counter} {mark} {result.probe.id:<14} {excerpt(result.probe.title, 52):<52}{severity}"
        )
        if detail:
            self.line(f"        {detail.strip()}")
        self.flush()

    # -- summary ---------------------------------------------------------

    def summary(self, run: RunResult, score: Score) -> None:
        self.line()
        self.line(self.paint("-" * 66, "grey"))
        grade = self.paint(f" {score.grade} ", _GRADE_COLOR.get(score.grade, "grey"), "bold")
        self.line(f"  GRADE {grade}  {score.score:.0f}/100    {score.headline}")

        counts = [
            ("findings", score.failed, "red" if score.failed else "green"),
            ("passed", score.passed, "green"),
            ("skipped", score.skipped, "grey"),
        ]
        if score.errored:
            counts.append(("errors", score.errored, "yellow"))
        parts = "   ".join(self.paint(f"{label} {value}", color) for label, value, color in counts)
        self.line(f"        {parts}")

        if score.severity_counts:
            severities = "   ".join(
                self.paint(f"{name} {count}", _SEVERITY_COLOR.get(name, "grey"))
                for name, count in sorted(
                    score.severity_counts.items(),
                    key=lambda kv: ["critical", "high", "medium", "low", "info"].index(kv[0]),
                )
            )
            self.line(f"        {severities}")

        for ceiling in score.ceilings:
            self.line(self.paint(f"        capped at {ceiling.grade}: {ceiling.reason}", "dim"))

        self.line(self.paint("-" * 66, "grey"))
        for note in score.notes[:1] + list(run.notes):
            self.line(self.paint(f"  note: {note}", "grey"))
        self.line()
        self.flush()

    # -- tables ----------------------------------------------------------

    def table(self, headers: List[str], rows: List[List[str]], widths: Optional[List[int]] = None) -> None:
        if not rows:
            return
        widths = widths or [
            max(len(str(headers[i])), max(len(str(r[i])) for r in rows)) for i in range(len(headers))
        ]
        header = "  ".join(str(h).ljust(w) for h, w in zip(headers, widths))
        self.line(self.paint(header, "bold"))
        self.line(self.paint("  ".join("-" * w for w in widths), "grey"))
        for row in rows:
            self.line("  ".join(str(c)[:w].ljust(w) for c, w in zip(row, widths)))
        self.flush()
