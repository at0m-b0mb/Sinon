"""Report writers: console, HTML, JSON, Markdown, SARIF."""

from . import brand, console, html, json_report, markdown, sarif

FORMATS = {
    "html": html,
    "json": json_report,
    "md": markdown,
    "markdown": markdown,
    "sarif": sarif,
}

EXTENSIONS = {
    "html": ".html",
    "json": ".json",
    "md": ".md",
    "markdown": ".md",
    "sarif": ".sarif",
}

__all__ = ["brand", "console", "html", "json_report", "markdown", "sarif", "FORMATS", "EXTENSIONS"]
