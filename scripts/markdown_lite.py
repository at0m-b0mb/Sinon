"""A small Markdown renderer, so the site has no build dependencies.

Not a general Markdown implementation and not trying to be. It handles the
subset this project's documentation actually uses --- ATX headings, fenced code,
tables, lists, blockquotes, horizontal rules, and inline code/emphasis/links ---
and it escapes everything else.

The escaping matters more here than the features. These documents quote prompt
injection payloads; a renderer that let one through as markup would put a
working payload on the project's own website.
"""

from __future__ import annotations

import html
import re
from typing import List

_INLINE_CODE = re.compile(r"`([^`]+)`")
_BOLD = re.compile(r"\*\*([^*]+)\*\*")
_ITALIC = re.compile(r"(?<![*\w])\*([^*\n]+)\*(?![*\w])")
_LINK = re.compile(r"\[([^\]]+)\]\(([^)\s]+)\)")
_AUTOLINK = re.compile(r"(?<![\"'=(])\bhttps?://[^\s<>\")\]]+")


def _inline(text: str) -> str:
    """Escape, then re-introduce only the inline markup we allow."""
    out = html.escape(text, quote=False)

    # Code spans first, and their contents are never re-processed.
    placeholders: List[str] = []

    def stash_code(match):
        placeholders.append(f"<code>{match.group(1)}</code>")
        return f"\x00{len(placeholders) - 1}\x00"

    out = _INLINE_CODE.sub(stash_code, out)

    def link(match):
        label, href = match.group(1), match.group(2)
        if not re.match(r"^(https?:|mailto:|[\w./#-]+$)", href):
            return html.escape(match.group(0), quote=False)
        href = href.replace("&amp;", "&")
        if href.endswith(".md"):
            href = href[:-3] + ".html"
        return f'<a href="{html.escape(href, quote=True)}">{label}</a>'

    out = _LINK.sub(link, out)
    out = _BOLD.sub(r"<strong>\1</strong>", out)
    out = _ITALIC.sub(r"<em>\1</em>", out)
    out = _AUTOLINK.sub(lambda m: f'<a href="{m.group(0)}">{m.group(0)}</a>', out)
    out = out.replace(" --- ", " &mdash; ").replace("---", "&mdash;")

    for index, code in enumerate(placeholders):
        out = out.replace(f"\x00{index}\x00", code)
    return out


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", re.sub(r"[`*]", "", text).lower()).strip("-")


def _table(rows: List[str]) -> str:
    def cells(line: str) -> List[str]:
        return [c.strip() for c in line.strip().strip("|").split("|")]

    header = cells(rows[0])
    body = [cells(r) for r in rows[2:]]
    head_html = "".join(f"<th>{_inline(c)}</th>" for c in header)
    body_html = "".join(
        "<tr>" + "".join(f"<td>{_inline(c)}</td>" for c in row) + "</tr>" for row in body
    )
    return (
        '<div class="tablewrap"><table><thead><tr>'
        + head_html
        + "</tr></thead><tbody>"
        + body_html
        + "</tbody></table></div>"
    )


def render(source: str) -> str:
    lines = source.replace("\r\n", "\n").split("\n")
    out: List[str] = []
    index = 0
    paragraph: List[str] = []
    list_stack: List[str] = []

    def flush_paragraph():
        if paragraph:
            out.append(f"<p>{_inline(' '.join(paragraph))}</p>")
            paragraph.clear()

    def close_lists():
        while list_stack:
            out.append(f"</{list_stack.pop()}>")

    while index < len(lines):
        line = lines[index]
        stripped = line.strip()

        if stripped.startswith("```"):
            flush_paragraph()
            close_lists()
            language = stripped[3:].strip()
            index += 1
            block: List[str] = []
            while index < len(lines) and not lines[index].strip().startswith("```"):
                block.append(lines[index])
                index += 1
            index += 1
            code = html.escape("\n".join(block))
            cls = f' class="lang-{html.escape(language, quote=True)}"' if language else ""
            out.append(f"<pre{cls}><code>{code}</code></pre>")
            continue

        if stripped.startswith("<!--"):
            index += 1
            continue

        if not stripped:
            flush_paragraph()
            close_lists()
            index += 1
            continue

        if re.match(r"^(-{3,}|\*{3,}|_{3,})$", stripped):
            flush_paragraph()
            close_lists()
            out.append("<hr>")
            index += 1
            continue

        heading = re.match(r"^(#{1,6})\s+(.*)$", stripped)
        if heading:
            flush_paragraph()
            close_lists()
            level = len(heading.group(1))
            text = heading.group(2)
            anchor = _slug(text)
            out.append(f'<h{level} id="{anchor}">{_inline(text)}</h{level}>')
            index += 1
            continue

        if stripped.startswith("|") and index + 1 < len(lines) and re.match(
            r"^\|[\s:|-]+\|$", lines[index + 1].strip()
        ):
            flush_paragraph()
            close_lists()
            block = []
            while index < len(lines) and lines[index].strip().startswith("|"):
                block.append(lines[index])
                index += 1
            out.append(_table(block))
            continue

        if stripped.startswith("> "):
            flush_paragraph()
            close_lists()
            quote = []
            while index < len(lines) and lines[index].strip().startswith(">"):
                quote.append(lines[index].strip().lstrip(">").strip())
                index += 1
            out.append(f"<blockquote><p>{_inline(' '.join(quote))}</p></blockquote>")
            continue

        bullet = re.match(r"^(\s*)[-*+]\s+(.*)$", line)
        ordered = re.match(r"^(\s*)\d+\.\s+(.*)$", line)
        if bullet or ordered:
            flush_paragraph()
            tag = "ul" if bullet else "ol"
            text = (bullet or ordered).group(2)
            if not list_stack:
                list_stack.append(tag)
                out.append(f"<{tag}>")
            elif list_stack[-1] != tag:
                out.append(f"</{list_stack.pop()}>")
                list_stack.append(tag)
                out.append(f"<{tag}>")
            out.append(f"<li>{_inline(text)}</li>")
            index += 1
            continue

        close_lists()
        paragraph.append(stripped)
        index += 1

    flush_paragraph()
    close_lists()
    return "\n".join(out)


def first_heading(source: str) -> str:
    for line in source.split("\n"):
        match = re.match(r"^#\s+(.*)$", line.strip())
        if match:
            return match.group(1)
    return "Sinon"
