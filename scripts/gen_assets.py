#!/usr/bin/env python3
"""Generate the brand assets from sinon.report.brand.

Assets are generated rather than hand-drawn so the logo in the README, the mark
in every HTML report and the icon on the documentation site cannot drift apart.
Change the palette or the mark in one module and re-run this.

    python3 scripts/gen_assets.py
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from sinon.report import brand  # noqa: E402

OUT = ROOT / "assets" / "brand"


def banner_svg(dark: bool = False) -> str:
    palette = brand.DARK_PALETTE if dark else brand.PALETTE
    ink, muted, ember, surface = palette["ink"], palette["muted"], palette["ember"], palette["surface"]
    line = palette["line"]
    mark = brand.logo_svg(size=104, color=ink, accent=ember)
    # Strip the outer <svg> so the mark can be positioned inside the banner.
    inner = mark.split(">", 1)[1].rsplit("</svg>", 1)[0]
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1200 360" width="1200" height="360"
     role="img" aria-label="Sinon --- AI agent pentest kit">
  <rect width="1200" height="360" fill="{surface}"/>
  <rect x="0" y="356" width="1200" height="4" fill="{ember}"/>
  <g transform="translate(96 108) scale(2.2)">{inner}</g>
  <text x="272" y="168" font-family="Iowan Old Style, Palatino, Georgia, serif"
        font-size="86" font-weight="600" letter-spacing="26" fill="{ink}">SINON</text>
  <text x="278" y="212" font-family="-apple-system, Segoe UI, Helvetica, Arial, sans-serif"
        font-size="23" letter-spacing="5.5" fill="{muted}">AI AGENT PENTEST KIT</text>
  <text x="278" y="264" font-family="Iowan Old Style, Palatino, Georgia, serif"
        font-size="27" font-style="italic" fill="{muted}">&#8220;{brand.TAGLINE}&#8221;</text>
  <g stroke="{line}" stroke-width="2">
    <path d="M278 288 H1104"/>
  </g>
  <text x="278" y="322" font-family="ui-monospace, SFMono-Regular, Menlo, monospace"
        font-size="21" fill="{ember}">prompt injection &#183; tool abuse &#183; over-permissioned actions</text>
</svg>
"""


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    written = []

    files = {
        "logo.svg": brand.logo_svg_file(
            color=brand.PALETTE["ink"], accent=brand.PALETTE["ember"]
        ),
        "logo-dark.svg": brand.logo_svg_file(
            color=brand.DARK_PALETTE["ink"], accent=brand.DARK_PALETTE["ember"]
        ),
        "logo-badge.svg": brand.logo_svg_file(
            color=brand.PALETTE["surface"],
            accent=brand.PALETTE["ember"],
            background=brand.PALETTE["ink"],
        ),
        "banner.svg": banner_svg(),
        "banner-dark.svg": banner_svg(dark=True),
    }
    for name, body in files.items():
        (OUT / name).write_text(body, encoding="utf-8")
        written.append(name)

    print(f"wrote {len(written)} asset(s) to {OUT.relative_to(ROOT)}:")
    for name in written:
        print(f"  {name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
