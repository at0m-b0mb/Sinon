"""Brand constants shared by the HTML report, the site and the generated assets.

Kept in one module so the report, the README banner and the documentation site
cannot drift apart. The palette is defined once, as CSS custom properties, and
every surface reads it from here.

The name: Sinon was the Greek who stayed behind at Troy and talked the Trojans
into pulling the horse through their own gates. No walls were breached. The
defenders did the work themselves, because the story they were told was
convincing. That is prompt injection, described three thousand years early, and
it is why the report's cover line is "they opened the gates themselves".
"""

from __future__ import annotations

WORDMARK = "SINON"
TAGLINE = "They opened the gates themselves."
DESCRIPTION = "AI agent pentest kit"
REPO_URL = "https://github.com/at0m-b0mb/Sinon"

# --------------------------------------------------------------------------
# Palette
#
# Night-blue ink, parchment ground, ember accent: a fire seen from outside the
# walls. Severity colours are chosen to stay distinguishable in the two most
# common forms of colour blindness and to survive a greyscale print, since
# pentest reports get printed.
# --------------------------------------------------------------------------

PALETTE = {
    "ink": "#101625",
    "ink-2": "#1c2436",
    "muted": "#5c6679",
    "line": "#dcd7cc",
    "surface": "#f7f4ee",
    "surface-2": "#ffffff",
    "ember": "#c2521f",
    "ember-soft": "#e8794a",
    "patina": "#1f6f6b",
    "critical": "#a32118",
    "high": "#c2521f",
    "medium": "#9a7212",
    "low": "#3f6493",
    "info": "#5c6679",
    "pass": "#1f6f6b",
    "skip": "#8a8577",
}

DARK_PALETTE = {
    "ink": "#eef1f6",
    "ink-2": "#c8cfdb",
    "muted": "#8d97a8",
    "line": "#2b3346",
    "surface": "#0d1220",
    "surface-2": "#141b2c",
    "ember": "#f08a55",
    "ember-soft": "#c2521f",
    "patina": "#4fb3ad",
    "critical": "#f2685c",
    "high": "#f08a55",
    "medium": "#e0b348",
    "low": "#7ea8dd",
    "info": "#8d97a8",
    "pass": "#4fb3ad",
    "skip": "#6f7787",
}


def logo_svg(size: int = 40, color: str = "currentColor", accent: str = "") -> str:
    """The Sinon mark: a horse's head passing through an open gate.

    Two shapes only, so it stays legible at favicon size: the arch of the gate,
    broken at the point the horse passes through it, and the head itself drawn
    in flat planks. The gap in the arch is the whole idea --- nothing forced it
    open.
    """
    accent = accent or color
    return f"""<svg viewBox="0 0 64 64" width="{size}" height="{size}" role="img" \
aria-label="Sinon" xmlns="http://www.w3.org/2000/svg">
  <g fill="none" stroke="{accent}" stroke-width="3.4" stroke-linecap="square">
    <path d="M8 58 V30 A24 24 0 0 1 32 6 A24 24 0 0 1 56 30 V58"/>
  </g>
  <path fill="{color}" d="M25.5 9.5 l4.6 8.2 l3.2 -8.6 l5.9 10.4
      l10.4 9.9 a2.4 2.4 0 0 1 0.5 2.7 l-2.1 4.3 l-7.7 -1.2 l-2.9 -2.7
      l-3.6 5.6 l1.4 12.3 l3.4 4.4 l-19.8 0 l1.2 -10.6 l-5.7 -8.4
      a3 3 0 0 1 -0.2 -3.2 l5.1 -8.6 z"/>
  <g fill="none" stroke="{PALETTE['surface']}" stroke-width="1.6" opacity="0.55">
    <path d="M20.8 27.4 L41.6 34.2"/>
    <path d="M23.4 39.6 L38.9 41.1"/>
  </g>
</svg>"""


def logo_svg_file(color: str = "#101625", accent: str = "#c2521f", background: str = "") -> str:
    """Standalone SVG file contents for ``assets/brand``."""
    body = logo_svg(size=256, color=color, accent=accent)
    body = body.replace('width="256" height="256"', 'width="256" height="256"')
    if background:
        body = body.replace(
            ">\n  <g fill=\"none\"",
            f'>\n  <rect width="64" height="64" rx="12" fill="{background}"/>\n  <g fill="none"',
            1,
        )
    return '<?xml version="1.0" encoding="UTF-8"?>\n' + body + "\n"


def css_variables(dark: bool = False) -> str:
    palette = DARK_PALETTE if dark else PALETTE
    return "\n".join(f"    --{key}: {value};" for key, value in palette.items())
