"""Primitives for infra diagrams in the AWS-account style: tiles, square edges, boundaries.

Import from a per-repo script, draw with a function draw(t), then write_both(draw, outdir).
"""

import os
from html import escape
from itertools import pairwise

THEMES = {
    "dark": dict(
        bg="#0b0e18",
        panel="#121827",
        lane="#10162a",
        border="#2c3550",
        text="#e6ecf6",
        muted="#93a0b8",
        dim="#66728a",
        arrow="#6b7894",
        acct="#f5b544",
        region="#3b82f6",
    ),
    "light": dict(
        bg="#f7f8fb",
        panel="#ffffff",
        lane="#eef1f7",
        border="#d6dbe6",
        text="#111524",
        muted="#4f5a70",
        dim="#7a8499",
        arrow="#8a94a8",
        acct="#b7791f",
        region="#2563eb",
    ),
}
# Fixed category colors, AWS-icon style.
CAT = dict(
    compute="#ED7100",
    integration="#E7157B",
    database="#C925D1",
    ml="#01A88D",
    security="#DD344C",
    saas="#632CA6",
    ext="#57606a",
)
SANS = "ui-sans-serif, -apple-system, 'Segoe UI', Helvetica, Arial, sans-serif"
MONO = "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace"
S = 52  # tile size


def text(x, y, s, t, size=13, fill="text", weight=400, family=SANS, anchor="middle"):
    color = t.get(fill, fill)
    return (
        f'<text x="{x}" y="{y}" font-family="{family}" font-size="{size}" font-weight="{weight}" '
        f'fill="{color}" text-anchor="{anchor}">{escape(s)}</text>'
    )


def glyph(kind, cx, cy):
    w = 'stroke="#fff" stroke-width="2.2" fill="none" stroke-linecap="round" stroke-linejoin="round"'
    if kind == "lambda":
        return f'<path d="M{cx - 9},{cy + 12} L{cx - 1},{cy - 2} M{cx - 8},{cy - 13} L{cx - 3},{cy - 13} L{cx + 7},{cy + 12} L{cx + 11},{cy + 12}" {w}/>'
    if kind == "sqs":
        return "".join(
            f'<rect x="{cx - 13}" y="{cy - 11 + i * 8}" width="26" height="5" rx="2" fill="#fff" opacity="{1 - i * 0.25}"/>'
            for i in range(3)
        )
    if kind == "eventbridge":
        pts = [(cx - 12, cy - 10), (cx + 12, cy - 10), (cx - 12, cy + 10), (cx + 12, cy + 10)]
        return (
            "".join(
                f'<path d="M{cx},{cy} L{x},{y}" {w}/><circle cx="{x}" cy="{y}" r="3.2" fill="#fff"/>'
                for x, y in pts
            )
            + f'<circle cx="{cx}" cy="{cy}" r="5" fill="#fff"/>'
        )
    if kind == "cloudwatch":
        return f'<circle cx="{cx}" cy="{cy}" r="13" {w}/><path d="M{cx - 9},{cy + 1} L{cx - 4},{cy + 1} L{cx - 1},{cy - 6} L{cx + 3},{cy + 6} L{cx + 5},{cy + 1} L{cx + 9},{cy + 1}" {w}/>'
    if kind == "dynamodb":
        return (
            f'<ellipse cx="{cx}" cy="{cy - 9}" rx="12" ry="4.5" {w}/><path d="M{cx - 12},{cy - 9} L{cx - 12},{cy + 9} '
            f'A12,4.5 0 0 0 {cx + 12},{cy + 9} L{cx + 12},{cy - 9} M{cx - 12},{cy} A12,4.5 0 0 0 {cx + 12},{cy}" {w}/>'
        )
    if kind == "bedrock":
        hexp = " ".join(
            f"{cx + 13 * c},{cy + 13 * s}"
            for c, s in [(0, -1), (0.87, -0.5), (0.87, 0.5), (0, 1), (-0.87, 0.5), (-0.87, -0.5)]
        )
        return f'<polygon points="{hexp}" {w}/><circle cx="{cx}" cy="{cy}" r="4" fill="#fff"/>'
    if kind == "iam":
        return f'<path d="M{cx},{cy - 13} L{cx + 11},{cy - 8} L{cx + 11},{cy + 1} C{cx + 11},{cy + 8} {cx + 5},{cy + 12} {cx},{cy + 14} C{cx - 5},{cy + 12} {cx - 11},{cy + 8} {cx - 11},{cy + 1} L{cx - 11},{cy - 8} Z" {w}/><path d="M{cx - 4},{cy} L{cx - 1},{cy + 4} L{cx + 5},{cy - 4}" {w}/>'
    if kind == "saas":
        return f'<path d="M{cx - 10},{cy + 8} C{cx - 17},{cy + 8} {cx - 17},{cy - 2} {cx - 10},{cy - 2} C{cx - 9},{cy - 10} {cx + 3},{cy - 12} {cx + 6},{cy - 4} C{cx + 15},{cy - 5} {cx + 16},{cy + 8} {cx + 9},{cy + 8} Z" {w}/>'
    if kind == "code":
        return f'<path d="M{cx - 6},{cy - 9} L{cx - 14},{cy} L{cx - 6},{cy + 9} M{cx + 6},{cy - 9} L{cx + 14},{cy} L{cx + 6},{cy + 9} M{cx + 3},{cy - 12} L{cx - 3},{cy + 12}" {w}/>'
    if kind == "api":
        return "".join(
            f'<rect x="{cx - 13}" y="{cy - 11 + i * 12}" width="26" height="9" rx="2" {w}/><circle cx="{cx - 7}" cy="{cy - 6.5 + i * 12}" r="1.6" fill="#fff"/>'
            for i in range(2)
        )
    if kind == "browser":
        return f'<rect x="{cx - 14}" y="{cy - 11}" width="28" height="22" rx="3" {w}/><path d="M{cx - 14},{cy - 4} L{cx + 14},{cy - 4}" {w}/>'
    if kind == "user":
        return f'<circle cx="{cx}" cy="{cy - 6}" r="6" {w}/><path d="M{cx - 12},{cy + 13} C{cx - 12},{cy + 3} {cx + 12},{cy + 3} {cx + 12},{cy + 13}" {w}/>'
    if kind == "grid":
        return "".join(
            f'<rect x="{cx - 12 + dx}" y="{cy - 12 + dy}" width="10" height="10" rx="2" fill="#fff" opacity="{o}"/>'
            for dx, dy, o in [(0, 0, 1), (14, 0, 0.7), (0, 14, 0.7), (14, 14, 1)]
        )
    return ""


def tile(cx, cy, kind, cat, name, sub, t, size=S):
    x, y = cx - size / 2, cy - size / 2
    out = [
        f'<rect x="{x}" y="{y}" width="{size}" height="{size}" rx="10" fill="{CAT[cat]}"/>',
        glyph(kind, cx, cy),
        text(cx, cy + size / 2 + 19, name, t, size=12.5, weight=650),
    ]
    if sub:
        out.append(text(cx, cy + size / 2 + 35, sub, t, size=10.5, fill="dim", family=MONO))
    return "".join(out)


def edge(pts, t, label=None, lx=None, ly=None, dashed=False, anchor="middle"):
    for (x1, y1), (x2, y2) in pairwise(pts):
        assert x1 == x2 or y1 == y2, (
            f"edge segment {(x1, y1)} to {(x2, y2)} is not horizontal or vertical"
        )
    d = "M" + " L".join(f"{x},{y}" for x, y in pts)
    dash = ' stroke-dasharray="5 4"' if dashed else ""
    out = f'<path d="{d}" stroke="{t["arrow"]}" stroke-width="1.6" fill="none" marker-end="url(#ah)"{dash}/>'
    if label:
        out += text(lx, ly, label, t, size=10.5, fill="muted", family=MONO, anchor=anchor)
    return out


def head(W, H, t, title, subtitle):
    return [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}" role="img" aria-label="{escape(title)}">',
        f'<defs><marker id="ah" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">'
        f'<path d="M0,0 L10,5 L0,10 z" fill="{t["arrow"]}"/></marker></defs>',
        f'<rect width="{W}" height="{H}" rx="18" fill="{t["bg"]}"/>',
        text(32, 46, title, t, size=21, weight=700, anchor="start"),
        text(32, 70, subtitle, t, size=13, fill="muted", anchor="start"),
    ]


def boundary(x, y, w, h, label, color, t, dashed=False):
    dash = ' stroke-dasharray="6 5"' if dashed else ""
    return (
        f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="14" fill="none" stroke="{t[color]}" stroke-width="1.4"{dash}/>'
        f'<rect x="{x + 16}" y="{y - 9}" width="{len(label) * 7 + 16}" height="18" rx="4" fill="{t["bg"]}"/>'
        + text(
            x + 24, y + 4, label, t, size=11, fill=color, weight=600, family=MONO, anchor="start"
        )
    )


def write_both(draw, outdir, stem="architecture"):
    """Write <stem>-dark.svg and <stem>-light.svg from draw(theme) into outdir."""
    os.makedirs(outdir, exist_ok=True)
    for name, theme in THEMES.items():
        with open(os.path.join(outdir, f"{stem}-{name}.svg"), "w") as f:
            f.write(draw(theme) + "\n")


# Flowchart shapes. A step is a numbered action, a decision a question the flow branches
# on, an outcome what a branch produces.
STEP_W, STEP_H = 480, 58


def step(cx, cy, n, title, sub, t, w=STEP_W):
    x, y = cx - w / 2, cy - STEP_H / 2
    return (
        f'<rect x="{x}" y="{y}" width="{w}" height="{STEP_H}" rx="10" fill="{t["panel"]}" stroke="{t["border"]}" stroke-width="1.2"/>'
        + text(
            x + 18, cy - 4, str(n), t, size=12, fill="dim", weight=600, family=MONO, anchor="start"
        )
        + text(x + 42, cy - 4, title, t, size=13.5, weight=650, anchor="start")
        + text(x + 42, cy + 14, sub, t, size=10.5, fill="muted", family=MONO, anchor="start")
    )


def decision(cx, cy, question, t, w=STEP_W):
    x, y = cx - w / 2, cy - 21
    return (
        f'<rect x="{x}" y="{y}" width="{w}" height="42" rx="21" fill="{t["lane"]}" stroke="{t["region"]}" stroke-width="1.3"/>'
        + text(cx, cy + 4.5, question, t, size=12.5, weight=600)
    )


def outcome(x, cy, label, cat, t):
    w = len(label) * 6.7 + 26
    return (
        f'<rect x="{x}" y="{cy - 14}" width="{w}" height="28" rx="14" fill="{CAT[cat]}" opacity="0.92"/>'
        + text(x + w / 2, cy + 4.5, label, t, size=11.5, fill="#ffffff", weight=600, family=MONO)
    )
