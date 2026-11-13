# version : 1.3.0
# created by : JK and CF
# last edited : 13/11/2026
# Name : bro-backup (bro/charts.py)
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 the BRO Backup authors
"""Small SVG charts for the history page, drawn on the server: no JavaScript, no outside libraries.

One series per chart, one axis, the app's accent color, a recessive grid, and a tooltip on every
mark (the SVG <title>, over a hit area as tall as the chart)."""

from html import escape

from .core import human_bytes, human_secs, local_time

W, H = 640, 190
PAD_L, PAD_R, PAD_T, PAD_B = 64, 12, 12, 28


def _nice_max(v):
    if v <= 0:
        return 1
    mag = 10 ** (len(str(int(v))) - 1)
    for m in (1, 2, 2.5, 5, 10):
        if v <= m * mag:
            return m * mag
    return 10 * mag


def _bytes_ticks(vmax):
    """A round top value in the unit that fits, so the axis reads 0, 25 MiB, 50 MiB..."""
    for unit in (1, 1024, 1024 ** 2, 1024 ** 3, 1024 ** 4):
        if vmax / unit < 1024:
            return _nice_max(vmax / unit) * unit
    return _nice_max(vmax)


def _frame(top, fmt):
    out = []
    for i in range(5):
        val = top * i / 4
        y = PAD_T + (H - PAD_T - PAD_B) * (1 - i / 4)
        out.append(f'<line x1="{PAD_L}" x2="{W - PAD_R}" y1="{y:.1f}" y2="{y:.1f}" stroke="var(--line)" stroke-width="1"/>')
        out.append(f'<text x="{PAD_L - 8}" y="{y + 4:.1f}" text-anchor="end" font-size="11" fill="var(--muted)">{escape(fmt(val))}</text>')
    return out


def _xlabels(points):
    out = []
    n = len(points)
    for idx in sorted({0, n // 2, n - 1}) if n > 2 else range(n):
        x, label = points[idx]
        anchor = "start" if idx == 0 else ("end" if idx == n - 1 else "middle")
        out.append(f'<text x="{x:.1f}" y="{H - 8}" text-anchor="{anchor}" font-size="11" fill="var(--muted)">{escape(label)}</text>')
    return out


def _svg(parts, label):
    return (f'<svg viewBox="0 0 {W} {H}" width="100%" role="img" aria-label="{escape(label)}" '
            f'style="display:block; max-width:{W}px">' + "".join(parts) + "</svg>")


def bars(entries, key, fmt, label):
    """Bar chart of entries[key]; bars rounded at the top and square at the baseline."""
    vals = [max(0, e.get(key) or 0) for e in entries]
    if not vals:
        return None
    top = _bytes_ticks(max(vals)) if fmt is human_bytes else _nice_max(max(vals))
    plot_w, plot_h = W - PAD_L - PAD_R, H - PAD_T - PAD_B
    slot = plot_w / len(vals)
    bw = max(2.0, min(18.0, slot - 2))  # at least a 2px gap between bars
    parts = _frame(top, fmt)
    pts = []
    for i, (e, v) in enumerate(zip(entries, vals)):
        cx = PAD_L + slot * (i + 0.5)
        h = plot_h * v / top if top else 0
        x, y, base = cx - bw / 2, PAD_T + plot_h - h, PAD_T + plot_h
        r = min(4, bw / 2, h)
        tip = f"{local_time(e['at'])}: {fmt(v)}"
        parts.append(f'<g><title>{escape(tip)}</title>'
                     f'<rect x="{cx - slot / 2:.1f}" y="{PAD_T}" width="{slot:.1f}" height="{plot_h}" fill="transparent"/>')
        if h > 0:
            parts.append(f'<path d="M{x:.1f},{base:.1f} V{y + r:.1f} Q{x:.1f},{y:.1f} {x + r:.1f},{y:.1f} '
                         f'H{x + bw - r:.1f} Q{x + bw:.1f},{y:.1f} {x + bw:.1f},{y + r:.1f} V{base:.1f} Z" fill="var(--accent)"/>')
        parts.append("</g>")
        pts.append((cx, local_time(e["at"])[:10]))
    parts.append(f'<line x1="{PAD_L}" x2="{W - PAD_R}" y1="{PAD_T + plot_h}" y2="{PAD_T + plot_h}" stroke="var(--muted)" stroke-width="1"/>')
    parts += _xlabels(pts)
    return _svg(parts, label)


def line(entries, key, fmt, label):
    """Line chart of entries[key], skipping entries without a value."""
    pts_in = [(e, e.get(key)) for e in entries if e.get(key) is not None]
    if len(pts_in) < 2:
        return None
    vals = [v for _, v in pts_in]
    top = _bytes_ticks(max(vals)) if fmt is human_bytes else _nice_max(max(vals))
    plot_w, plot_h = W - PAD_L - PAD_R, H - PAD_T - PAD_B
    step = plot_w / (len(vals) - 1)
    xy = [(PAD_L + step * i, PAD_T + plot_h * (1 - v / top)) for i, v in enumerate(vals)]
    parts = _frame(top, fmt)
    parts.append('<polyline fill="none" stroke="var(--accent)" stroke-width="2" stroke-linejoin="round" points="'
                 + " ".join(f"{x:.1f},{y:.1f}" for x, y in xy) + '"/>')
    for k, ((e, v), (x, y)) in enumerate(zip(pts_in, xy)):
        dot = 4 if len(vals) <= 20 or k == len(vals) - 1 else 0  # dense lines: only the latest point
        tip = f"{local_time(e['at'])}: {fmt(v)}"
        parts.append(f'<g><title>{escape(tip)}</title>'
                     f'<rect x="{x - step / 2:.1f}" y="{PAD_T}" width="{max(step, 8):.1f}" height="{plot_h}" fill="transparent"/>'
                     f'<circle cx="{x:.1f}" cy="{y:.1f}" r="{dot}" fill="var(--accent)" '
                     'stroke="var(--card)" stroke-width="2"/></g>')
    parts.append(f'<line x1="{PAD_L}" x2="{W - PAD_R}" y1="{PAD_T + plot_h}" y2="{PAD_T + plot_h}" stroke="var(--muted)" stroke-width="1"/>')
    parts += _xlabels([(x, local_time(e["at"])[:10]) for (e, _), (x, _) in zip(pts_in, xy)])
    return _svg(parts, label)


def mbit_fmt(bps):
    v = f"{bps / 1e6:.1f}".rstrip("0").rstrip(".") if bps else "0"
    return f"{v} Mbit/s"


def duration_fmt(s):
    return human_secs(s) if s else "0"
