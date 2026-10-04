"""Self-contained HTML report (no JavaScript, no CDN): Jinja2 template + hand-built SVG timeline."""

from __future__ import annotations

from datetime import timedelta
from html import escape
from importlib.resources import files

from jinja2 import Environment, select_autoescape

from .analyze import Report

SERIES = [("Failed logins", "#f85149", lambda e: e.source == "auth" and e.kind in ("auth_failure", "invalid_user")),
          ("Successful logins", "#3fb950", lambda e: e.source == "auth" and e.kind == "auth_success"),
          ("Web 4xx/5xx", "#d29922", lambda e: e.source == "web" and e.status >= 400),
          ("Web OK", "#388bfd", lambda e: e.source == "web" and e.status < 400)]
SEV_COLOR = {"critical": "#ff4d6d", "high": "#f85149", "medium": "#d29922", "low": "#58a6ff"}


def timeline_svg(report: Report, width: int = 1000, height: int = 220, buckets: int = 96) -> str:
    tr = report.time_range
    if not tr:
        return ""
    start, end = tr
    span = max((end - start).total_seconds(), 60)
    step = span / buckets
    counts = [[0] * buckets for _ in SERIES]
    for e in report.events:
        b = min(int((e.ts - start).total_seconds() / step), buckets - 1)
        for i, (_, _, pred) in enumerate(SERIES):
            if pred(e):
                counts[i][b] += 1
                break
    pad_l, pad_b, pad_t = 44, 26, 14
    w, h = width - pad_l - 10, height - pad_b - pad_t
    totals = [sum(c[b] for c in counts) for b in range(buckets)]
    peak = max(max(totals), 1)
    bw = w / buckets
    parts = [f'<svg viewBox="0 0 {width} {height}" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="Event timeline">']
    for frac in (0, 0.5, 1):
        y = pad_t + h - frac * h
        parts.append(f'<line x1="{pad_l}" x2="{width - 10}" y1="{y:.1f}" y2="{y:.1f}" stroke="#30363d" stroke-dasharray="3 3"/>')
        parts.append(f'<text x="{pad_l - 6}" y="{y + 4:.1f}" text-anchor="end" fill="#8b949e" font-size="11">{int(peak * frac)}</text>')
    for b in range(buckets):
        y = pad_t + h
        for i, (name, color, _) in enumerate(SERIES):
            v = counts[i][b]
            if not v:
                continue
            bh = v / peak * h
            y -= bh
            t0 = start + timedelta(seconds=b * step)
            parts.append(f'<rect x="{pad_l + b * bw + 0.5:.1f}" y="{y:.1f}" width="{max(bw - 1, 1):.1f}" height="{bh:.1f}" fill="{color}">'
                         f'<title>{escape(name)}: {v} @ {t0:%H:%M}</title></rect>')
    for f in report.findings:  # severity markers along the top
        x = pad_l + (f.first_seen - start).total_seconds() / span * w
        parts.append(f'<circle cx="{x:.1f}" cy="{pad_t - 6}" r="4" fill="{SEV_COLOR.get(f.severity, "#8b949e")}"><title>{escape(f.title)} ({f.ip})</title></circle>')
    for k in range(5):
        t = start + timedelta(seconds=span * k / 4)
        x = pad_l + w * k / 4
        anchor = "start" if k == 0 else "end" if k == 4 else "middle"
        parts.append(f'<text x="{x:.1f}" y="{height - 6}" text-anchor="{anchor}" fill="#8b949e" font-size="11">{t:%d %b %H:%M}</text>')
    parts.append("</svg>")
    return "".join(parts)


def render_html(report: Report) -> str:
    env = Environment(autoescape=select_autoescape(["html"]), trim_blocks=True, lstrip_blocks=True)
    tpl = env.from_string(files("logsentinel").joinpath("templates/report.html").read_text(encoding="utf-8"))
    return tpl.render(r=report, timeline=timeline_svg(report), series=SERIES, sev_color=SEV_COLOR)
