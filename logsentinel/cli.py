"""``log-sentinel analyze`` / ``log-sentinel simulate``."""

from __future__ import annotations

import argparse
import os
import sys
from datetime import timedelta
from pathlib import Path

from .analyze import analyze_files
from .llm import summarize
from .report import render_html
from .rules import SEVERITY_ORDER, RuleConfig
from .simulate import generate_access_log, generate_auth_log

SEV_ANSI = {"critical": "1;35", "high": "1;31", "medium": "33", "low": "36"}


def _c(s: str, code: str, on: bool) -> str:
    return f"\033[{code}m{s}\033[0m" if on else s


def _print_summary(report, color: bool) -> None:
    tr = report.time_range
    print(_c(f"log-sentinel: {len(report.events)} events", "1", color)
          + (f"  {tr[0]:%d %b %H:%M} -> {tr[1]:%d %b %H:%M}" if tr else ""))
    print("  " + "  ".join(_c(f"{n} {s}", SEV_ANSI[s], color) for s, n in report.severity_counts.items())
          + f"  | {len(report.anomalies)} anomalies")
    print()
    for f in report.findings:
        print(f"  {_c(f'[{f.severity.upper():>8}]', SEV_ANSI[f.severity], color)} {f.title:<38} {f.ip:<16} {f.first_seen:%H:%M:%S}  x{f.count}")
        print(_c(f"             {f.description}", "90", color))
    if report.anomalies:
        print(_c("\n  Behavioural anomalies (Isolation Forest)", "1", color))
        for a in report.anomalies:
            print(f"  {_c(f'{a.score:.2f}', '36', color)} {a.source:<4} {a.ip:<16} {a.window_start:%d %b %H:%M}  " + "; ".join(a.reasons))


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="log-sentinel", description="Security log anomaly detection: rules + Isolation Forest")
    ap.add_argument("--no-color", action="store_true")
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("analyze", help="analyse auth.log / access.log files")
    a.add_argument("files", nargs="+")
    a.add_argument("--format", choices=["auto", "auth", "web"], default="auto")
    a.add_argument("--year", type=int, default=2026, help="year for syslog timestamps (they don't include one)")
    a.add_argument("--html", metavar="PATH", help="write a self-contained HTML report")
    a.add_argument("--json", metavar="PATH", help="write findings as JSON ('-' for stdout)")
    a.add_argument("--window", type=int, default=60, help="anomaly window in minutes (default 60)")
    a.add_argument("--contamination", type=float, default=0.05, help="expected anomaly share for Isolation Forest")
    a.add_argument("--brute-threshold", type=int, default=10, help="failed logins per 5 min that count as brute force")
    a.add_argument("--llm", action="store_true", help="add an executive summary (needs OPENAI_API_KEY)")
    a.add_argument("--fail-on", choices=list(SEVERITY_ORDER)[:4], help="exit 1 if a finding at/above this severity exists")
    s = sub.add_parser("simulate", help="write synthetic auth.log + access.log with injected attacks")
    s.add_argument("--out", default="samples")
    s.add_argument("--hours", type=int, default=24)
    s.add_argument("--seed", type=int, default=42)
    args = ap.parse_args(argv)
    color = (sys.stdout.isatty() or bool(os.environ.get("FORCE_COLOR"))) and not args.no_color and not os.environ.get("NO_COLOR")

    if args.cmd == "simulate":
        out = Path(args.out)
        out.mkdir(parents=True, exist_ok=True)
        (out / "auth.log").write_text("\n".join(generate_auth_log(hours=args.hours, seed=args.seed)) + "\n")
        (out / "access.log").write_text("\n".join(generate_access_log(hours=args.hours, seed=args.seed + 1)) + "\n")
        print(f"wrote {out / 'auth.log'} and {out / 'access.log'}")
        return 0

    cfg = RuleConfig(brute_force_threshold=args.brute_threshold, brute_force_window=timedelta(minutes=5))
    report = analyze_files(args.files, args.format, args.year, cfg=cfg, window_minutes=args.window, contamination=args.contamination)
    if args.llm:
        text = "\n".join(f"[{f.severity}] {f.title} from {f.ip}: {f.description}" for f in report.findings[:30])
        report.summary_text = summarize(text) or "(LLM summary skipped: set OPENAI_API_KEY to enable)"
    if args.json == "-":
        print(report.to_json())
    else:
        _print_summary(report, color)
        if args.json:
            Path(args.json).write_text(report.to_json())
            print(f"\n  JSON  -> {args.json}")
    if args.html:
        Path(args.html).write_text(render_html(report), encoding="utf-8")
        if args.json != "-":
            print(f"  HTML  -> {args.html}")
    if args.fail_on and any(SEVERITY_ORDER[f.severity] >= SEVERITY_ORDER[args.fail_on] for f in report.findings):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
