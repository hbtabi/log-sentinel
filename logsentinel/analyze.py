"""Glue: parse files -> rules + anomalies -> a single ``Report`` object."""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime

from .anomaly import Anomaly, detect_anomalies
from .parsers import Event, parse_file
from .rules import SEVERITY_ORDER, Finding, RuleConfig, run_rules


@dataclass
class Report:
    sources: list[str]
    events: list[Event]
    findings: list[Finding]
    anomalies: list[Anomaly]
    generated_at: datetime = field(default_factory=lambda: datetime.now().replace(microsecond=0))
    summary_text: str | None = None

    @property
    def severity_counts(self) -> dict[str, int]:
        c = Counter(f.severity for f in self.findings)
        return {s: c.get(s, 0) for s in sorted(SEVERITY_ORDER, key=lambda s: -SEVERITY_ORDER[s]) if s != "info"}

    @property
    def time_range(self) -> tuple[datetime, datetime] | None:
        if not self.events:
            return None
        ts = [e.ts for e in self.events]
        return min(ts), max(ts)

    @property
    def flagged_ips(self) -> list[tuple[str, str, int]]:
        """(ip, worst severity, number of findings) for every IP with a finding."""
        worst: dict[str, str] = {}
        n: Counter = Counter()
        for f in self.findings:
            n[f.ip] += 1
            if f.ip not in worst or SEVERITY_ORDER[f.severity] > SEVERITY_ORDER[worst[f.ip]]:
                worst[f.ip] = f.severity
        return sorted(((ip, worst[ip], n[ip]) for ip in worst), key=lambda x: (-SEVERITY_ORDER[x[1]], -x[2]))

    def top_talkers(self, k: int = 8) -> list[tuple[str, int]]:
        return Counter(e.ip for e in self.events).most_common(k)

    def to_json(self) -> str:
        tr = self.time_range
        return json.dumps({
            "generated_at": self.generated_at.isoformat(), "sources": self.sources, "events": len(self.events),
            "time_range": [tr[0].isoformat(), tr[1].isoformat()] if tr else None,
            "severity_counts": self.severity_counts, "findings": [f.to_dict() for f in self.findings],
            "anomalies": [a.to_dict() for a in self.anomalies], "summary": self.summary_text,
        }, indent=2)


def analyze_events(events: list[Event], sources: list[str] | None = None, cfg: RuleConfig | None = None,
                   window_minutes: int = 60, contamination: float = 0.05) -> Report:
    events = sorted(events, key=lambda e: e.ts)
    return Report(sources or [], events, run_rules(events, cfg), detect_anomalies(events, window_minutes, contamination))


def analyze_files(paths: list[str], fmt: str = "auto", year: int = 2026, **kw) -> Report:
    events: list[Event] = []
    for p in paths:
        events += parse_file(p, fmt, year)
    return analyze_events(events, paths, **kw)
