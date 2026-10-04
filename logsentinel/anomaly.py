"""Unsupervised anomaly detection with Isolation Forest over per-IP, per-time-window behaviour.

Rules catch what we already know to look for. The forest catches the "that's odd" cases, like a valid login from a
new IP at 3am or one client pulling gigabytes, that no single rule describes. Each anomaly is explained with the
features that deviate most from the median window (robust z-scores).
"""

from __future__ import annotations

import math
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta

import numpy as np
from sklearn.ensemble import IsolationForest

from .parsers import Event

AUTH_FEATURES = ["events", "failures", "successes", "distinct_users", "failure_ratio", "off_hours", "new_ip_for_user", "invalid_users"]
WEB_FEATURES = ["requests", "distinct_paths", "client_errors", "server_errors", "log_bytes", "peak_per_minute",
                "off_hours", "non_get_ratio"]
COUNT_FEATURES = {"events", "failures", "invalid_users", "requests", "distinct_paths", "peak_per_minute", "client_errors", "server_errors"}
WEAK_REASONS = ("Activity between",)  # context, not evidence on its own
LABELS = {
    "events": "auth events", "failures": "failed logins", "successes": "successful logins", "distinct_users": "distinct usernames",
    "failure_ratio": "failure ratio", "off_hours": "activity between 00:00 and 05:59",
    "new_ip_for_user": "successful login from an IP that user rarely uses",
    "invalid_users": "attempts on non-existent users", "requests": "requests", "distinct_paths": "distinct paths",
    "client_errors": "4xx responses", "server_errors": "5xx responses", "log_bytes": "bytes transferred",
    "peak_per_minute": "peak requests/minute", "non_get_ratio": "non-GET ratio",
}


@dataclass
class Anomaly:
    source: str
    ip: str
    window_start: datetime
    score: float
    features: dict[str, float]
    reasons: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = self.__dict__.copy()
        d["window_start"] = self.window_start.isoformat()
        return d


def _bucket(ts: datetime, window: timedelta) -> datetime:
    secs = int(window.total_seconds())
    epoch = int(ts.timestamp())
    return datetime.fromtimestamp(epoch - epoch % secs)


def auth_windows(events: list[Event], window: timedelta) -> dict[tuple[str, datetime], dict[str, float]]:
    groups: dict[tuple[str, datetime], list[Event]] = defaultdict(list)
    # How often each user logs in successfully from each IP, across the whole log.
    user_ip: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for e in events:
        if e.source == "auth" and e.kind == "auth_success":
            user_ip[e.user][e.ip] += 1
    new_ip_hits: dict[tuple[str, datetime], int] = defaultdict(int)
    for e in events:
        if e.source != "auth" or e.kind == "sudo":
            continue
        key = (e.ip, _bucket(e.ts, window))
        groups[key].append(e)
        if e.kind == "auth_success":
            history = user_ip[e.user]
            # rare = a one-off IP for a user with an established pattern (>=5 successful logins)
            if sum(history.values()) >= 5 and history[e.ip] == 1:
                new_ip_hits[key] += 1
    rows = {}
    for key, evs in groups.items():
        fails = sum(e.kind == "auth_failure" for e in evs)
        succ = sum(e.kind == "auth_success" for e in evs)
        rows[key] = {
            "events": math.log1p(len(evs)), "failures": math.log1p(fails), "successes": float(succ),
            "distinct_users": float(len({e.user for e in evs if e.user})), "failure_ratio": fails / max(1, fails + succ),
            "off_hours": float(key[1].hour < 6), "new_ip_for_user": float(new_ip_hits[key]),
            "invalid_users": math.log1p(sum(e.kind == "invalid_user" for e in evs)),
        }
    return rows


def web_windows(events: list[Event], window: timedelta) -> dict[tuple[str, datetime], dict[str, float]]:
    groups: dict[tuple[str, datetime], list[Event]] = defaultdict(list)
    for e in events:
        if e.source == "web":
            groups[(e.ip, _bucket(e.ts, window))].append(e)
    rows = {}
    for key, evs in groups.items():
        n = len(evs)
        per_min: dict[datetime, int] = defaultdict(int)
        for e in evs:
            per_min[e.ts.replace(second=0)] += 1
        rows[key] = {
            "requests": math.log1p(n), "distinct_paths": math.log1p(len({e.path for e in evs})),
            "client_errors": math.log1p(sum(400 <= e.status < 500 for e in evs)), "server_errors": math.log1p(sum(e.status >= 500 for e in evs)),
            "log_bytes": math.log1p(sum(e.size for e in evs)), "peak_per_minute": math.log1p(max(per_min.values())),
            "off_hours": float(key[1].hour < 6), "non_get_ratio": sum(e.method not in ("GET", "HEAD") for e in evs) / n,
        }
    return rows


def _explain(x: np.ndarray, X: np.ndarray, names: list[str], raw: dict[str, float]) -> list[str]:
    med = np.median(X, axis=0)
    mad = np.median(np.abs(X - med), axis=0) * 1.4826
    scale = np.where(mad > 1e-9, mad, np.maximum(X.std(axis=0), 1e-3))
    z = (x - med) / scale
    out = []
    for i in np.argsort(-z)[:3]:
        if z[i] < 2.5:
            continue  # only "more than usual" is interesting from a security point of view
        name = names[i]
        val = raw[name]
        if name in COUNT_FEATURES and math.expm1(val) - math.expm1(med[i]) < 5:
            continue  # one stray 404 is statistically rare but operationally meaningless
        if name in ("off_hours", "new_ip_for_user"):
            out.append(LABELS[name][0].upper() + LABELS[name][1:])
            continue
        shown = f"{math.expm1(val):,.0f}" if name in COUNT_FEATURES else (
            f"{math.expm1(val) / 1e6:,.1f} MB" if name == "log_bytes" else f"{val:.2f}".rstrip("0").rstrip("."))
        typical = med[i]
        typ = f"{math.expm1(typical):,.0f}" if name in COUNT_FEATURES else (
            f"{math.expm1(typical) / 1e6:,.2f} MB" if name == "log_bytes" else f"{typical:.2f}".rstrip("0").rstrip("."))
        out.append(f"{LABELS[name]}: {shown} (typical {typ})")
    return out


def detect_anomalies(events: list[Event], window_minutes: int = 60, contamination: float | str = 0.05,
                     seed: int = 0, min_windows: int = 20) -> list[Anomaly]:
    """Fit one Isolation Forest per log source and return the windows it isolates, most anomalous first."""
    window = timedelta(minutes=window_minutes)
    results: list[Anomaly] = []
    for source, rows, names in (("auth", auth_windows(events, window), AUTH_FEATURES), ("web", web_windows(events, window), WEB_FEATURES)):
        if len(rows) < min_windows:
            continue  # not enough behaviour to learn what "normal" looks like
        keys = list(rows)
        X = np.array([[rows[k][n] for n in names] for k in keys])
        forest = IsolationForest(n_estimators=300, contamination=contamination, random_state=seed).fit(X)
        pred = forest.predict(X)
        scores = -forest.score_samples(X)
        for idx in np.where(pred == -1)[0]:
            ip, start = keys[idx]
            reasons = _explain(X[idx], X, names, rows[keys[idx]])
            if not any(not r.startswith(WEAK_REASONS) for r in reasons):
                continue  # isolated for being quiet / merely nocturnal (e.g. a health-check bot) - not a security signal
            results.append(Anomaly(source, ip, start, round(float(scores[idx]), 3), rows[keys[idx]], reasons))
    return sorted(results, key=lambda a: -a.score)
