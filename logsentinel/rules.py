"""Deterministic detection rules. Each produces ``Finding`` objects with evidence and a MITRE ATT&CK reference."""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from urllib.parse import unquote

from .parsers import Event

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


@dataclass
class Finding:
    rule: str
    severity: str
    ip: str
    title: str
    description: str
    first_seen: datetime
    last_seen: datetime
    count: int
    mitre: str = ""
    evidence: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = self.__dict__.copy()
        d["first_seen"], d["last_seen"] = self.first_seen.isoformat(), self.last_seen.isoformat()
        return d


@dataclass
class RuleConfig:
    brute_force_threshold: int = 10  # failures ...
    brute_force_window: timedelta = timedelta(minutes=5)  # ... within this window
    spray_distinct_users: int = 6
    scan_distinct_paths: int = 15
    scan_window: timedelta = timedelta(minutes=10)
    evidence_lines: int = 5


SENSITIVE_PATHS = re.compile(
    r"(?i)(/\.env\b|/\.git/|/\.svn/|/\.aws/|/\.DS_Store|wp-login\.php|/wp-admin|xmlrpc\.php|phpmyadmin|/server-status|"
    r"/actuator/|eval-stdin\.php|\.sql\b|\.bak\b|backup\.(zip|tar|gz)|/etc/(passwd|shadow))"
)
INJECTION = {
    "SQL injection": re.compile(r"(?i)(\bunion\b.{0,40}\bselect\b|'\s*or\s*'?\d*'?\s*=\s*'?\d*|\bor\s+1\s*=\s*1\b|sleep\(\d+\)|--\s*$|;\s*drop\s+table)"),
    "Cross-site scripting": re.compile(r"(?i)(<script\b|javascript:|onerror\s*=|onload\s*=)"),
    "Path traversal": re.compile(r"(\.\./|\.\.\\|\.\.\.\.//)"),
    "Command injection": re.compile(r"(?i)(;|\||`|\$\()\s*(cat|ls|id|whoami|wget|curl|nc|bash|sh)\b"),
    "Log4Shell / JNDI": re.compile(r"(?i)\$\{jndi:"),
}
SCANNER_UA = re.compile(r"(?i)(sqlmap|nikto|nmap|masscan|zgrab|gobuster|dirbuster|wpscan|nuclei|feroxbuster|ffuf|acunetix|nessus)")


def _span(events: list[Event]) -> tuple[datetime, datetime]:
    return events[0].ts, events[-1].ts


def _evidence(events: list[Event], n: int) -> list[str]:
    if len(events) <= n:
        return [e.raw for e in events]
    return [e.raw for e in events[: n - 1]] + [f"... {len(events) - n} more ...", events[-1].raw]


def _sliding_max(events: list[Event], window: timedelta) -> tuple[int, int, int]:
    """Max number of events in any window; returns (count, start_idx, end_idx)."""
    best, bi, bj, i = 0, 0, 0, 0
    for j in range(len(events)):
        while events[j].ts - events[i].ts > window:
            i += 1
        if j - i + 1 > best:
            best, bi, bj = j - i + 1, i, j
    return best, bi, bj


def ssh_rules(events: list[Event], cfg: RuleConfig) -> list[Finding]:
    findings: list[Finding] = []
    by_ip: dict[str, list[Event]] = defaultdict(list)
    for e in events:
        if e.source == "auth" and e.ip not in ("local", ""):
            by_ip[e.ip].append(e)
    for ip, evs in by_ip.items():
        fails = [e for e in evs if e.kind == "auth_failure"]
        count, i, j = _sliding_max(fails, cfg.brute_force_window)
        if count >= cfg.brute_force_threshold:
            burst = fails[i : j + 1]
            users = sorted({e.user for e in fails})
            findings.append(Finding(
                "ssh_brute_force", "high", ip, "SSH brute force",
                f"{len(fails)} failed logins ({count} within {int(cfg.brute_force_window.total_seconds() // 60)} min) "
                f"against {len(users)} account(s): {', '.join(users[:6])}{'...' if len(users) > 6 else ''}",
                *_span(burst), len(fails), "T1110.001 Brute Force: Password Guessing", _evidence(burst, cfg.evidence_lines)))
            after = [e for e in evs if e.kind == "auth_success" and e.ts >= burst[0].ts]
            if after:
                s = after[0]
                findings.append(Finding(
                    "login_after_brute_force", "critical", ip, "Successful login after brute force",
                    f"'{s.user}' logged in from {ip} after {len(fails)} failures - treat this account as compromised",
                    s.ts, s.ts, 1, "T1078 Valid Accounts", [s.raw]))
        users = {e.user for e in fails}
        if len(users) >= cfg.spray_distinct_users and count < cfg.brute_force_threshold:
            findings.append(Finding(
                "password_spray", "high", ip, "Password spraying",
                f"{len(fails)} failures spread across {len(users)} different accounts (low-and-slow, evades simple thresholds)",
                *_span(fails), len(fails), "T1110.003 Brute Force: Password Spraying", _evidence(fails, cfg.evidence_lines)))
    for e in events:
        if e.kind == "sudo" and re.search(r"/etc/shadow|/etc/sudoers|useradd|passwd\s|chmod\s+[0-7]*7[0-7]*\s+/", e.path):
            findings.append(Finding("sensitive_sudo", "high", "localhost", "Sensitive command via sudo",
                                    f"'{e.user}' ran: {e.path.strip()}", e.ts, e.ts, 1, "T1003.008 /etc/passwd and /etc/shadow", [e.raw]))
    return findings


def web_rules(events: list[Event], cfg: RuleConfig) -> list[Finding]:
    findings: list[Finding] = []
    by_ip: dict[str, list[Event]] = defaultdict(list)
    for e in events:
        if e.source == "web":
            by_ip[e.ip].append(e)
    for ip, evs in by_ip.items():
        errors = [e for e in evs if 400 <= e.status < 500]
        count, i, j = _sliding_max(errors, cfg.scan_window)
        burst = errors[i : j + 1] if errors else []
        distinct = len({e.path for e in burst})
        if distinct >= cfg.scan_distinct_paths:
            findings.append(Finding("web_scanning", "medium", ip, "Web content / vulnerability scanning",
                                    f"{len(errors)} client errors, {distinct} distinct paths probed within {int(cfg.scan_window.total_seconds() // 60)} min",
                                    *_span(burst), len(errors), "T1595.003 Active Scanning: Wordlist Scanning",
                                    _evidence(burst, cfg.evidence_lines)))
        probes = [e for e in evs if SENSITIVE_PATHS.search(unquote(e.path))]
        if probes:
            paths = sorted({e.path for e in probes})
            findings.append(Finding("sensitive_path_probe", "medium", ip, "Probing for sensitive files",
                                    f"Requested {len(paths)} sensitive path(s): {', '.join(paths[:5])}{'...' if len(paths) > 5 else ''}",
                                    *_span(probes), len(probes), "T1083 File and Directory Discovery", _evidence(probes, cfg.evidence_lines)))
        hits: dict[str, list[Event]] = defaultdict(list)
        for e in evs:
            decoded = unquote(unquote(e.path))
            for name, pat in INJECTION.items():
                if pat.search(decoded):
                    hits[name].append(e)
        if hits:
            hs = sorted({id(e): e for v in hits.values() for e in v}.values(), key=lambda e: e.ts)
            ok = sum(200 <= e.status < 300 for e in hs)
            kinds = ", ".join(f"{k} ({len(v)})" for k, v in hits.items())
            findings.append(Finding("injection_attempt", "critical" if ok else "high", ip, "Injection / exploit attempts",
                                    f"{len(hs)} request(s) with attack payloads: {kinds}"
                                    + (f". {ok} returned 2xx, check whether they succeeded" if ok else ". All were rejected (4xx/5xx)"),
                                    *_span(hs), len(hs), "T1190 Exploit Public-Facing Application", _evidence(hs, cfg.evidence_lines)))
        scanners = [e for e in evs if SCANNER_UA.search(e.ua)]
        if scanners:
            findings.append(Finding("scanner_user_agent", "medium", ip, "Known scanner user-agent",
                                    f"User-agent '{scanners[0].ua}' belongs to an automated scanning tool",
                                    *_span(scanners), len(scanners), "T1595 Active Scanning", _evidence(scanners, 2)))
    return findings


def run_rules(events: list[Event], cfg: RuleConfig | None = None) -> list[Finding]:
    cfg = cfg or RuleConfig()
    events = sorted(events, key=lambda e: e.ts)
    findings = ssh_rules(events, cfg) + web_rules(events, cfg)
    return sorted(findings, key=lambda f: (-SEVERITY_ORDER[f.severity], f.first_seen))
