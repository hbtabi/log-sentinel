"""Parsers for OpenSSH auth logs (syslog format) and web access logs (Nginx/Apache combined format).

Both are normalised into ``Event`` objects so the detectors don't care where an event came from.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from datetime import datetime

SYSLOG_RE = re.compile(r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2} \d{2}:\d{2}:\d{2}) (?P<host>\S+) (?P<proc>[\w\-./]+)(?:\[\d+\])?: (?P<msg>.*)$")
ISO_SYSLOG_RE = re.compile(r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{2}:?\d{2}|Z)?) (?P<host>\S+) (?P<proc>[\w\-./]+)(?:\[\d+\])?: (?P<msg>.*)$")
SSH_PATTERNS = [
    ("auth_failure", re.compile(r"Failed (?:password|publickey) for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\d.:a-fA-F]+)")),
    ("auth_success", re.compile(r"Accepted (?:password|publickey|keyboard-interactive/pam) for (?P<user>\S+) from (?P<ip>[\d.:a-fA-F]+)")),
    ("invalid_user", re.compile(r"Invalid user (?P<user>\S*) from (?P<ip>[\d.:a-fA-F]+)")),
    ("disconnect_preauth", re.compile(r"(?:Disconnected from|Connection closed by) (?:authenticating |invalid )?(?:user (?P<user>\S+) )?(?P<ip>[\d.:a-fA-F]+) port \d+ \[preauth\]")),
    ("sudo", re.compile(r"^\s*(?P<user>\S+) : .*COMMAND=(?P<cmd>.*)$")),
]
ACCESS_RE = re.compile(
    r'^(?P<ip>\S+) \S+ (?P<user>\S+) \[(?P<ts>[^\]]+)\] "(?P<method>[A-Z]+|-) ?(?P<path>[^"]*?)(?: HTTP/[\d.]+)?" '
    r'(?P<status>\d{3}) (?P<size>\d+|-)(?: "(?P<ref>[^"]*)" "(?P<ua>[^"]*)")?'
)


@dataclass
class Event:
    ts: datetime
    source: str  # "auth" | "web"
    kind: str  # auth_failure, auth_success, invalid_user, request, sudo...
    ip: str
    user: str = ""
    path: str = ""
    method: str = ""
    status: int = 0
    size: int = 0
    ua: str = ""
    raw: str = field(default="", repr=False)


def _parse_syslog_ts(ts: str, year: int) -> datetime:
    if ts[:4].isdigit():
        return datetime.fromisoformat(ts.replace("Z", "+00:00")).replace(tzinfo=None)
    return datetime.strptime(f"{year} {' '.join(ts.split())}", "%Y %b %d %H:%M:%S")


def parse_auth_line(line: str, year: int = 2026) -> Event | None:
    m = SYSLOG_RE.match(line) or ISO_SYSLOG_RE.match(line)
    if not m:
        return None
    msg, proc = m["msg"], m["proc"]
    for kind, pat in SSH_PATTERNS:
        if kind == "sudo" and proc != "sudo":
            continue
        pm = pat.search(msg)
        if pm:
            d = pm.groupdict()
            return Event(_parse_syslog_ts(m["ts"], year), "auth", kind, d.get("ip") or "local", d.get("user") or "",
                         path=d.get("cmd", "") or "", raw=line)
    return None


def parse_access_line(line: str) -> Event | None:
    m = ACCESS_RE.match(line)
    if not m:
        return None
    ts = datetime.strptime(m["ts"].split()[0], "%d/%b/%Y:%H:%M:%S")
    size = 0 if m["size"] == "-" else int(m["size"])
    return Event(ts, "web", "request", m["ip"], "" if m["user"] == "-" else m["user"], path=m["path"] or "",
                 method=m["method"], status=int(m["status"]), size=size, ua=m["ua"] or "", raw=line)


def detect_format(lines: list[str]) -> str:
    sample = [ln for ln in lines[:50] if ln.strip()]
    web = sum(bool(ACCESS_RE.match(ln)) for ln in sample)
    auth = sum(bool(SYSLOG_RE.match(ln) or ISO_SYSLOG_RE.match(ln)) for ln in sample)
    return "web" if web >= auth else "auth"


def parse_lines(lines: Iterable[str], fmt: str = "auto", year: int = 2026) -> Iterator[Event]:
    lines = [ln.rstrip("\n") for ln in lines]
    if fmt == "auto":
        fmt = detect_format(lines)
    for ln in lines:
        ev = parse_access_line(ln) if fmt == "web" else parse_auth_line(ln, year)
        if ev:
            yield ev


def parse_file(path: str, fmt: str = "auto", year: int = 2026) -> list[Event]:
    with open(path, encoding="utf-8", errors="replace") as fh:
        return list(parse_lines(fh, fmt, year))
