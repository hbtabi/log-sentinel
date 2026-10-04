from datetime import datetime

from logsentinel.parsers import detect_format, parse_access_line, parse_auth_line, parse_lines


def test_parse_failed_password_invalid_user():
    e = parse_auth_line("Sep 28 02:10:01 web-01 sshd[1234]: Failed password for invalid user admin from 203.0.113.45 port 51234 ssh2")
    assert e.kind == "auth_failure" and e.user == "admin" and e.ip == "203.0.113.45"
    assert e.ts == datetime(2026, 9, 28, 2, 10, 1)


def test_parse_accepted_and_iso_timestamp():
    e = parse_auth_line("2026-09-28T09:15:00.123+01:00 web-01 sshd[99]: Accepted publickey for hasaan from 10.20.0.11 port 5000 ssh2")
    assert e.kind == "auth_success" and e.user == "hasaan" and e.ts.hour == 9


def test_parse_sudo_command():
    e = parse_auth_line("Sep 28 02:20:09 web-01 sudo[77]: deploy : TTY=pts/1 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/cat /etc/shadow")
    assert e.kind == "sudo" and e.user == "deploy" and "/etc/shadow" in e.path


def test_irrelevant_lines_are_skipped():
    assert parse_auth_line("Sep 28 02:20:09 web-01 CRON[1]: (root) CMD (run-parts /etc/cron.hourly)") is None
    assert parse_auth_line("garbage") is None


def test_parse_access_combined():
    line = '198.51.100.23 - - [28/Sep/2026:05:20:00 +0000] "GET /.env HTTP/1.1" 404 153 "-" "Mozilla/5.0 zgrab/0.x"'
    e = parse_access_line(line)
    assert (e.ip, e.method, e.path, e.status, e.size) == ("198.51.100.23", "GET", "/.env", 404, 153)
    assert "zgrab" in e.ua


def test_access_without_referer_and_dash_size():
    e = parse_access_line('10.0.0.1 - bob [01/Oct/2026:10:00:00 +0000] "POST /login HTTP/1.1" 302 -')
    assert e.user == "bob" and e.size == 0 and e.method == "POST"


def test_detect_format_and_parse_lines():
    web = ['10.0.0.1 - - [01/Oct/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 5 "-" "x"'] * 3
    assert detect_format(web) == "web"
    assert len(list(parse_lines(web))) == 3
