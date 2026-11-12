#!/usr/bin/env python3
"""
SSH Guard - advanced SSH brute force detection (stdlib only)
=============================================================
Stack: Python 3.9+, Linux, Elasticsearch (raw REST, no client library), Tkinter

Detection
  * brute_force          N failed logins from one IP inside a short window
  * password_spray       same, but with many distinct usernames
  * slow_brute_force     low-and-slow attacks over a long window
  * distributed_attack   many different IPs hammering one username
  * possible_compromise  successful login right after failures (critical)
  * per-IP risk score (0-100), allowlist (CIDR), IPv4-mapped IPv6 normalisation

Response
  * optional auto-block (iptables or nftables set with native timeout),
    dry-run by default, TTL expiry, allowlist + your own SSH client IP protected

Storage / integration
  * SQLite for alerts and blocks (works fully offline)
  * Elasticsearch bulk indexing with retry/backoff, queries for top attackers
  * Sources: auth.log / secure (rotation-safe tail) or journald

Alerting and reporting
  * "SSH Brute Force Attempt Detected!" alert box (pop-up, console, email, Slack/Discord webhook)
  * Login attempts log: Time | IP Address | Username | Result | Attempts
  * HTML reports and analytics (totals, timeline, top IPs/users, recommendations)

Interfaces
  * Tkinter dashboard (chart, attempts, alerts, attackers, blocklist, reports, settings, guide)
  * Web dashboard (stdlib http.server, read-only, loopback by default)
  * Headless mode (JSON lines on stdout), replay mode, report mode, built-in self-test

Usage
  python3 ssh_guard.py                      GUI
  python3 ssh_guard.py --headless           daemon-style, alerts as JSON lines
  python3 ssh_guard.py --replay auth.log    process an existing log once
  python3 ssh_guard.py --report 24          write an HTML report for the last 24 hours
  python3 ssh_guard.py --headless --web     headless + web dashboard on http://127.0.0.1:8080
  python3 ssh_guard.py --selftest           run built-in tests

Enrichment
  * Offline GeoIP country lookup with a from-scratch MaxMind DB (.mmdb) reader
    (GeoLite2 / DB-IP lite). Country shows in every table, report and Elasticsearch document.
  * Kibana dashboard export (--kibana-export), systemd service in deploy/

Services (one detector per service, thresholds overridable per service)
  * SSH, Telnet, HTTP, HTTPS (nginx/Apache access+error logs: brute force, SQLi/XSS/traversal/RCE/
    log4shell signatures, sensitive-path probing, scanner user-agents, 404 floods, TLS probing),
    FTP (vsftpd/proftpd/pure-ftpd), SMTP/IMAP/POP3 (postfix/dovecot), MySQL/MariaDB, PostgreSQL,
    RDP (xrdp), SIP (asterisk), Webmin and ANY daemon that authenticates through pam_unix
  * Several log files at once (auto-detected or listed), plus journald

Live network sensor (raw AF_PACKET capture or --pcap replay, stdlib only, needs root)
  * Cleartext logins seen on the wire: Telnet, FTP, HTTP (basic auth, login forms, SQLi/XSS/traversal/RCE
    signatures, scanner user-agents), SMTP AUTH, POP3, IMAP, MySQL, PostgreSQL, MSSQL, Redis, SIP
  * Encrypted / binary services (SSH, RDP, VNC, SMB, HTTPS, TLS mail, LDAP ...): connection-rate brute force,
    connection floods, TLS handshake refusals, scanner banners; SYN and stealth port scans on any port
  * Usernames are kept, passwords are parsed away and never stored

Advanced
  * Extra detections: user_enumeration, ssh_scanner, honeypot (canary) users, root_login,
    new_login_source (per-user baseline), known_bad_ip (threat feeds: local file or URLs)
  * Escalating bans for repeat offenders, lock-out protection for IPs with login history
  * Syslog/CEF forwarding (SIEM), Telegram alerts, Prometheus /metrics, SIGHUP config reload
"""

import argparse
import base64
import csv
import ipaddress
import json
import os
import queue
import re
import html
import shutil
import signal
import smtplib
import socket
import sqlite3
import ssl
import struct
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
import webbrowser
from collections import Counter, defaultdict, deque
from dataclasses import asdict, dataclass, fields
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote, urlparse

try:
    import tkinter as tk
    from tkinter import filedialog, messagebox, ttk
    from tkinter.scrolledtext import ScrolledText
    TK_OK = True
except Exception:  # headless box without tkinter
    TK_OK = False

HOSTNAME = socket.gethostname()
__version__ = "1.2.0"
APP_DIR = os.environ.get("SSH_GUARD_HOME") or os.path.expanduser("~/.ssh_guard")
CONFIG_PATH = os.path.join(APP_DIR, "config.json")
DB_PATH = os.path.join(APP_DIR, "state.db")
SEV_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}
SECRETS = ("es_password", "es_api_key", "smtp_password", "telegram_token")


# ==========================================================================
# Configuration
# ==========================================================================
@dataclass
class Config:
    log_path: str = ""
    use_journal: bool = False
    from_start: bool = False
    threshold: int = 5
    window: int = 60
    slow_threshold: int = 20
    slow_window: int = 3600
    spray_users: int = 4
    distributed_ips: int = 5
    distributed_window: int = 300
    allowlist: str = "127.0.0.0/8, ::1"
    auto_block: bool = False
    block_dry_run: bool = True
    block_ttl: int = 3600
    block_backend: str = "iptables"
    block_min_severity: str = "high"
    es_enabled: bool = False
    es_url: str = "http://localhost:9200"
    es_user: str = ""
    es_password: str = ""
    es_api_key: str = ""
    es_verify: bool = True
    es_prefix: str = "ssh-guard"
    gui_popup: bool = True
    email_enabled: bool = False
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_security: str = "starttls"   # starttls | ssl | none
    smtp_user: str = ""
    smtp_password: str = ""
    mail_from: str = ""
    mail_to: str = ""
    email_min_severity: str = "high"
    webhook_url: str = ""
    web_enabled: bool = False
    web_host: str = "127.0.0.1"
    web_port: int = 8080
    geoip_db: str = ""
    enum_users: int = 8
    scan_threshold: int = 15
    canary_users: str = ""
    alert_root_login: bool = True
    new_source_alerts: bool = False
    block_escalate: bool = True
    protect_known_logins: bool = True
    feed_file: str = ""
    feed_urls: str = ""
    feed_refresh_hours: int = 12
    syslog_target: str = ""
    telegram_token: str = ""
    telegram_chat_id: str = ""
    extra_sources: str = ""
    auto_sources: bool = True
    web_probe_threshold: int = 5
    web_scan_threshold: int = 30
    web_attack_alerts: bool = True
    thresholds_override: str = "http=10,https=10"
    net_enabled: bool = True          # live network sensor (needs root / CAP_NET_RAW, otherwise it just says so)
    net_iface: str = ""               # "" = every interface
    net_scope: str = "local"          # local = traffic to this host | all = every flow on the segment (mirror/SPAN/gateway)
    net_inspect: bool = True          # read cleartext protocols (usernames only; passwords are never kept)
    net_ports: str = ""               # extra / overriding service ports: "ssh=2200; http=8081,8082; imap=1993/tls"
    net_conn_threshold: int = 20      # connections per window to a login service = guessing (SSH, RDP, VNC, SMB ...)
    net_flood_threshold: int = 300    # connections per window to any other service = flood
    net_scan_ports: int = 15          # distinct ports/hosts probed per window = port scan
    net_rate_override: str = ""       # per-service connection limits: "ssh=10,rdp=10"


def default_log_path():
    for p in ("/var/log/auth.log", "/var/log/secure"):
        if os.path.exists(p):
            return p
    return "/var/log/auth.log"


def load_config():
    cfg = Config(log_path=default_log_path())
    try:
        with open(CONFIG_PATH) as f:
            data = json.load(f)
        for fld in fields(Config):
            if fld.name in data and fld.name not in SECRETS:
                setattr(cfg, fld.name, type(getattr(cfg, fld.name))(data[fld.name]))
    except (OSError, ValueError):
        pass
    cfg.es_password = os.environ.get("ES_PASSWORD", cfg.es_password)
    cfg.es_api_key = os.environ.get("ES_API_KEY", cfg.es_api_key)
    cfg.smtp_password = os.environ.get("SMTP_PASSWORD", cfg.smtp_password)
    cfg.telegram_token = os.environ.get("TELEGRAM_TOKEN", cfg.telegram_token)
    return cfg


def save_config(cfg):
    os.makedirs(APP_DIR, exist_ok=True)
    data = {k: v for k, v in asdict(cfg).items() if k not in SECRETS}  # never persist secrets
    with open(CONFIG_PATH, "w") as f:
        json.dump(data, f, indent=2)


# ==========================================================================
# IP helpers
# ==========================================================================
def norm_ip(s):
    try:
        a = ipaddress.ip_address(s.strip("[]"))
    except ValueError:
        return None
    if a.version == 6 and a.ipv4_mapped:
        a = a.ipv4_mapped
    return str(a)


def parse_allowlist(text):
    nets = []
    for tok in re.split(r"[,\s]+", text.strip()):
        if not tok:
            continue
        try:
            nets.append(ipaddress.ip_network(tok, strict=False))
        except ValueError:
            pass
    conn = os.environ.get("SSH_CONNECTION")  # never lock out the admin's own session
    if conn:
        try:
            nets.append(ipaddress.ip_network(conn.split()[0]))
        except (ValueError, IndexError):
            pass
    return nets


def is_allowed(ip, nets):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(a in n for n in nets if n.version == a.version)


# ==========================================================================
# Log parsing
# ==========================================================================
ISO_TS = re.compile(r"^(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2})(\.\d+)?(Z|[+-]\d{2}:?\d{2})?")
SYSLOG_TS = re.compile(r"^\[?([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})")
MONTHS = {m: i for i, m in enumerate(
    "Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split(), 1)}
SSHD = r"sshd(?:-session)?\[\d+\]: "
IPX = r"(?P<ip>[0-9a-fA-F:.]+)"
# Usernames are attacker-controlled: they may contain spaces or even fake "from <ip> port <n>" text.
# sshd appends the REAL source last, so the user group is greedy and anchors on the final match.
PATTERNS = [
    (re.compile(SSHD + r"Failed (?P<method>[\w/-]+) for (?P<inv>invalid user )?(?P<user>.+) from "
                + IPX + r" port (?P<port>\d+)"), "failed"),
    (re.compile(SSHD + r"Accepted (?P<method>[\w/-]+) for (?P<user>.+) from "
                + IPX + r" port (?P<port>\d+)"), "accepted"),
    (re.compile(SSHD + r"Invalid user (?P<user>.*) from " + IPX + r"(?: port (?P<port>\d+))?"),
     "invalid_user"),
    (re.compile(SSHD + r"(?:Connection closed by|Disconnected from) (?:invalid|authenticating) user "
                r"(?P<user>.+) " + IPX + r" port (?P<port>\d+) \[preauth\]"), "preauth_close"),
    (re.compile(SSHD + r"(?:error: )?maximum authentication attempts exceeded for (?:invalid user )?"
                r"(?P<user>.+) from " + IPX + r" port (?P<port>\d+)"), "max_auth"),
    # scanners: connect, then drop / reset / never speak SSH
    (re.compile(SSHD + r"(?:Connection (?:closed|reset) by|Did not receive identification string from|"
                r"Unable to negotiate with) " + IPX + r" port (?P<port>\d+)"), "preauth_close"),
]
NOISE_TYPES = ("invalid_user", "preauth_close", "max_auth")


CTIME_TS = re.compile(r"^[A-Z][a-z]{2} ([A-Z][a-z]{2}) +(\d{1,2}) (\d{2}:\d{2}:\d{2}) (\d{4})\b")
APACHE_TS = re.compile(r"^\[[A-Z][a-z]{2} ([A-Z][a-z]{2}) (\d{2}) (\d{2}:\d{2}:\d{2})(?:\.\d+)? (\d{4})\]")
SLASH_TS = re.compile(r"^(\d{4})/(\d{2})/(\d{2}) (\d{2}:\d{2}:\d{2})")


def _other_ts(line):
    """vsftpd 'Mon Nov  3 10:15:01 2026', Apache error '[Mon Nov 03 10:15:01.1 2026]', nginx error '2026/11/03 10:15:01'."""
    try:
        m = CTIME_TS.match(line) or APACHE_TS.match(line)
        if m:
            mon, day, hms, year = m.groups()
            h, mi, s = map(int, hms.split(":"))
            return datetime(int(year), MONTHS[mon], int(day), h, mi, s).astimezone().astimezone(timezone.utc)
        m = SLASH_TS.match(line)
        if m:
            y, mo, d, hms = m.groups()
            h, mi, s = map(int, hms.split(":"))
            return datetime(int(y), int(mo), int(d), h, mi, s).astimezone().astimezone(timezone.utc)
    except (ValueError, KeyError):
        pass
    return None


def parse_timestamp(line):
    m = ISO_TS.match(line)
    if m:
        date, hms, frac, tz = m.groups()
        frac = "." + frac[1:7].ljust(6, "0") if frac else ""
        if tz == "Z":
            tz = "+00:00"
        elif tz and ":" not in tz:
            tz = tz[:3] + ":" + tz[3:]
        try:
            dt = datetime.fromisoformat(f"{date}T{hms}{frac}{tz or ''}")
            if dt.tzinfo is None:
                dt = dt.astimezone()
            return dt.astimezone(timezone.utc)
        except ValueError:
            pass
    dt = _other_ts(line)
    if dt:
        return dt
    m = SYSLOG_TS.match(line)
    if m:
        mon, day, hms = m.groups()
        now = datetime.now()
        try:
            h, mi, s = map(int, hms.split(":"))
            dt = datetime(now.year, MONTHS[mon], int(day), h, mi, s)
            if dt > now + timedelta(days=1):
                dt = dt.replace(year=now.year - 1)
            return dt.astimezone().astimezone(timezone.utc)
        except (ValueError, KeyError):
            pass
    return datetime.now(timezone.utc)


SERVICE_LABELS = {
    "http": "HTTP", "https": "HTTPS", "telnet": "Telnet", "ftp": "FTP", "smtp": "SMTP", "imap": "IMAP",
    "pop3": "POP3", "sieve": "ManageSieve", "mysql": "MySQL", "postgres": "PostgreSQL", "rdp": "RDP",
    "sip": "SIP", "webmin": "Webmin", "mssql": "MSSQL", "redis": "Redis", "mongodb": "MongoDB", "vnc": "VNC",
    "smb": "SMB", "ldap": "LDAP", "ldaps": "LDAPS", "snmp": "SNMP", "mqtt": "MQTT", "network": "Network",
    "oracle": "Oracle", "memcached": "Memcached", "rsync": "rsync", "irc": "IRC", "x11": "X11",
}
WEB_TYPES = ("web_attack", "probe", "web_404")
ROOT_SERVICES = ("ssh", "telnet", "ftp", "rdp")
IPC = r"[0-9a-fA-F:.]+"
IP4 = r"(?:\d{1,3}\.){3}\d{1,3}"


def _rx(pattern):
    return re.compile(pattern)


def _dovecot_service(gd):
    return {"imap": "imap", "pop3": "pop3", "submission": "smtp", "managesieve": "sieve"}[gd["proto"]]


def _pam_service(gd):
    svc = gd["svc"].lower()
    if svc.startswith("sshd"):
        return None  # sshd is parsed from its own, richer lines
    return {"login": "telnet", "vsftpd": "ftp", "proftpd": "ftp", "pure-ftpd": "ftp", "dovecot": "imap",
            "xrdp-sesman": "rdp", "xrdp": "rdp"}.get(svc, svc[:20])


# (hint substrings, service or callable(groups)->service|None, regex, event type, username if none captured)
SERVICE_PATTERNS = [
    # --- telnet (login(1) / busybox / telnetd)
    (("FAILED LOGIN",), "telnet", _rx(r"FAILED LOGIN \d+ FROM (?P<ip>" + IPC + r") FOR (?P<user>[^,\s]+)"), "failed", ""),
    (("LOGIN ON",), "telnet", _rx(r"ROOT LOGIN ON \S+ FROM (?P<ip>" + IPC + r")"), "accepted", "root"),
    (("LOGIN ON",), "telnet", _rx(r"LOGIN ON \S+ BY (?P<user>\S+) FROM (?P<ip>" + IPC + r")"), "accepted", ""),
    (("telnetd",), "telnet", _rx(r"telnetd\[\d+\]: connect from (?P<ip>" + IPC + r")"), "preauth_close", "<empty>"),
    # --- FTP (vsftpd, proftpd, pure-ftpd)
    (("LOGIN: Client",), "ftp", _rx(r'\[(?P<user>[^\]]*)\] FAIL LOGIN: Client "(?P<ip>' + IPC + r')"'), "failed", ""),
    (("LOGIN: Client",), "ftp", _rx(r'\[(?P<user>[^\]]*)\] OK LOGIN: Client "(?P<ip>' + IPC + r')"'), "accepted", ""),
    (("proftpd",), "ftp", _rx(r"\[(?P<ip>" + IPC + r")\]\)(?::| -)? USER (?P<user>\S+) \(Login failed\)"), "failed", ""),
    (("proftpd",), "ftp", _rx(r"\[(?P<ip>" + IPC + r")\]\)(?::| -)? USER (?P<user>\S+): Login successful"), "accepted", ""),
    (("pure-ftpd",), "ftp", _rx(r"\(\S*@(?P<ip>" + IPC + r")\) \[WARNING\] Authentication failed for user \[(?P<user>[^\]]*)\]"), "failed", ""),
    (("pure-ftpd",), "ftp", _rx(r"\(\S*@(?P<ip>" + IPC + r")\) \[INFO\] (?P<user>\S+) is now logged in"), "accepted", ""),
    # --- mail (postfix SASL, dovecot imap/pop3/submission)
    (("SASL",), "smtp", _rx(r"warning: \S*\[(?P<ip>" + IPC + r")\]: SASL [\w-]+ authentication failed"), "failed", "<unknown>"),
    (("Relay access denied",), "smtp", _rx(r"NOQUEUE: reject: RCPT from \S*\[(?P<ip>" + IPC + r")\]:.*Relay access denied"), "preauth_close", "<empty>"),
    (("-login:",), _dovecot_service, _rx(r"(?P<proto>imap|pop3|submission|managesieve)-login: .*?auth failed.*?user=<(?P<user>[^>]*)>.*?rip=(?P<ip>" + IPC + r")"), "failed", ""),
    (("-login:",), _dovecot_service, _rx(r"(?P<proto>imap|pop3|submission|managesieve)-login: Login: user=<(?P<user>[^>]*)>.*?rip=(?P<ip>" + IPC + r")"), "accepted", ""),
    # --- databases
    (("Access denied for user",), "mysql", _rx(r"Access denied for user '(?P<user>[^']*)'@'(?P<ip>" + IPC + r")'"), "failed", ""),
    (("FATAL:",), "postgres", _rx(r"(?P<ip>" + IP4 + r")(?:\(\d+\))?\s.*?FATAL:\s+password authentication failed for user \"(?P<user>[^\"]*)\""), "failed", ""),
    (("pg_hba.conf",), "postgres", _rx(r"no pg_hba\.conf entry for host \"(?P<ip>[^\"]+)\", user \"(?P<user>[^\"]*)\""), "failed", ""),
    # --- remote access / telephony / admin panels
    (("AUTHFAIL",), "rdp", _rx(r"AUTHFAIL: user=(?P<user>\S+) ip=(?P<ip>\S+)"), "failed", ""),
    (("AUTHSUCCESS",), "rdp", _rx(r"AUTHSUCCESS: user=(?P<user>\S+) ip=(?P<ip>\S+)"), "accepted", ""),
    (("Registration from",), "sip", _rx(r"Registration from '[^']*?sip:(?P<user>[^@>']*)@[^']*' failed for '(?P<ip>" + IP4 + r")(?::\d+)?' - (?:Wrong password|No matching peer found|Username/auth name mismatch|Device does not match ACL|Peer is not supposed to register)"), "failed", ""),
    (("Invalid login as",), "webmin", _rx(r"Invalid login as (?P<user>\S+) from (?P<ip>" + IPC + r")"), "failed", ""),
    # --- generic PAM: any daemon that authenticates through pam_unix with a remote host
    (("pam_unix(",), _pam_service, _rx(r"pam_unix\((?P<svc>[\w.\-]+):auth\): authentication failure;.*?rhost=(?P<ip>" + IPC + r")(?:\s+user=(?P<user>\S+))?"), "failed", ""),
]
ALL_PATTERNS = [(("sshd",), "ssh", rx, et, "") for rx, et in PATTERNS] + SERVICE_PATTERNS


def parse_line(line):
    """Parse one syslog-style line from any supported service. Returns an event dict or None."""
    for hints, service, rx, etype, default_user in ALL_PATTERNS:
        if not any(h in line for h in hints):
            continue
        m = rx.search(line)
        if not m:
            continue
        gd = m.groupdict()
        svc = service(gd) if callable(service) else service
        if svc is None:
            return None
        ip = norm_ip(gd["ip"])
        if not ip:
            return None
        ts = parse_timestamp(line)
        return {
            "@timestamp": ts.isoformat(),
            "event_type": etype,
            "auth_method": gd.get("method") or "",
            "username": (gd.get("user") or "").strip() or default_user or "<empty>",
            "invalid_user": bool(gd.get("inv")) or etype == "invalid_user",
            "source_ip": ip,
            "source_port": int(gd["port"]) if gd.get("port") else 0,
            "host": HOSTNAME,
            "raw": line.strip()[:500],
            "_ts": ts.timestamp(),
            "service": svc,
        }
    return None


# ==========================================================================
# Web servers (nginx / Apache access and error logs, HTTP and HTTPS)
# ==========================================================================
WEB_ACCESS = re.compile(
    r'^(?:(?P<vhost>[\w.\-]+):(?P<vport>\d+) )?(?P<ip>[0-9a-fA-F:.]+) \S+ (?P<user>\S+) '
    r'\[(?P<ts>[^\]]+)\] "(?P<req>[^"]*)" (?P<status>\d{3}) (?P<size>\S+)'
    r'(?: "(?P<ref>[^"]*)" "(?P<ua>[^"]*)")?')
WEB_REQUEST = re.compile(r"^([A-Z]{3,10}) (.*?)(?: HTTP/\d(?:\.\d)?)?$")
LOGIN_PATHS = re.compile(
    r"(?i)(?:^|/)(?:wp-login\.php|xmlrpc\.php|login(?:\.php|\.aspx|\.jsp|\.html|\.do)?|signin|sign-in|"
    r"log-in|auth(?:enticate)?|admin/login|administrator/index\.php|user/login|users/sign_in|"
    r"j_security_check|api/(?:v\d+/)?(?:login|auth|token)|session|account/login|"
    r"phpmyadmin/index\.php|manager/html)(?:[/?]|$)")
SENSITIVE_PATHS = re.compile(
    r"(?i)(?:/\.env\b|/\.git(?:/|$)|/\.svn|/\.aws|/\.ssh|/\.ds_store|/wp-config|/phpmyadmin|/pma/|/myadmin|"
    r"/cgi-bin/|/vendor/phpunit|/actuator|/server-status|/server-info|/manager/html|/solr/|/hnap1|"
    r"/boaform|/owa/|/ecp/|/autodiscover|/admin\.php|/setup\.php|/install\.php|/eval-stdin\.php|"
    r"/etc/passwd|/boot\.ini|/dump\.sql|/db\.sql|/id_rsa|/\.htpasswd|/config\.json|/web\.config)")
WEB_ATTACKS = [
    ("sql_injection", re.compile(
        r"(?i)(?:union(?:\s|\+|/\*.*?\*/)+(?:all(?:\s|\+)+)?select|select(?:\s|\+).+(?:\sfrom\s|sleep\(|benchmark\()|"
        r"'\s*or\s*'?1'?\s*=\s*'?1|\bor\s+1=1|information_schema|sleep\(\d|benchmark\(|waitfor\s+delay|;\s*drop\s+table)")),
    ("xss", re.compile(r"(?i)(?:<script|%3cscript|javascript:|onerror\s*=|onload\s*=|<svg[^>]*onload)")),
    ("path_traversal", re.compile(
        r"(?i)(?:\.\./|\.\.\\|%2e%2e[/%\\]|\.\.%2f|%252e%252e|/etc/passwd|/etc/shadow|c:\\windows|/proc/self/environ)")),
    ("command_injection", re.compile(
        r"(?i)(?:;|\|\||&&|\||`|\$\()\s*(?:cat|ls|id|whoami|uname|wget|curl|nc|bash|sh|cmd|powershell|ping)\b|"
        r"/bin/(?:ba)?sh|cmd\.exe|powershell")),
    ("log4shell", re.compile(r"(?i)\$\{(?:jndi|\$\{|lower|upper|env|sys)[:}]")),
    ("shellshock", re.compile(r"\(\)\s*\{\s*:?;?\s*\}\s*;")),
    ("php_injection", re.compile(r"(?i)(?:php://(?:input|filter)|data://text|allow_url_include|auto_prepend_file|expect://)")),
]
BAD_UA = re.compile(
    r"(?i)(?:sqlmap|nikto|nmap|masscan|zgrab|gobuster|dirbuster|dirb/|wpscan|acunetix|nessus|openvas|"
    r"metasploit|hydra|havij|w3af|nuclei|feroxbuster|ffuf|jaeles|zmeu|morfeus|fimap)")
NGX_AUTH = re.compile(r'user "(?P<user>[^"]*)"(?::\s*password mismatch| was not found in "[^"]*"),\s*client: (?P<ip>' + IPC + r")")
APA_AUTH = re.compile(r"\[client (?P<ip>" + IPC + r"?)(?::\d+)?\] (?:AH\d+: )?user (?P<user>\S+?)(?::| not found)")
TLS_ERR = re.compile(
    r"(?:SSL_do_handshake\(\) failed|SSL routines|\[ssl:(?:error|warn)\]|ssl3_get_record|tlsv1 alert|no shared cipher)"
    r".*?(?:client: |\[client )(?P<ip>" + IPC + r")")
WEB_ERROR_PATTERNS = [(NGX_AUTH, "failed", None), (APA_AUTH, "failed", None), (TLS_ERR, "preauth_close", "https")]
_CTRL = re.compile(r"[\x00-\x1f\x7f]")


WEB_TS = re.compile(r"(\d{2})/([A-Za-z]{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2}) ([+-])(\d{2})(\d{2})")


def _parse_web_ts(s):
    """'03/Nov/2026:10:15:01 +0530' -> aware UTC datetime. Independent of the process locale."""
    m = WEB_TS.match(s)
    if not m:
        raise ValueError("bad web timestamp")
    d, mon, y, h, mi, sec, sign, oh, om = m.groups()
    offset = timedelta(minutes=(1 if sign == "+" else -1) * (int(oh) * 60 + int(om)))
    return datetime(int(y), MONTHS[mon.capitalize()], int(d), int(h), int(mi), int(sec),
                    tzinfo=timezone(offset)).astimezone(timezone.utc)


def _web_event(ts, etype, ip, username, service, line, method="", detail="", category="", status=0, ua=""):
    return {
        "@timestamp": ts.isoformat(), "event_type": etype, "auth_method": method, "username": username,
        "invalid_user": False, "source_ip": ip, "source_port": 0, "host": HOSTNAME,
        "raw": _CTRL.sub("?", line.strip()[:500]), "_ts": ts.timestamp(), "service": service,
        "detail": _CTRL.sub("?", detail)[:200], "category": category, "http_status": status, "user_agent": _CTRL.sub("?", ua),
    }


def _parse_web_error(line, default_service):
    if "client" not in line:
        return None
    for rx, etype, service in WEB_ERROR_PATTERNS:
        m = rx.search(line)
        if not m:
            continue
        ip = norm_ip(m.group("ip"))
        if not ip:
            return None
        user = m.groupdict().get("user") or "<n/a>"
        return _web_event(parse_timestamp(line), etype, ip, user, service or default_service, line,
                          category="tls_error" if etype == "preauth_close" else "basic_auth")
    return None


def parse_web_line(line, default_service="http"):
    """Parse an nginx/Apache access or error log line into an event (or None if uninteresting)."""
    m = WEB_ACCESS.match(line)
    if not m:
        return _parse_web_error(line, default_service)
    ip = norm_ip(m.group("ip"))
    if not ip:
        return None
    try:
        ts = _parse_web_ts(m.group("ts"))
    except (ValueError, KeyError):
        ts = datetime.now(timezone.utc)
    rm = WEB_REQUEST.match(m.group("req"))
    method, target = (rm.group(1), rm.group(2)) if rm else ("", m.group("req"))
    status = int(m.group("status"))
    ua = (m.group("ua") or "")[:200]
    decoded = unquote(unquote(target))[:500]
    service = "https" if m.group("vport") in ("443", "8443") else default_service
    user = m.group("user")
    category = next((name for name, rx in WEB_ATTACKS
                     if rx.search(decoded) or (name in ("log4shell", "shellshock") and rx.search(ua))), None)
    username = "<n/a>"
    if category:
        etype = "web_attack"
    elif status == 401:
        etype, username = "failed", (user if user != "-" else "<none>")
    elif method == "POST" and LOGIN_PATHS.search(decoded) and status in (200, 401, 403, 429):
        etype, username, category = "failed", "<form login>", "login_post"
    elif SENSITIVE_PATHS.search(decoded):
        etype, category = "probe", "sensitive_path"
    elif BAD_UA.search(ua):
        etype, category = "probe", "scanner_ua"
    elif status in (400, 403, 404, 405, 414, 444):
        etype = "web_404"
    else:
        return None
    return _web_event(ts, etype, ip, username, service, line, method, f"{method} {decoded}".strip(),
                      category or "", status, ua)


# ==========================================================================
# Log sources: user-defined, auto-detected, journald
# ==========================================================================
SOURCE_KINDS = {"syslog": "syslog", "auth": "syslog", "web": "web", "http": "web", "nginx": "web",
                "apache": "web", "https": "web-https"}
AUTO_SOURCES = [
    ("web", "/var/log/nginx/access.log"), ("web", "/var/log/nginx/error.log"),
    ("web-https", "/var/log/nginx/ssl_access.log"),
    ("web", "/var/log/apache2/access.log"), ("web", "/var/log/apache2/error.log"),
    ("web-https", "/var/log/apache2/ssl_access.log"),
    ("web", "/var/log/httpd/access_log"), ("web", "/var/log/httpd/error_log"),
    ("web-https", "/var/log/httpd/ssl_access_log"), ("web", "/var/log/httpd/ssl_error_log"),
    ("syslog", "/var/log/vsftpd.log"), ("syslog", "/var/log/proftpd/proftpd.log"),
    ("syslog", "/var/log/mail.log"), ("syslog", "/var/log/maillog"),
    ("syslog", "/var/log/daemon.log"), ("syslog", "/var/log/messages"), ("syslog", "/var/log/secure"),
    ("syslog", "/var/log/mysql/error.log"), ("syslog", "/var/log/mysqld.log"),
    ("syslog", "/var/log/mariadb/mariadb.log"), ("syslog", "/var/log/xrdp-sesman.log"),
    ("syslog", "/var/log/asterisk/messages"),
]
JOURNAL_IDS = ("sshd", "sshd-session", "login", "telnetd", "in.telnetd", "vsftpd", "proftpd", "pure-ftpd",
               "postfix/smtpd", "dovecot", "xrdp-sesman", "mysqld", "mariadbd", "asterisk", "webmin")


def parse_sources(text, log=lambda m: None):
    """'web=/var/log/nginx/access.log; https=/var/log/x/ssl.log; syslog=/var/log/vsftpd.log'"""
    out = []
    for entry in re.split(r"[;\n]+", text or ""):
        entry = entry.strip()
        if not entry:
            continue
        kind, sep, path = entry.partition("=")
        kind, path = kind.strip().lower(), path.strip()
        if not sep or kind not in SOURCE_KINDS or not path:
            log(f"Ignoring log source '{entry[:60]}' (format kind=path; kinds: syslog, web, https)")
            continue
        norm = SOURCE_KINDS[kind]
        if norm == "web" and re.search(r"ssl|https", os.path.basename(path), re.I):
            norm = "web-https"
        out.append((norm, path))
    return out


def discover_sources(log=lambda m: None):
    """Standard service logs that exist on this machine."""
    import glob
    found, unreadable = [], []
    candidates = list(AUTO_SOURCES)
    candidates += [("syslog", p) for p in sorted(glob.glob("/var/log/postgresql/postgresql-*.log"))]
    for kind, path in candidates:
        if not os.path.isfile(path):
            continue
        (found if os.access(path, os.R_OK) else unreadable).append((kind, path))
    if unreadable:
        log("Found but cannot read (add your user to the 'adm' group or run with sudo): "
            + ", ".join(p for _, p in unreadable[:6]))
    return found


_OVERRIDES = {}


def parse_overrides(text):
    """'http=10,https=10,telnet=3' -> {'http': 10, ...} (per-service failure thresholds)."""
    d = _OVERRIDES.get(text)
    if d is None:
        d = {}
        for tok in re.split(r"[,\s;]+", (text or "").strip()):
            k, _, v = tok.partition("=")
            if k and v.isdigit() and int(v) > 0:
                d[k.strip().lower()] = int(v)
        _OVERRIDES[text] = d
    return d


# ==========================================================================
# GeoIP: minimal MaxMind DB (.mmdb) reader, no dependencies
# ==========================================================================
LOCAL_LABEL = "Local/reserved"


class GeoIP:
    MARKER = b"\xab\xcd\xefMaxMind.com"

    def __init__(self, path):
        with open(path, "rb") as f:
            self.buf = f.read()
        i = self.buf.rfind(self.MARKER)
        if i < 0:
            raise ValueError("not a MaxMind DB file")
        start = i + len(self.MARKER)
        meta, _ = self._decode(start, start)
        self.node_count = meta["node_count"]
        self.rec = meta["record_size"]
        self.ipv = meta["ip_version"]
        if self.rec not in (24, 28, 32):
            raise ValueError(f"unsupported record size {self.rec}")
        self.node_bytes = self.rec // 4
        self.tree_size = self.node_count * self.node_bytes
        self.data_start = self.tree_size + 16
        self.cache = {}
        self._v4_node = None

    def _decode(self, off, base, depth=0):
        if depth > 16:
            raise ValueError("corrupt database (pointer loop)")
        b = self.buf
        ctrl = b[off]
        off += 1
        typ = ctrl >> 5
        if typ == 1:  # pointer
            ss, vvv = (ctrl >> 3) & 3, ctrl & 7
            if ss == 0:
                ptr = (vvv << 8) | b[off]
                off += 1
            elif ss == 1:
                ptr = ((vvv << 16) | int.from_bytes(b[off:off + 2], "big")) + 2048
                off += 2
            elif ss == 2:
                ptr = ((vvv << 24) | int.from_bytes(b[off:off + 3], "big")) + 526336
                off += 3
            else:
                ptr = int.from_bytes(b[off:off + 4], "big")
                off += 4
            val, _ = self._decode(base + ptr, base, depth + 1)
            return val, off
        if typ == 0:  # extended type
            typ = 7 + b[off]
            off += 1
        size = ctrl & 0x1F
        if size == 29:
            size = 29 + b[off]
            off += 1
        elif size == 30:
            size = 285 + int.from_bytes(b[off:off + 2], "big")
            off += 2
        elif size == 31:
            size = 65821 + int.from_bytes(b[off:off + 3], "big")
            off += 3
        if typ == 7:  # map
            m = {}
            for _ in range(size):
                k, off = self._decode(off, base, depth + 1)
                v, off = self._decode(off, base, depth + 1)
                m[k] = v
            return m, off
        if typ == 11:  # array
            arr = []
            for _ in range(size):
                v, off = self._decode(off, base, depth + 1)
                arr.append(v)
            return arr, off
        if typ == 14:  # boolean (value lives in the size field)
            return bool(size), off
        data = b[off:off + size]
        off += size
        if typ == 2:
            return data.decode("utf-8", "replace"), off
        if typ in (5, 6, 9, 10):
            return int.from_bytes(data, "big"), off
        if typ == 8:  # int32
            n = int.from_bytes(data, "big")
            return (n - (1 << 32) if size == 4 and n >= (1 << 31) else n), off
        if typ == 3 and size == 8:
            return struct.unpack(">d", data)[0], off
        if typ == 15 and size == 4:
            return struct.unpack(">f", data)[0], off
        if typ == 4:
            return bytes(data), off
        return None, off

    def _node(self, node, bit):
        b, o = self.buf, node * self.node_bytes
        if self.rec == 24:
            s = o + bit * 3
            return int.from_bytes(b[s:s + 3], "big")
        if self.rec == 28:
            if bit == 0:
                return ((b[o + 3] & 0xF0) << 20) | int.from_bytes(b[o:o + 3], "big")
            return ((b[o + 3] & 0x0F) << 24) | int.from_bytes(b[o + 4:o + 7], "big")
        s = o + bit * 4
        return int.from_bytes(b[s:s + 4], "big")

    def _v4_start(self):
        if self._v4_node is None:
            node = 0
            for _ in range(96):
                if node >= self.node_count:
                    break
                node = self._node(node, 0)
            self._v4_node = node
        return self._v4_node

    def lookup(self, ip):
        if ip in self.cache:
            return self.cache[ip]
        try:
            res = self._lookup(ip)
        except (ValueError, IndexError, KeyError):
            res = {}
        if len(self.cache) > 20000:
            self.cache.clear()
        self.cache[ip] = res
        return res

    def _lookup(self, ip):
        a = ipaddress.ip_address(ip)
        if self.ipv == 4 and a.version == 6:
            return {}
        packed = a.packed
        node = self._v4_start() if (self.ipv == 6 and a.version == 4) else 0
        for i in range(len(packed) * 8):
            if node >= self.node_count:
                break
            node = self._node(node, (packed[i >> 3] >> (7 - (i & 7))) & 1)
        if node > self.node_count:
            val, _ = self._decode(node - self.node_count + self.tree_size, self.data_start)
            return val if isinstance(val, dict) else {}
        return {}


def geo_fields(rec):
    """Turn a GeoLite2/DB-IP record into event fields. '_geo' is the short display label."""
    if not rec:
        return {}
    c = rec.get("country") or rec.get("registered_country") or {}
    iso = c.get("iso_code", "")
    name = (c.get("names") or {}).get("en", "")
    city = ((rec.get("city") or {}).get("names") or {}).get("en", "")
    out = {"_geo": f"{name} ({iso})" if name and iso else (name or iso)}
    if iso:
        out["country_iso"] = iso
    if name:
        out["country"] = name
    if city:
        out["city"] = city
    if isinstance(rec.get("autonomous_system_number"), int):
        out["asn"] = rec["autonomous_system_number"]
    if rec.get("autonomous_system_organization"):
        out["as_org"] = str(rec["autonomous_system_organization"])[:100]
    return out


# ==========================================================================
# Detector (only ever touched from one thread)
# ==========================================================================
class Detector:
    def __init__(self, cfg, allow_nets, service="ssh"):
        self.cfg = cfg
        self.service = service
        self.allow = allow_nets          # shared list; may grow at runtime
        self.fails = defaultdict(deque)  # ip   -> deque[(ts, user)]
        self.target = defaultdict(deque)  # user -> deque[(ts, ip)]
        self.noise = defaultdict(int)    # ip   -> invalid/preauth count
        self.cool = {}
        self.n = 0
        self.invalid_q = defaultdict(deque)  # ip -> (ts, username) of non-existent users
        self.scan_q = defaultdict(deque)     # ip -> (ts, '') pre-auth drops
        self.bonus = defaultdict(int)        # ip -> extra risk (threat feed hits)

    # -- helpers
    @staticmethod
    def _prune(dq, cutoff):
        while dq and dq[0][0] < cutoff:
            dq.popleft()

    def _cool(self, key, ts, span):
        last = self.cool.get(key)
        if last is not None and ts - last < span:
            return False
        self.cool[key] = ts
        return True

    @property
    def thr(self):
        """Failure threshold for this service (global value unless overridden, e.g. http=10)."""
        return parse_overrides(self.cfg.thresholds_override).get(self.service, self.cfg.threshold)

    def fast_count(self, ip, ts):
        dq = self.fails.get(ip)
        return sum(1 for t, _ in dq if ts - t <= self.cfg.window) if dq else 0

    def risk(self, ip):
        dq = self.fails.get(ip)
        if not dq:
            return min(100, self.noise.get(ip, 0) + self.bonus.get(ip, 0))
        ts = dq[-1][0]
        fast = sum(1 for t, _ in dq if ts - t <= self.cfg.window)
        users = {u for _, u in dq}
        score = (fast / max(1, self.thr)) * 40 + min(len(dq), 100) * 0.3 \
            + len(users) * 4 + (15 if "root" in users else 0) + min(self.noise.get(ip, 0), 20) \
            + self.bonus.get(ip, 0)
        return int(min(100, score))

    def _alert(self, ev, typ, sev, attempts, window, users, note="", target=""):
        return {
            "@timestamp": ev["@timestamp"], "alert_type": typ, "severity": sev,
            "source_ip": ev["source_ip"], "attempts": attempts, "window_seconds": window,
            "usernames": users[:20], "target_user": target,
            "risk_score": self.risk(ev["source_ip"]), "host": HOSTNAME, "note": note,
            "country": ev.get("_geo", ""),
            "service": ev.get("service") or self.service,
            "_ts": ev["_ts"],
        }

    def extra_alert(self, ev, typ, sev, note="", span=3600, target=""):
        """Stateless rule alert (canary users, root login, feeds...). Allowlist + cooldown applied."""
        ip = ev["source_ip"]
        if is_allowed(ip, self.allow) or not self._cool((ip, typ), ev["_ts"], span):
            return None
        return self._alert(ev, typ, sev, 1, span, [ev["username"]], note, target)

    def _gc(self, ts):
        for store, span in ((self.fails, self.cfg.slow_window),
                            (self.target, self.cfg.distributed_window),
                            (self.invalid_q, self.cfg.window),
                            (self.scan_q, self.cfg.window)):
            for k in list(store):
                self._prune(store[k], ts - span)
                if not store[k]:
                    del store[k]
        if len(self.noise) > 50000:
            self.noise.clear()
        if len(self.bonus) > 50000:
            self.bonus.clear()
        for k in [k for k, t in self.cool.items() if ts - t > self.cfg.slow_window]:
            del self.cool[k]

    # -- main entry
    def process(self, ev):
        cfg = self.cfg
        ip, ts, et = ev["source_ip"], ev["_ts"], ev["event_type"]
        self.n += 1
        if self.n % 5000 == 0:
            self._gc(ts)

        if et in NOISE_TYPES:
            self.noise[ip] += 1
            if is_allowed(ip, self.allow):
                return []
            out = []
            if et == "invalid_user":
                dq = self.invalid_q[ip]
                dq.append((ts, ev["username"]))
                self._prune(dq, ts - cfg.window)
                users = sorted({u for _, u in dq})
                if len(users) >= cfg.enum_users and self._cool((ip, "enum"), ts, cfg.window):
                    out.append(self._alert(ev, "user_enumeration", "medium", len(dq), cfg.window, users,
                                           note=f"{len(users)} distinct non-existent usernames"))
            else:
                dq = self.scan_q[ip]
                dq.append((ts, ""))
                self._prune(dq, ts - cfg.window)
                if len(dq) >= cfg.scan_threshold and self._cool((ip, "scan"), ts, cfg.window):
                    out.append(self._alert(ev, "ssh_scanner", "medium", len(dq), cfg.window,
                                           [ev["username"]],
                                           note="many connections dropped before authentication"))
            return out

        allowed = is_allowed(ip, self.allow)
        out = []

        if et == "failed":
            user = ev["username"]
            dq = self.fails[ip]
            dq.append((ts, user))
            self._prune(dq, ts - cfg.slow_window)
            tq = self.target[user]
            tq.append((ts, ip))
            self._prune(tq, ts - cfg.distributed_window)
            if allowed:
                return []

            fast = [(t, u) for t, u in dq if ts - t <= cfg.window]
            if len(fast) >= self.thr and self._cool((ip, "fast"), ts, cfg.window):
                users = sorted({u for _, u in fast})
                spray = len(users) >= cfg.spray_users
                out.append(self._alert(ev, "password_spray" if spray else "brute_force", "high",
                                       len(fast), cfg.window, users))
            elif len(dq) >= cfg.slow_threshold and self._cool((ip, "slow"), ts, cfg.slow_window):
                out.append(self._alert(ev, "slow_brute_force", "medium", len(dq), cfg.slow_window,
                                       sorted({u for _, u in dq})))

            ips = {i for _, i in tq}
            if len(ips) >= cfg.distributed_ips and self._cool((user, "dist"), ts, cfg.distributed_window):
                out.append(self._alert(ev, "distributed_attack", "high", len(tq),
                                       cfg.distributed_window, [user],
                                       note=f"{len(ips)} distinct IPs targeting '{user}'", target=user))

        elif et == "accepted":
            dq = self.fails.get(ip)
            if dq and not allowed:
                span = max(cfg.window, 300)
                recent = [(t, u) for t, u in dq if ts - t <= span]
                if len(recent) >= 3 and self._cool((ip, "compromise"), ts, span):
                    out.append(self._alert(
                        ev, "possible_compromise", "critical", len(recent), span,
                        sorted({u for _, u in recent} | {ev["username"]}),
                        note=f"Successful login as '{ev['username']}' after {len(recent)} failures",
                        target=ev["username"]))
            if dq:
                dq.clear()
        return out


class WebDetector(Detector):
    """Stateful rules for web events: attack signatures, probing of sensitive paths, error floods."""

    def __init__(self, cfg, allow_nets):
        super().__init__(cfg, allow_nets, "http")
        self.probe_q = defaultdict(deque)
        self.miss_q = defaultdict(deque)

    def _gc(self, ts):
        super()._gc(ts)
        for store in (self.probe_q, self.miss_q):
            for k in list(store):
                self._prune(store[k], ts - self.cfg.window)
                if not store[k]:
                    del store[k]

    def process_web(self, ev):
        cfg, ip, ts, et = self.cfg, ev["source_ip"], ev["_ts"], ev["event_type"]
        self.n += 1
        if self.n % 5000 == 0:
            self._gc(ts)
        if is_allowed(ip, self.allow):
            return []
        out, cat = [], ev.get("category", "")
        who = [(ev.get("detail") or ev["username"])[:60]]
        if et == "web_attack":
            self.noise[ip] += 40
            if cfg.web_attack_alerts and self._cool((ip, "web_attack", cat), ts, 600):
                out.append(self._alert(ev, "web_attack", "medium" if cat == "xss" else "high", 1, 600, who,
                                       note=f"{cat}: {ev.get('detail', '')[:100]}"))
        elif et == "probe":
            self.noise[ip] += 8
            if cat == "scanner_ua" and self._cool((ip, "bad_ua"), ts, 3600):
                out.append(self._alert(ev, "bad_user_agent", "medium", 1, 3600, who,
                                       note=f"scanner user-agent: {ev.get('user_agent', '')[:80]}"))
            dq = self.probe_q[ip]
            dq.append((ts, ""))
            self._prune(dq, ts - cfg.window)
            if len(dq) >= cfg.web_probe_threshold and self._cool((ip, "web_probe"), ts, cfg.window):
                out.append(self._alert(ev, "web_probe", "medium", len(dq), cfg.window, who,
                                       note=f"{len(dq)} probes for sensitive paths / scanner user-agents"))
        elif et == "web_404":
            self.noise[ip] += 1
            dq = self.miss_q[ip]
            dq.append((ts, ""))
            self._prune(dq, ts - cfg.window)
            if len(dq) >= cfg.web_scan_threshold and self._cool((ip, "web_scanner"), ts, cfg.window):
                out.append(self._alert(ev, "web_scanner", "medium", len(dq), cfg.window, who,
                                       note=f"{len(dq)} error responses (404/403/400...) in {cfg.window}s"))
        return out


def _net_event(ts, etype, ip, username, service, raw, cport=0, dport=0, method="", detail="", category="",
               status=0, ua=""):
    """Event from the network sensor: same shape as a log event, plus the ports it was seen on."""
    ev = _web_event(datetime.fromtimestamp(ts, timezone.utc), etype, ip,
                    _CTRL.sub("?", str(username))[:64] or "<empty>", service, raw, method, detail, category, status, ua)
    ev["source_port"], ev["dest_port"], ev["capture"] = cport, dport, "network"
    return ev


class NetDetector(Detector):
    """Rules that only need packet headers: connection-rate brute force, floods and port scans.

    Encrypted or binary protocols (SSH, RDP, VNC, SMB, TLS mail ...) never show a failed login on the wire, but
    a password guesser has to open a new connection for almost every guess - so many connections to one
    login service from one address inside the window is reported as 'conn_brute_force'.
    """

    def __init__(self, cfg, allow_nets, annotate=None):
        super().__init__(cfg, allow_nets, "network")
        self.annotate = annotate or (lambda ev: None)
        self.rate_q = defaultdict(deque)   # (ip, service) -> deque[(ts, '')]
        self.port_q = defaultdict(deque)   # ip -> deque[(ts, (dst, port))]
        self.k = 0

    def _gc_net(self, ts):
        for store in (self.rate_q, self.port_q):
            for key in list(store):
                self._prune(store[key], ts - self.cfg.window)
                if not store[key]:
                    del store[key]

    def _build(self, ts, ip, svc, port, text):
        ev = _net_event(ts, "conn", ip, "<n/a>", svc, text, 0, port)
        self.annotate(ev)
        return ev

    def syn(self, ts, ip, dst, port, svc, parser, stealth=False):
        """One new connection attempt (TCP SYN / odd-flag probe / UDP datagram) from `ip` to dst:port.

        svc/parser describe the service on that port (None when the port is not a known service).
        Returns a list of (event, [alerts]) - empty almost always, so the hot path stays cheap."""
        cfg = self.cfg
        self.k += 1
        if self.k % 5000 == 0:
            self._gc(ts)
            self._gc_net(ts)
        if is_allowed(ip, self.allow):
            return []
        out = []
        # --- port scan: many distinct (host, port) targets from one source
        pq = self.port_q[ip]
        pq.append((ts, (dst, port)))
        self._prune(pq, ts - cfg.window)
        if len(pq) >= cfg.net_scan_ports:
            hits = {k for _, k in pq}
            for sev, mult in (("high", 3), ("medium", 1)):
                if len(hits) >= cfg.net_scan_ports * mult and self._cool((ip, "pscan", sev), ts, cfg.window):
                    ports = sorted({p for _, p in hits})
                    ev = self._build(ts, ip, "network", port,
                                     f"[net] {ip} probed {len(hits)} targets in {cfg.window}s")
                    self.noise[ip] = max(self.noise[ip], 30 if sev == "medium" else 60)
                    out.append((ev, [self._alert(
                        ev, "port_scan", sev, len(pq), cfg.window, [str(p) for p in ports[:12]],
                        note=f"{len(hits)} distinct ports/hosts probed" + (" (incl. stealth flags)" if stealth else "")
                             + f" - e.g. {', '.join(map(str, ports[:8]))}")]))
                    break
        # --- connection rate to one service
        if svc and not stealth:
            auth = parser in ("conn", "tls") and svc != "https"
            thr = parse_overrides(cfg.net_rate_override).get(
                svc, cfg.net_conn_threshold if auth else cfg.net_flood_threshold)
            rq = self.rate_q[(ip, svc)]
            rq.append((ts, ""))
            self._prune(rq, ts - cfg.window)
            n = len(rq)
            if n >= thr:
                for sev, mult in (("high", 3), ("medium", 1)):
                    if n >= thr * mult and self._cool((ip, "rate", svc, sev), ts, cfg.window):
                        typ = "conn_brute_force" if auth else "connection_flood"
                        ev = self._build(ts, ip, svc, port, f"[net] {n} connections to {svc}:{port} in {cfg.window}s")
                        self.noise[ip] = max(self.noise[ip], 30 if sev == "medium" else 60)
                        note = (f"{n} connections to {svc} in {cfg.window}s - login guessing inferred from the "
                                "connection rate (the protocol is encrypted/binary)" if auth else
                                f"{n} connections to {svc} in {cfg.window}s")
                        out.append((ev, [self._alert(ev, typ, sev, n, cfg.window, [f"{svc}:{port}"], note=note)]))
                        break
        return out


# ==========================================================================
# SQLite store
# ==========================================================================
class Store:
    def __init__(self, path=DB_PATH):
        if path != ":memory:":
            os.makedirs(os.path.dirname(path), exist_ok=True)
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.lock = threading.Lock()
        self._pending = 0
        self._inserted = 0
        with self.lock:
            self.db.executescript("""
                CREATE TABLE IF NOT EXISTS alerts(
                    id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, type TEXT, severity TEXT,
                    ip TEXT, attempts INTEGER, risk INTEGER, who TEXT, note TEXT,
                    status TEXT DEFAULT '', country TEXT DEFAULT '', service TEXT DEFAULT 'ssh');
                CREATE TABLE IF NOT EXISTS blocks(
                    ip TEXT PRIMARY KEY, blocked_at REAL, expires_at REAL, reason TEXT,
                    dry_run INTEGER, backend TEXT);
                CREATE TABLE IF NOT EXISTS attempts(
                    id INTEGER PRIMARY KEY AUTOINCREMENT, ts_epoch REAL, ts TEXT, ip TEXT,
                    username TEXT, kind TEXT, result TEXT, attempts INTEGER, method TEXT,
                    country TEXT DEFAULT '', service TEXT DEFAULT 'ssh');
                CREATE INDEX IF NOT EXISTS idx_attempts_ts ON attempts(ts_epoch);
                CREATE TABLE IF NOT EXISTS offenders(
                    ip TEXT PRIMARY KEY, first_seen REAL, last_seen REAL,
                    alerts INTEGER DEFAULT 0, blocks INTEGER DEFAULT 0);
                CREATE TABLE IF NOT EXISTS known_logins(
                    user TEXT, ip TEXT, first_seen REAL, last_seen REAL, n INTEGER DEFAULT 1,
                    PRIMARY KEY(user, ip));
            """)
            for table, col in (("alerts", "status"), ("alerts", "country"), ("attempts", "country"),
                               ("alerts", "service"), ("attempts", "service")):
                cols = [r[1] for r in self.db.execute(f"PRAGMA table_info({table})")]
                if col not in cols:  # database created by an older version
                    default = "'ssh'" if col == "service" else "''"
                    self.db.execute(f"ALTER TABLE {table} ADD COLUMN {col} TEXT DEFAULT {default}")
            self.db.commit()

    # -- alerts (row order: ts, severity, type, ip, attempts, risk, who, status, note)
    def add_alert(self, al):
        who = al["target_user"] or ",".join(al["usernames"][:4])
        with self.lock:
            self.db.execute(
                "INSERT INTO alerts(ts,type,severity,ip,attempts,risk,who,note,status,country,service) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (al["@timestamp"], al["alert_type"], al["severity"], al["source_ip"],
                 al["attempts"], al["risk_score"], who, al["note"], al.get("status", ""),
                 al.get("country", ""), al.get("service", "ssh")))
            self.db.commit()
            self._pending = 0

    def recent_alerts(self, limit=300):
        with self.lock:
            rows = self.db.execute(
                "SELECT ts,severity,type,ip,country,service,attempts,risk,who,status,note FROM alerts "
                "ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return rows[::-1]

    # -- login attempts log
    def add_attempt(self, ts_epoch, ts, ip, user, kind, result, attempts, method, country="", service="ssh"):
        with self.lock:
            self.db.execute(
                "INSERT INTO attempts(ts_epoch,ts,ip,username,kind,result,attempts,method,country,service) "
                "VALUES(?,?,?,?,?,?,?,?,?,?)",
                (ts_epoch, ts, ip, user, kind, result, attempts, method, country, service))
            self._pending += 1
            self._inserted += 1
            if self._inserted % 5000 == 0:  # keep the table bounded
                self.db.execute("DELETE FROM attempts WHERE id < "
                                "(SELECT MAX(id) FROM attempts) - 200000")
            if self._pending >= 100:
                self.db.commit()
                self._pending = 0

    def flush(self):
        with self.lock:
            self.db.commit()
            self._pending = 0

    def recent_attempts(self, limit=200):
        """Newest first: (time, ip, username, result, attempts)."""
        with self.lock:
            rows = self.db.execute(
                "SELECT ts,ip,username,result,attempts,country,service FROM attempts "
                "ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return [(r[0][:19].replace("T", " "),) + tuple(r[1:]) for r in rows]

    # -- blocks
    def add_block(self, ip, at, exp, reason, dry, backend):
        with self.lock:
            self.db.execute("INSERT OR REPLACE INTO blocks VALUES(?,?,?,?,?,?)",
                            (ip, at, exp, reason, int(dry), backend))
            self.db.commit()

    def remove_block(self, ip):
        with self.lock:
            self.db.execute("DELETE FROM blocks WHERE ip=?", (ip,))
            self.db.commit()

    def is_blocked(self, ip):
        with self.lock:
            return self.db.execute("SELECT 1 FROM blocks WHERE ip=?", (ip,)).fetchone() is not None

    def active_blocks(self):
        with self.lock:
            return self.db.execute(
                "SELECT ip,blocked_at,expires_at,reason,dry_run,backend FROM blocks "
                "ORDER BY blocked_at DESC").fetchall()

    def expired_blocks(self, now):
        with self.lock:
            return self.db.execute(
                "SELECT ip,dry_run,backend FROM blocks WHERE expires_at>0 AND expires_at<=?",
                (now,)).fetchall()

    def count_blocks(self):
        with self.lock:
            return self.db.execute("SELECT COUNT(*) FROM blocks").fetchone()[0]

    # -- offender history and login baseline
    def offender_alert(self, ip, ts):
        with self.lock:
            self.db.execute(
                "INSERT INTO offenders(ip,first_seen,last_seen,alerts) VALUES(?,?,?,1) "
                "ON CONFLICT(ip) DO UPDATE SET last_seen=excluded.last_seen, alerts=alerts+1",
                (ip, ts, ts))
            self._pending += 1

    def offender_block(self, ip):
        now = time.time()
        with self.lock:
            self.db.execute(
                "INSERT INTO offenders(ip,first_seen,last_seen,blocks) VALUES(?,?,?,1) "
                "ON CONFLICT(ip) DO UPDATE SET last_seen=excluded.last_seen, blocks=blocks+1",
                (ip, now, now))
            self.db.commit()
            self._pending = 0

    def ban_count(self, ip):
        with self.lock:
            r = self.db.execute("SELECT blocks FROM offenders WHERE ip=?", (ip,)).fetchone()
        return r[0] if r else 0

    def add_known_login(self, user, ip, ts):
        with self.lock:
            self.db.execute(
                "INSERT INTO known_logins(user,ip,first_seen,last_seen) VALUES(?,?,?,?) "
                "ON CONFLICT(user,ip) DO UPDATE SET last_seen=excluded.last_seen, n=n+1",
                (user, ip, ts, ts))
            self._pending += 1

    def login_known(self, user, ip):
        with self.lock:
            return self.db.execute("SELECT 1 FROM known_logins WHERE user=? AND ip=?",
                                   (user, ip)).fetchone() is not None

    def user_has_logins(self, user):
        with self.lock:
            return self.db.execute("SELECT 1 FROM known_logins WHERE user=? LIMIT 1",
                                   (user,)).fetchone() is not None

    def ip_trusted(self, ip, before_ts):
        """True if this IP logged in successfully at or before before_ts (i.e. before the attack)."""
        with self.lock:
            return self.db.execute("SELECT 1 FROM known_logins WHERE ip=? AND first_seen<=? LIMIT 1",
                                   (ip, before_ts)).fetchone() is not None

    # -- analytics for reports and the web dashboard
    def report_data(self, hours):
        since = time.time() - hours * 3600
        since_iso = datetime.fromtimestamp(since, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")
        bucket = 3600 if hours <= 72 else 86400

        def q(sql, *args):
            return self.db.execute(sql, args).fetchall()

        with self.lock:
            self.db.commit()
            self._pending = 0
            failed = q("SELECT COUNT(*) FROM attempts WHERE kind='failed' AND ts_epoch>=?", since)[0][0]
            accepted = q("SELECT COUNT(*) FROM attempts WHERE kind='accepted' AND ts_epoch>=?", since)[0][0]
            uniq = q("SELECT COUNT(DISTINCT ip) FROM attempts WHERE kind IN ('failed','web_attack','probe') AND ts_epoch>=?", since)[0][0]
            top_ips = q("SELECT ip, COUNT(*), COUNT(DISTINCT username), MIN(ts_epoch), MAX(ts_epoch), MAX(country) "
                        "FROM attempts WHERE kind IN ('failed','web_attack','probe') AND ts_epoch>=? GROUP BY ip "
                        "ORDER BY COUNT(*) DESC LIMIT 10", since)
            top_users = q("SELECT username, COUNT(*) FROM attempts WHERE kind='failed' AND ts_epoch>=? "
                          "GROUP BY username ORDER BY COUNT(*) DESC LIMIT 10", since)
            top_countries = q(
                "SELECT country, COUNT(*), COUNT(DISTINCT ip) FROM attempts WHERE kind IN ('failed','web_attack','probe') "
                "AND ts_epoch>=? AND country!='' AND country!='Local/reserved' "
                "GROUP BY country ORDER BY COUNT(*) DESC LIMIT 10", since)
            svc_events = q("SELECT service, COUNT(*) FROM attempts WHERE kind IN ('failed','web_attack','probe') "
                           "AND ts_epoch>=? GROUP BY service", since)
            svc_alerts = q("SELECT service, COUNT(*) FROM alerts WHERE ts>=? GROUP BY service", since_iso)
            by_service = {}
            for name, n in svc_events:
                by_service.setdefault(name or "ssh", [0, 0])[0] = n
            for name, n in svc_alerts:
                by_service.setdefault(name or "ssh", [0, 0])[1] = n
            repeat = q("SELECT ip, alerts, blocks, first_seen, last_seen FROM offenders "
                       "WHERE alerts>=2 AND last_seen>=? ORDER BY blocks DESC, alerts DESC LIMIT 10", since)
            timeline = q("SELECT CAST(ts_epoch/? AS INTEGER) AS b, COUNT(*) FROM attempts "
                         "WHERE kind='failed' AND ts_epoch>=? GROUP BY b ORDER BY b", bucket, since)
            by_type = q("SELECT type, COUNT(*) FROM alerts WHERE ts>=? GROUP BY type "
                        "ORDER BY COUNT(*) DESC", since_iso)
            by_sev = q("SELECT severity, COUNT(*) FROM alerts WHERE ts>=? GROUP BY severity", since_iso)
            alerts = q("SELECT ts,severity,type,ip,country,service,attempts,risk,who,status,note FROM alerts "
                       "WHERE ts>=? ORDER BY id DESC LIMIT 50", since_iso)
            blocks = q("SELECT ip,blocked_at,expires_at,reason,dry_run,backend FROM blocks "
                       "ORDER BY blocked_at DESC LIMIT 50")
        return {
            "hours": hours, "generated": datetime.now(timezone.utc).isoformat()[:19],
            "host": HOSTNAME, "failed": failed, "accepted": accepted, "unique_ips": uniq,
            "top_ips": top_ips, "top_users": top_users, "top_countries": top_countries, "repeat_offenders": repeat, "by_service": by_service, "timeline": timeline, "bucket": bucket,
            "alerts_by_type": by_type, "alerts_by_severity": dict(by_sev),
            "alerts": alerts, "blocks": blocks,
        }

    def close(self):
        with self.lock:
            self.db.commit()
            self.db.close()


# ==========================================================================
# Blocker (iptables / nftables)
# ==========================================================================
class Blocker:
    def __init__(self, cfg, store, allow_nets, log):
        self.cfg, self.store, self.allow, self.log = cfg, store, allow_nets, log
        self._nft_ready = False

    @staticmethod
    def _run(cmd):
        if os.geteuid() != 0:
            cmd = ["sudo", "-n"] + cmd
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            return r.returncode, (r.stderr or r.stdout).strip()
        except FileNotFoundError:
            return 127, f"{cmd[-1] if cmd else 'command'} not found"
        except subprocess.TimeoutExpired:
            return 124, "timed out"

    # -- nftables
    def _nft_ensure(self):
        if self._nft_ready:
            return True, ""
        steps = [
            ["nft", "add", "table", "inet", "ssh_guard"],
            ["nft", "add", "set", "inet", "ssh_guard", "blocked4",
             "{ type ipv4_addr; flags timeout; }"],
            ["nft", "add", "set", "inet", "ssh_guard", "blocked6",
             "{ type ipv6_addr; flags timeout; }"],
            ["nft", "add", "chain", "inet", "ssh_guard", "input",
             "{ type filter hook input priority -10 ; policy accept ; }"],
        ]
        for s in steps:
            rc, err = self._run(s)
            if rc:
                return False, err
        rc, out = self._run(["nft", "list", "chain", "inet", "ssh_guard", "input"])
        if rc == 0 and "blocked4" not in out:
            for fam, setname in (("ip", "blocked4"), ("ip6", "blocked6")):
                rc, err = self._run(["nft", "add", "rule", "inet", "ssh_guard", "input",
                                     fam, "saddr", "@" + setname, "drop"])
                if rc:
                    return False, err
        self._nft_ready = True
        return True, ""

    def _apply(self, ip, ttl):
        if self.backend() == "nft":
            ok, err = self._nft_ensure()
            if not ok:
                return False, err
            setname = "blocked6" if ":" in ip else "blocked4"
            elem = f"{{ {ip} timeout {ttl}s }}" if ttl > 0 else f"{{ {ip} }}"
            rc, err = self._run(["nft", "add", "element", "inet", "ssh_guard", setname, elem])
            return rc == 0, err
        tool = "ip6tables" if ":" in ip else "iptables"
        rc, _ = self._run([tool, "-C", "INPUT", "-s", ip, "-j", "DROP"])
        if rc == 0:
            return True, ""
        rc, err = self._run([tool, "-I", "INPUT", "1", "-s", ip, "-j", "DROP"])
        return rc == 0, err

    def _remove(self, ip, backend):
        if backend == "nft":
            setname = "blocked6" if ":" in ip else "blocked4"
            return self._run(["nft", "delete", "element", "inet", "ssh_guard", setname,
                              f"{{ {ip} }}"])[0] == 0
        tool = "ip6tables" if ":" in ip else "iptables"
        return self._run([tool, "-D", "INPUT", "-s", ip, "-j", "DROP"])[0] == 0

    def backend(self):
        want = self.cfg.block_backend
        if want == "iptables" and not shutil.which("iptables") and shutil.which("nft"):
            return "nft"
        return want

    # -- public API
    def block(self, ip, reason, ttl=None, dry=None):
        ip = norm_ip(ip)
        if not ip:
            return False, "invalid IP"
        if is_allowed(ip, self.allow):
            return False, f"{ip} is allowlisted - refusing to block"
        if self.store.is_blocked(ip):
            return False, f"{ip} is already blocked"
        escalate = ttl is None
        ttl = self.cfg.block_ttl if ttl is None else ttl
        if escalate and ttl > 0 and self.cfg.block_escalate:
            prior = self.store.ban_count(ip)
            if prior >= 5:
                ttl = 0  # sixth strike: permanent
            else:
                ttl = min(ttl * (2 ** prior), 30 * 86400)
            if prior:
                self.log(f"Repeat offender {ip}: ban #{prior + 1} "
                         f"({'permanent' if ttl == 0 else f'{ttl} s'})")
        dry = self.cfg.block_dry_run if dry is None else dry
        backend = self.backend()
        if dry:
            msg = f"[DRY-RUN] would block {ip} via {backend} ({reason})"
        else:
            ok, err = self._apply(ip, ttl)
            if not ok:
                return False, f"block failed for {ip}: {err or 'unknown error'}"
            msg = f"Blocked {ip} via {backend} ({reason})"
        self.store.add_block(ip, time.time(), time.time() + ttl if ttl > 0 else 0,
                             reason, dry, backend)
        self.store.offender_block(ip)
        self.log(msg)
        return True, msg

    def unblock(self, ip, dry=False, backend=None, expired=False):
        if not dry:
            self._remove(ip, backend or self.backend())
        self.store.remove_block(ip)
        self.log(f"{'Block expired' if expired else 'Unblocked'}: {ip}")

    def expire(self):
        for ip, dry, backend in self.store.expired_blocks(time.time()):
            self.unblock(ip, bool(dry), backend, expired=True)


# ==========================================================================
# Elasticsearch: tiny REST client + batching sink
# ==========================================================================
class ESClient:
    def __init__(self, url, user="", password="", api_key="", verify=True):
        self.base = url.rstrip("/")
        self.headers = {}
        if api_key:
            self.headers["Authorization"] = "ApiKey " + api_key
        elif user:
            tok = base64.b64encode(f"{user}:{password}".encode()).decode()
            self.headers["Authorization"] = "Basic " + tok
        self.ctx = None
        if self.base.startswith("https"):
            self.ctx = ssl.create_default_context()
            if not verify:
                self.ctx.check_hostname = False
                self.ctx.verify_mode = ssl.CERT_NONE

    def request(self, method, path, body=None, ndjson=False, timeout=15):
        data, headers = None, dict(self.headers)
        if body is not None:
            data = body.encode() if isinstance(body, str) else json.dumps(body, default=str).encode()
            headers["Content-Type"] = "application/x-ndjson" if ndjson else "application/json"
        req = urllib.request.Request(self.base + path, data=data, method=method, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=self.ctx) as r:
                raw = r.read()
                return r.status, (json.loads(raw) if raw else {})
        except urllib.error.HTTPError as e:
            raw = e.read()
            try:
                return e.code, json.loads(raw)
            except ValueError:
                return e.code, {"error": raw.decode(errors="replace")[:300]}

    def ping(self):
        status, body = self.request("GET", "/", timeout=5)
        if status != 200:
            raise ConnectionError(f"HTTP {status}: {body}")
        return body.get("version", {}).get("number", "?")

    def ensure_index(self, name, mappings):
        status, _ = self.request("GET", f"/{name}")
        if status == 404:
            status, body = self.request("PUT", f"/{name}", {"mappings": mappings})
            if status >= 300 and "already_exists" not in json.dumps(body):
                raise RuntimeError(f"cannot create index {name}: {body}")
            return True
        return False

    def bulk(self, items):
        lines = []
        for index, doc in items:
            lines.append(json.dumps({"index": {"_index": index}}))
            lines.append(json.dumps(doc, default=str))
        status, res = self.request("POST", "/_bulk", "\n".join(lines) + "\n", ndjson=True, timeout=30)
        if status >= 300:
            raise ConnectionError(f"bulk HTTP {status}: {res}")
        if res.get("errors"):
            bad = next((i["index"] for i in res["items"] if i["index"].get("error")), {})
            return f"some documents rejected: {bad.get('error')}"
        return ""


def es_mappings():
    ip_ev = {"@timestamp": {"type": "date"}, "event_type": {"type": "keyword"},
             "auth_method": {"type": "keyword"}, "username": {"type": "keyword"},
             "invalid_user": {"type": "boolean"}, "source_ip": {"type": "ip"},
             "source_port": {"type": "integer"}, "host": {"type": "keyword"},
             "raw": {"type": "text"}, "country_iso": {"type": "keyword"},
             "country": {"type": "keyword"}, "city": {"type": "keyword"},
             "asn": {"type": "long"}, "as_org": {"type": "keyword"}, "service": {"type": "keyword"},
             "detail": {"type": "keyword", "ignore_above": 512}, "category": {"type": "keyword"},
             "http_status": {"type": "integer"}, "user_agent": {"type": "keyword", "ignore_above": 256},
             "dest_port": {"type": "integer"}, "capture": {"type": "keyword"}}
    ip_al = {"@timestamp": {"type": "date"}, "alert_type": {"type": "keyword"},
             "severity": {"type": "keyword"}, "source_ip": {"type": "ip"},
             "attempts": {"type": "integer"}, "window_seconds": {"type": "integer"},
             "usernames": {"type": "keyword"}, "target_user": {"type": "keyword"},
             "risk_score": {"type": "integer"}, "host": {"type": "keyword"},
             "status": {"type": "keyword"}, "country": {"type": "keyword"},
             "service": {"type": "keyword"}, "note": {"type": "text"}}
    return {"properties": ip_ev}, {"properties": ip_al}


def make_client(cfg):
    return ESClient(cfg.es_url, cfg.es_user, cfg.es_password, cfg.es_api_key, cfg.es_verify)


class ESSink:
    def __init__(self, cfg, log):
        self.cfg, self.log = cfg, log
        self.client = make_client(cfg)
        self.events_idx = f"{cfg.es_prefix}-events"
        self.alerts_idx = f"{cfg.es_prefix}-alerts"
        self.q = queue.Queue(maxsize=100000)
        self.stop_evt = threading.Event()
        self.thread = None

    def start(self):
        ver = self.client.ping()
        ev_map, al_map = es_mappings()
        for idx, m in ((self.events_idx, ev_map), (self.alerts_idx, al_map)):
            if self.client.ensure_index(idx, m):
                self.log(f"Created Elasticsearch index '{idx}'")
        self.log(f"Elasticsearch {ver} ready")
        self.thread = threading.Thread(target=self._loop, daemon=True)
        self.thread.start()

    def add(self, kind, doc):
        doc = {k: v for k, v in doc.items() if not k.startswith("_")}
        try:
            self.q.put_nowait((self.events_idx if kind == "event" else self.alerts_idx, doc))
        except queue.Full:
            pass

    def _loop(self):
        pending, fails = [], 0
        while True:
            if len(pending) < 500:
                deadline = time.time() + 2
                while len(pending) < 500 and time.time() < deadline:
                    try:
                        pending.append(self.q.get(timeout=0.5))
                    except queue.Empty:
                        if self.stop_evt.is_set():
                            break
            if pending:
                try:
                    warn = self.client.bulk(pending)
                    if warn:
                        self.log(f"[ES] {warn}")
                    pending, fails = [], 0
                except Exception as e:
                    fails += 1
                    self.log(f"[ES] bulk failed ({e}); retry #{fails}")
                    if fails >= 6 or len(pending) > 20000:
                        self.log(f"[ES] dropping {len(pending)} documents")
                        pending, fails = [], 0
                    elif not self.stop_evt.wait(min(30, 2 ** fails)):
                        continue
            if self.stop_evt.is_set() and self.q.empty() and not pending:
                return
            if self.stop_evt.is_set() and fails:
                return

    def close(self):
        self.stop_evt.set()
        if self.thread:
            self.thread.join(timeout=8)


def es_top(cfg, hours=24, size=10):
    client = make_client(cfg)
    body = {"size": 0,
            "query": {"bool": {"filter": [{"term": {"event_type": "failed"}},
                                           {"range": {"@timestamp": {"gte": f"now-{hours}h"}}}]}},
            "aggs": {"ips": {"terms": {"field": "source_ip", "size": size}},
                     "users": {"terms": {"field": "username", "size": size}}}}
    status, res = client.request("POST", f"/{cfg.es_prefix}-events/_search", body)
    if status >= 300:
        raise RuntimeError(f"HTTP {status}: {res}")
    aggs = res["aggregations"]
    return ([(b["key"], b["doc_count"]) for b in aggs["ips"]["buckets"]],
            [(b["key"], b["doc_count"]) for b in aggs["users"]["buckets"]])


# ==========================================================================
# Core: wires everything together; shared by GUI and headless mode
# ==========================================================================
class Engine(threading.Thread):
    """Tails every configured log source (one worker per source) and feeds Core.handle_line."""

    def __init__(self, core):
        super().__init__(daemon=True)
        self.core = core
        self.stop_evt = threading.Event()
        self.procs = []
        self.workers = []

    def stop(self):
        self.stop_evt.set()
        for p in list(self.procs):
            try:
                p.terminate()
            except OSError:
                pass

    def plan(self):
        """[(kind, path|None, optional)] - kind is 'syslog', 'web', 'web-https' or 'journal'."""
        cfg, log = self.core.cfg, self.core.log
        plan, seen = [], set()

        def add(kind, path, optional):
            key = os.path.realpath(path) if path else "journal"
            if key not in seen:
                seen.add(key)
                plan.append((kind, path, optional))

        main = cfg.log_path
        if cfg.use_journal:
            add("journal", None, False)
        elif os.path.exists(main) or not shutil.which("journalctl"):
            add("syslog", main, False)
        else:
            log(f"{main} not found (Kali/Debian often log to journald only) - "
                "reading service events from journald instead")
            add("journal", None, False)
        for kind, path in parse_sources(cfg.extra_sources, log):
            add(kind, path, True)
        if cfg.auto_sources:
            for kind, path in discover_sources(log):
                add(kind, path, True)
        return plan

    def run(self):
        try:
            for kind, path, optional in self.plan():
                th = threading.Thread(target=self._worker, args=(kind, path, optional), daemon=True)
                th.start()
                self.workers.append(th)
            while not self.stop_evt.wait(0.5):
                if not any(w.is_alive() for w in self.workers):
                    break
        except Exception as e:
            self.core.log(f"Engine error: {e}")
        finally:
            self.stop()
            self.core.emit("stopped", None)

    def _worker(self, kind, path, optional):
        try:
            if kind == "journal":
                self._journal()
            else:
                self._file(kind, path, optional)
        except Exception as e:
            self.core.log(f"Source {path or 'journald'} stopped: {type(e).__name__}: {e}")

    def _file(self, kind, path, optional):
        if optional:
            announced = False
            while not os.path.exists(path):
                if not announced:
                    self.core.log(f"Waiting for {path} to appear")
                    announced = True
                if self.stop_evt.wait(5):
                    return
        try:
            f = open(path, "r", errors="replace")
        except OSError as e:
            hint = (" - permission denied: run with sudo or add your user to the 'adm' group"
                    if isinstance(e, PermissionError) else "")
            self.core.log(f"Cannot open {path}: {e}{hint}")
            return
        inode = os.fstat(f.fileno()).st_ino
        if not self.core.cfg.from_start:
            f.seek(0, os.SEEK_END)
        self.core.log(f"Tailing {path} [{kind}]{' (from start)' if self.core.cfg.from_start else ''}")
        while not self.stop_evt.is_set():
            line = f.readline()
            if line:
                self.core.handle_line(line, kind)
                continue
            time.sleep(0.4)
            try:
                st = os.stat(path)
                if st.st_ino != inode or st.st_size < f.tell():
                    f.close()
                    f = open(path, "r", errors="replace")
                    inode = os.fstat(f.fileno()).st_ino
                    self.core.log(f"{path} rotated - reopened")
            except OSError:
                pass
        f.close()

    def _journal(self):
        n = "20000" if self.core.cfg.from_start else "0"
        # OpenSSH 9.8+ logs authentication as 'sshd-session', older versions as 'sshd'
        cmd = ["journalctl"]
        for ident in JOURNAL_IDS:
            cmd += ["-t", ident]
        cmd += ["-o", "short-iso", "--no-pager", "-f", "-n", n]
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                    text=True, errors="replace")
        except OSError as e:
            self.core.log(f"Cannot run journalctl: {e}")
            return
        self.procs.append(proc)
        self.core.log("Reading service events from journald")
        other = []
        for line in proc.stdout:
            if self.stop_evt.is_set():
                break
            if "not seeing messages" in line or "insufficient permissions" in line:
                self.core.log("journald: " + line.strip()[:200] + "  ->  add your user to the 'adm' or "
                              "'systemd-journal' group, or run with sudo")
            elif line.startswith("-- "):
                if len(other) < 3:
                    other.append(line.strip()[:160])
            else:
                self.core.handle_line(line, "syslog")
        if not self.stop_evt.is_set():
            try:
                rc = proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                rc = "?"
            self.core.log(f"journalctl exited (status {rc}) {' | '.join(other)}")


def safe_text(s, n=40):
    """Attacker-controlled strings (usernames) are cleaned before going to email/chat/popups."""
    return re.sub(r"[^\w.@\-$' /(),:;+=#%]", "?", str(s))[:n]


def format_alert(al, status=None):
    status = status or al.get("status") or "ALERT"
    user = safe_text(al.get("target_user") or ", ".join(al.get("usernames", [])[:3]) or "?")
    when = str(al["@timestamp"])[:19].replace("T", " ")
    svc = al.get("service") or "ssh"
    title = ("SSH Brute Force Attempt Detected!" if svc == "ssh"
             else f"{SERVICE_LABELS.get(svc, svc.upper())} Attack Detected!")
    text = (f"{title}\n"
            f"Type       : {al['alert_type']}\n"
            f"Service    : {svc}\n"
            f"IP Address : {al['source_ip']}\n"
            f"Username   : {user}\n"
            f"Attempts   : {al['attempts']}\n"
            f"Risk       : {al['risk_score']}/100\n"
            f"Time       : {when} UTC\n"
            f"Status     : {status}")
    if al.get("country"):
        text = text.replace("\nUsername", f"\nCountry    : {safe_text(al['country'], 60)}\nUsername", 1)
    if al.get("note"):
        text += f"\nNote       : {safe_text(al['note'], 120)}"
    return text


# ==========================================================================
# Notifications: email (SMTP) + webhook (Slack / Discord / generic)
# ==========================================================================
class Notifier:
    def __init__(self, cfg, log, start_thread=True):
        self.cfg, self.log = cfg, log
        self.q = queue.Queue(maxsize=200)
        self.sent = deque()
        self.stop_evt = threading.Event()
        self.thread = None
        if start_thread:
            self.thread = threading.Thread(target=self._loop, daemon=True)
            self.thread.start()

    @property
    def email_ready(self):
        c = self.cfg
        return bool(c.email_enabled and c.smtp_host and c.mail_to)

    @property
    def telegram_ready(self):
        return bool(self.cfg.telegram_token and self.cfg.telegram_chat_id)

    @property
    def active(self):
        return self.email_ready or bool(self.cfg.webhook_url) or self.telegram_ready

    def notify(self, al):
        if not self.active or SEV_RANK[al["severity"]] < SEV_RANK[self.cfg.email_min_severity]:
            return
        try:
            self.q.put_nowait(al)
        except queue.Full:
            pass

    def _allow(self):
        now = time.time()
        while self.sent and now - self.sent[0] > 3600:
            self.sent.popleft()
        if len(self.sent) >= 30:
            return False
        self.sent.append(now)
        return True

    def _loop(self):
        while not self.stop_evt.is_set():
            try:
                al = self.q.get(timeout=1)
            except queue.Empty:
                continue
            if not self._allow():
                self.log("Notification rate limit reached (30 per hour)")
                continue
            for err in self.send(al):
                self.log(f"Notification failed - {err}")

    def send(self, al):
        text, errs = format_alert(al), []
        if self.email_ready:
            try:
                self._email(al, text)
            except Exception as e:
                errs.append(f"email: {e}")
        if self.cfg.webhook_url:
            try:
                self._webhook(text)
            except Exception as e:
                errs.append(f"webhook: {e}")
        if self.telegram_ready:
            try:
                self._telegram(text)
            except Exception as e:
                errs.append(f"telegram: {type(e).__name__}")  # never echo the URL (contains the token)
        return errs

    def _email(self, al, text):
        c = self.cfg
        msg = EmailMessage()
        msg["Subject"] = f"[SSH Guard] {al['severity'].upper()} {al['alert_type']} from {al['source_ip']} on {HOSTNAME}"
        msg["From"] = c.mail_from or c.smtp_user or f"ssh-guard@{HOSTNAME}"
        msg["To"] = c.mail_to
        msg.set_content(text)
        ctx = ssl.create_default_context()
        smtp = (smtplib.SMTP_SSL(c.smtp_host, c.smtp_port, timeout=15, context=ctx)
                if c.smtp_security == "ssl" else smtplib.SMTP(c.smtp_host, c.smtp_port, timeout=15))
        with smtp:
            if c.smtp_security == "starttls":
                smtp.starttls(context=ctx)
            if c.smtp_user:
                smtp.login(c.smtp_user, c.smtp_password)
            smtp.send_message(msg)

    def _webhook(self, text):
        url = self.cfg.webhook_url
        if not url.startswith(("http://", "https://")):
            raise ValueError("webhook URL must start with http:// or https://")
        body = json.dumps({"text": text, "content": text}).encode()  # Slack + Discord keys
        req = urllib.request.Request(url, data=body, method="POST",
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=10) as r:
            r.read()

    def _telegram(self, text):
        token, chat = self.cfg.telegram_token, self.cfg.telegram_chat_id
        if not re.fullmatch(r"\d{5,}:[A-Za-z0-9_-]{20,}", token):
            raise ValueError("invalid bot token format")
        if not re.fullmatch(r"-?\d+|@[A-Za-z0-9_]{5,}", chat):
            raise ValueError("invalid chat id")
        body = json.dumps({"chat_id": chat, "text": text}).encode()
        req = urllib.request.Request(f"https://api.telegram.org/bot{token}/sendMessage", data=body,
                                     method="POST", headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=10) as r:
            r.read()

    def close(self):
        self.stop_evt.set()


# ==========================================================================
# Threat intelligence feed (local file and/or URLs; IPs and CIDRs, # and ; comments)
# ==========================================================================
class ThreatFeed:
    def __init__(self, cfg, log):
        self.cfg, self.log = cfg, log
        self.ips, self.nets, self.cache, self.count = set(), [], {}, 0
        self.wake = threading.Event()

    @staticmethod
    def parse(text):
        ips, nets = set(), []
        for raw in text.splitlines():
            line = raw.split("#")[0].strip()
            if not line:
                continue
            tok = re.split(r"[\s,;]", line, 1)[0]
            try:
                net = ipaddress.ip_network(tok, strict=False)
            except ValueError:
                continue
            if net.prefixlen == net.max_prefixlen:
                ips.add(str(net.network_address))
            else:
                nets.append(net)
        return ips, nets

    def set_entries(self, ips, nets):
        self.ips, self.nets, self.cache = ips, nets, {}
        self.count = len(ips) + len(nets)

    def request_refresh(self):
        self.wake.set()

    def refresh(self):
        c, ips, nets, got = self.cfg, set(), [], False
        if c.feed_file:
            try:
                with open(c.feed_file, errors="replace") as f:
                    a, b = self.parse(f.read(5_000_000))
                ips |= a
                nets += b
                got = True
            except OSError as e:
                self.log(f"Threat feed file unreadable: {e}")
        for url in re.split(r"[,\s]+", c.feed_urls.strip()):
            if not url:
                continue
            if not url.startswith(("http://", "https://")):
                self.log(f"Threat feed skipped (not http/https): {url[:60]}")
                continue
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "ssh-guard"})
                with urllib.request.urlopen(req, timeout=20) as r:
                    a, b = self.parse(r.read(5_000_000).decode("utf-8", "replace"))
                ips |= a
                nets += b
                got = True
            except Exception as e:
                self.log(f"Threat feed {url[:60]} failed: {type(e).__name__}")
        if got:
            self.set_entries(ips, nets)
            self.log(f"Threat feed loaded: {self.count} entries")
        return self.count

    def contains(self, ip):
        hit = self.cache.get(ip)
        if hit is None:
            try:
                a = ipaddress.ip_address(ip)
            except ValueError:
                return False
            hit = ip in self.ips or any(a in n for n in self.nets if n.version == a.version)
            if len(self.cache) > 50000:
                self.cache.clear()
            self.cache[ip] = hit
        return hit


# ==========================================================================
# SIEM forwarding: CEF over syslog (UDP or TCP)
# ==========================================================================
def cef_alert(al):
    sev = {"low": 3, "medium": 5, "high": 8, "critical": 10}.get(al["severity"], 5)

    def head(v):
        return str(v).replace("\\", "\\\\").replace("|", "\\|")

    def ext(v):
        return str(v).replace("\\", "\\\\").replace("=", "\\=").replace("\n", " ").replace("\r", " ")

    user = al.get("target_user") or ",".join(al.get("usernames", [])[:3])
    fields_ = (f"src={al['source_ip']} suser={ext(user)} cnt={al['attempts']} "
               f"cs1Label=risk cs1={al['risk_score']} cs2Label=status cs2={ext(al.get('status', ''))} "
               f"cs3Label=country cs3={ext(al.get('country', ''))} msg={ext(al.get('note', ''))} "
               f"app={ext(al.get('service', 'ssh'))} "
               f"rt={int(al.get('_ts', time.time()) * 1000)} dvchost={ext(HOSTNAME)}")
    return f"CEF:0|SSHGuard|SSHGuard|1.0|{head(al['alert_type'])}|{head(al['alert_type'])}|{sev}|{fields_}"


def format_syslog(al):
    pri = 4 * 8 + {"low": 5, "medium": 4, "high": 3, "critical": 2}.get(al["severity"], 4)
    now = datetime.now()
    return f"<{pri}>{now:%b} {now.day:>2} {now:%H:%M:%S} {HOSTNAME} ssh-guard: {cef_alert(al)}"


class SyslogForwarder:
    def __init__(self, target, log):
        self.log = log
        t, self.proto = target.strip(), "udp"
        if "://" in t:
            self.proto, t = t.split("://", 1)
            self.proto = self.proto.lower()
        host, _, port = t.rpartition(":")
        if self.proto not in ("udp", "tcp") or not host or not port.isdigit():
            raise ValueError("target must look like udp://host:514 or tcp://host:514")
        self.host, self.port = host.strip("[]"), int(port)
        self.sock, self.sockaddr, self.last_err = None, None, 0.0
        self.q = queue.Queue(maxsize=1000)
        self.stop_evt = threading.Event()
        threading.Thread(target=self._loop, daemon=True).start()

    def send(self, al):
        try:
            self.q.put_nowait(format_syslog(al))
        except queue.Full:
            pass

    def _loop(self):
        while not self.stop_evt.is_set():
            try:
                msg = self.q.get(timeout=1)
            except queue.Empty:
                continue
            try:
                self._emit(msg)
            except OSError as e:
                if time.time() - self.last_err > 60:
                    self.last_err = time.time()
                    self.log(f"Syslog forwarding error: {e}")
                self._close_sock()

    def _emit(self, msg):
        data = msg.encode("utf-8", "replace")[:4000]
        if self.proto == "udp":
            if not self.sock:
                info = socket.getaddrinfo(self.host, self.port, type=socket.SOCK_DGRAM)[0]
                self.sock, self.sockaddr = socket.socket(info[0], socket.SOCK_DGRAM), info[4]
            self.sock.sendto(data, self.sockaddr)
        else:
            if not self.sock:
                self.sock = socket.create_connection((self.host, self.port), timeout=5)
            self.sock.sendall(data + b"\n")

    def _close_sock(self):
        if self.sock:
            try:
                self.sock.close()
            except OSError:
                pass
        self.sock = None

    def close(self):
        self.stop_evt.set()
        self._close_sock()


# ==========================================================================
# Reports (self-contained HTML, everything escaped)
# ==========================================================================
REPORT_CSS = """
body{background:#0e0b16;color:#e8e4f3;font-family:system-ui,sans-serif;margin:0;padding:24px}
h1{color:#fff;margin:0 0 4px}h1 span{color:#a86bff}h2{color:#a86bff;margin-top:28px;border-bottom:1px solid #3a2b66;padding-bottom:4px}
.sub{color:#9a90b8;margin-bottom:18px}.cards{display:flex;gap:12px;flex-wrap:wrap}
.card{background:#171226;border:1px solid #3a2b66;border-radius:10px;padding:12px 18px;min-width:130px}
.card b{display:block;font-size:26px;color:#fff}.card small{color:#9a90b8}
table{border-collapse:collapse;width:100%;background:#171226;border:1px solid #3a2b66}
th,td{padding:6px 10px;text-align:left;border-bottom:1px solid #2a2046;font-size:14px}th{color:#a86bff}
.chart{display:flex;align-items:flex-end;gap:2px;height:120px;background:#171226;border:1px solid #3a2b66;padding:8px}
.bar{flex:1;background:#d9534f;min-width:2px}.critical{color:#ff6b6b;font-weight:700}.high{color:#ffa94d}.medium{color:#ffe066}
ul{line-height:1.7}
"""


def render_report_html(rep):
    e = html.escape

    def when(t):
        return datetime.fromtimestamp(t, timezone.utc).strftime("%Y-%m-%d %H:%M")

    def table(headers, rows):
        head = "".join(f"<th>{e(str(h))}</th>" for h in headers)
        body = "".join("<tr>" + "".join(f"<td>{e(str(c))}</td>" for c in r) + "</tr>" for r in rows)
        empty = f"<tr><td colspan='{len(headers)}'>No data</td></tr>"
        return f"<table><tr>{head}</tr>{body or empty}</table>"

    peak = max([c for _, c in rep["timeline"]] or [1])
    unit = "hour" if rep["bucket"] == 3600 else "day"
    bars = "".join(
        f"<div class='bar' style='height:{max(2, int(100 * c / peak))}%' "
        f"title='{e(when(b * rep['bucket']))}: {c}'></div>" for b, c in rep["timeline"])
    sev = rep["alerts_by_severity"]
    cards = "".join(
        f"<div class='card'><b>{e(str(v))}</b><small>{e(k)}</small></div>" for k, v in (
            ("Failed logins", rep["failed"]), ("Unique attacker IPs", rep["unique_ips"]),
            ("Accepted logins", rep["accepted"]), ("Alerts", sum(sev.values())),
            ("Critical alerts", sev.get("critical", 0)), ("Blocked IPs", len(rep["blocks"]))))

    recs = ["Use strong SSH credentials and prefer key-based authentication.",
            "Change the default SSH port and restrict access with a firewall.",
            "Enable fail2ban (or this tool's auto-block) for automatic protection.",
            "Regularly review access logs and these reports."]
    if any(u == "root" for u, _ in rep["top_users"]):
        recs.insert(0, "Root is being targeted: set 'PermitRootLogin no' in sshd_config.")
    if any(t == "possible_compromise" for t, _ in rep["alerts_by_type"]):
        recs.insert(0, "URGENT: a login succeeded after repeated failures. Check the account and active sessions.")

    ips = [(ip, c or "-", n, u, when(a), when(b)) for ip, n, u, a, b, c in rep["top_ips"]]
    alerts = [(str(r[0])[:19].replace("T", " "),) + tuple(r[1:]) for r in rep["alerts"]]
    blocks = [(ip, when(at), when(exp) if exp else "never", reason, "dry-run" if dry else backend)
              for ip, at, exp, reason, dry, backend in rep["blocks"]]
    return f"""<!doctype html><html><head><meta charset="utf-8"><title>SSH Guard report</title>
<style>{REPORT_CSS}</style></head><body>
<h1>SSH <span>Guard</span> report</h1>
<div class="sub">Host {e(rep['host'])} | last {rep['hours']} h | generated {e(rep['generated'])} UTC</div>
<div class="cards">{cards}</div>
<h2>Failed logins per {unit}</h2><div class="chart">{bars}</div>
<h2>Activity by service</h2>{table(["Service", "Failed logins / attacks / probes", "Alerts"], [(k, v[0], v[1]) for k, v in sorted(rep["by_service"].items(), key=lambda kv: -kv[1][0])])}
<h2>Top attacker IPs</h2>{table(["IP", "Country", "Failures", "Distinct users", "First seen (UTC)", "Last seen (UTC)"], ips)}
<h2>Most targeted usernames</h2>{table(["Username", "Failures"], rep["top_users"])}
<h2>Top source countries</h2>{table(["Country", "Failures", "Distinct IPs"], rep["top_countries"])}
<h2>Alerts by type</h2>{table(["Type", "Count"], rep["alerts_by_type"])}
<h2>Recent alerts</h2>{table(["Time (UTC)", "Severity", "Type", "IP", "Country", "Service", "Attempts", "Risk", "User", "Status", "Note"], alerts)}
<h2>Blocked IPs</h2>{table(["IP", "Blocked at (UTC)", "Expires (UTC)", "Reason", "Mode"], blocks)}
<h2>Repeat offenders</h2>{table(["IP", "Alerts", "Bans", "First seen (UTC)", "Last seen (UTC)"], [(r[0], r[1], r[2], when(r[3]), when(r[4])) for r in rep["repeat_offenders"]])}
<h2>Recommendations</h2><ul>{"".join(f"<li>{e(r)}</li>" for r in recs)}</ul>
</body></html>"""


def write_report(store, hours=24, directory=None):
    rep = store.report_data(hours)
    d = directory or os.path.join(APP_DIR, "reports")
    os.makedirs(d, exist_ok=True)
    path = os.path.join(d, f"ssh-report-{datetime.now():%Y%m%d-%H%M%S}.html")
    with open(path, "w", encoding="utf-8") as f:
        f.write(render_report_html(rep))
    return path


# ==========================================================================
# Kibana dashboard export (importable saved objects, NDJSON)
# ==========================================================================
def kibana_objects(prefix="ssh-guard"):
    ev_id, al_id = f"{prefix}-events-dv", f"{prefix}-alerts-dv"
    objs = []
    for pid, title in ((ev_id, f"{prefix}-events*"), (al_id, f"{prefix}-alerts*")):
        objs.append({"id": pid, "type": "index-pattern",
                     "attributes": {"title": title, "timeFieldName": "@timestamp"},
                     "references": [], "migrationVersion": {"index-pattern": "7.6.0"},
                     "coreMigrationVersion": "7.10.0"})

    count = {"id": "1", "enabled": True, "type": "count", "params": {}, "schema": "metric"}

    def terms(field, schema, size=10):
        return {"id": "2", "enabled": True, "type": "terms", "schema": schema,
                "params": {"field": field, "orderBy": "1", "order": "desc", "size": size,
                           "otherBucket": False, "otherBucketLabel": "Other",
                           "missingBucket": False, "missingBucketLabel": "Missing"}}

    metric_params = {"addTooltip": True, "addLegend": False, "type": "metric", "metric": {
        "percentageMode": False, "useRanges": False, "colorSchema": "Green to Red",
        "metricColorMode": "None", "colorsRange": [{"from": 0, "to": 10000}],
        "labels": {"show": True}, "invertColors": False,
        "style": {"bgFill": "#000", "bgColor": False, "labelColor": False, "subText": "", "fontSize": 54}}}
    table_params = {"perPage": 10, "showPartialRows": False, "showMetricsAtAllLevels": False,
                    "sort": {"columnIndex": None, "direction": None}, "showTotal": False,
                    "totalFunc": "sum", "percentageCol": ""}
    pie_params = {"type": "pie", "addTooltip": True, "addLegend": True, "legendPosition": "right",
                  "isDonut": True, "labels": {"show": False, "values": True, "last_level": True,
                                              "truncate": 100}}
    hist_params = {
        "type": "histogram", "grid": {"categoryLines": False},
        "categoryAxes": [{"id": "CategoryAxis-1", "type": "category", "position": "bottom", "show": True,
                          "style": {}, "scale": {"type": "linear"},
                          "labels": {"show": True, "filter": True, "truncate": 100}, "title": {}}],
        "valueAxes": [{"id": "ValueAxis-1", "name": "LeftAxis-1", "type": "value", "position": "left",
                       "show": True, "style": {}, "scale": {"type": "linear", "mode": "normal"},
                       "labels": {"show": True, "rotate": 0, "filter": False, "truncate": 100},
                       "title": {"text": "Count"}}],
        "seriesParams": [{"show": True, "type": "histogram", "mode": "stacked",
                          "data": {"label": "Count", "id": "1"}, "valueAxis": "ValueAxis-1",
                          "drawLinesBetweenPoints": True, "lineWidth": 2, "showCircles": True}],
        "addTooltip": True, "addLegend": False, "legendPosition": "right", "times": [],
        "addTimeMarker": False, "labels": {"show": False},
        "thresholdLine": {"show": False, "value": 10, "width": 1, "style": "full", "color": "#E7664C"}}
    date_hist = {"id": "2", "enabled": True, "type": "date_histogram", "schema": "segment",
                 "params": {"field": "@timestamp", "useNormalizedEsInterval": True,
                            "scaleMetricValues": False, "interval": "auto", "drop_partials": False,
                            "min_doc_count": 1, "extended_bounds": {}}}

    def vis(vid, title, index_id, query, vtype, aggs, params):
        state = {"title": title, "type": vtype, "aggs": aggs, "params": params}
        ss = {"query": {"query": query, "language": "kuery"}, "filter": [],
              "indexRefName": "kibanaSavedObjectMeta.searchSourceJSON.index"}
        return {"id": vid, "type": "visualization",
                "attributes": {"title": title, "visState": json.dumps(state), "uiStateJSON": "{}",
                               "description": "", "version": 1,
                               "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps(ss)}},
                "references": [{"name": "kibanaSavedObjectMeta.searchSourceJSON.index",
                                "type": "index-pattern", "id": index_id}],
                "migrationVersion": {"visualization": "7.10.0"}, "coreMigrationVersion": "7.10.0"}

    v = f"{prefix}-vis"
    specs = [  # id, title, index, query, type, aggs, params, x, y, w, h
        (f"{v}-failed", "Failed logins", ev_id, "event_type:failed", "metric", [count], metric_params, 0, 0, 16, 8),
        (f"{v}-accepted", "Accepted logins", ev_id, "event_type:accepted", "metric", [count], metric_params, 16, 0, 16, 8),
        (f"{v}-alerts", "Alerts", al_id, "", "metric", [count], metric_params, 32, 0, 16, 8),
        (f"{v}-timeline", "Failed logins over time", ev_id, "event_type:failed", "histogram",
         [count, date_hist], hist_params, 0, 8, 48, 14),
        (f"{v}-top-ips", "Top attacker IPs", ev_id, "event_type:failed", "table",
         [count, terms("source_ip", "bucket")], table_params, 0, 22, 24, 16),
        (f"{v}-top-users", "Most targeted usernames", ev_id, "event_type:failed", "table",
         [count, terms("username", "bucket")], table_params, 24, 22, 24, 16),
        (f"{v}-alert-types", "Alerts by type", al_id, "", "pie",
         [count, terms("alert_type", "segment")], pie_params, 0, 38, 16, 16),
        (f"{v}-alert-sev", "Alerts by severity", al_id, "", "pie",
         [count, terms("severity", "segment")], pie_params, 16, 38, 16, 16),
        (f"{v}-countries", "Top source countries", ev_id, "event_type:failed", "table",
         [count, terms("country", "bucket")], table_params, 32, 38, 16, 16),
        (f"{v}-svc-events", "Attack activity by service", ev_id, "event_type:(failed or probe or web_attack)",
         "pie", [count, terms("service", "segment")], pie_params, 0, 54, 24, 16),
        (f"{v}-svc-alerts", "Alerts by service", al_id, "", "pie",
         [count, terms("service", "segment")], pie_params, 24, 54, 24, 16),
    ]
    panels, refs = [], []
    for n, (vid, title, idx, query, vtype, aggs, params, x, y, w, h) in enumerate(specs, 1):
        objs.append(vis(vid, title, idx, query, vtype, aggs, params))
        panels.append({"version": "7.10.0", "gridData": {"x": x, "y": y, "w": w, "h": h, "i": str(n)},
                       "panelIndex": str(n), "embeddableConfig": {}, "panelRefName": f"panel_{n}"})
        refs.append({"name": f"panel_{n}", "type": "visualization", "id": vid})
    objs.append({"id": f"{prefix}-dashboard", "type": "dashboard",
                 "attributes": {"title": "SSH Guard", "description": "SSH brute force detector",
                                "hits": 0, "version": 1, "timeRestore": True,
                                "timeFrom": "now-24h", "timeTo": "now",
                                "refreshInterval": {"pause": False, "value": 30000},
                                "optionsJSON": json.dumps({"hidePanelTitles": False, "useMargins": True}),
                                "panelsJSON": json.dumps(panels),
                                "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps(
                                    {"query": {"query": "", "language": "kuery"}, "filter": []})}},
                 "references": refs, "migrationVersion": {"dashboard": "7.9.3"},
                 "coreMigrationVersion": "7.10.0"})
    return objs


def kibana_export(path, prefix="ssh-guard"):
    with open(path, "w", encoding="utf-8") as f:
        for o in kibana_objects(prefix):
            f.write(json.dumps(o) + "\n")
    return path


# ==========================================================================
# Web dashboard (stdlib http.server, read-only, loopback by default)
# ==========================================================================
DASH_HTML = """<!doctype html><html><head><meta charset="utf-8"><title>SSH Guard</title>
<style>
body{background:#0e0b16;color:#e8e4f3;font-family:system-ui,sans-serif;margin:0;padding:20px}
h1 span{color:#a86bff}h2{color:#a86bff;font-size:16px;margin:22px 0 6px}
.cards{display:flex;gap:10px;flex-wrap:wrap}.card{background:#171226;border:1px solid #3a2b66;border-radius:10px;padding:10px 16px;min-width:120px}
.card b{display:block;font-size:24px}.card small{color:#9a90b8}
table{border-collapse:collapse;width:100%;background:#171226;border:1px solid #3a2b66}
th,td{padding:5px 9px;text-align:left;border-bottom:1px solid #2a2046;font-size:13px}th{color:#a86bff}
.chart{display:flex;align-items:flex-end;gap:2px;height:100px;background:#171226;border:1px solid #3a2b66;padding:6px}
.bar{flex:1;background:#d9534f;min-width:2px}a{color:#a86bff}
</style></head><body>
<h1>SSH <span>Guard</span> live dashboard</h1>
<div>Reports: <a href="/report?hours=24">24 h</a> | <a href="/report?hours=168">7 days</a> | <a href="/report?hours=720">30 days</a></div>
<div class="cards" id="cards"></div>
<h2>Failed logins per minute (last 60 min)</h2><div class="chart" id="chart"></div>
<h2>Recent login attempts</h2><table><thead><tr><th>Time (UTC)</th><th>IP</th><th>Username</th><th>Result</th><th>Attempts</th><th>Country</th><th>Service</th></tr></thead><tbody id="att"></tbody></table>
<h2>Services</h2><table><thead><tr><th>Service</th><th>Events</th><th>Failed</th><th>Alerts</th></tr></thead><tbody id="svc"></tbody></table>
<h2>Top attackers</h2><table><thead><tr><th>IP</th><th>Failures</th><th>Last</th><th>Users</th><th>Risk</th><th>Country</th><th>Services</th></tr></thead><tbody id="ips"></tbody></table>
<h2>Recent alerts</h2><table><thead><tr><th>Time</th><th>Severity</th><th>Type</th><th>IP</th><th>Country</th><th>Service</th><th>Attempts</th><th>Risk</th><th>User</th><th>Status</th><th>Note</th></tr></thead><tbody id="alerts"></tbody></table>
<script>
function fill(id,rows){const tb=document.getElementById(id);tb.replaceChildren();rows.forEach(function(r){const tr=document.createElement('tr');r.forEach(function(c){const td=document.createElement('td');td.textContent=c;tr.appendChild(td)});tb.appendChild(tr)})}
async function load(){
  const d=await (await fetch('/api/state')).json();
  const cards=document.getElementById('cards');cards.replaceChildren();
  [['SSH events',d.stats.events],['Failed',d.stats.failed],['Accepted',d.stats.accepted],['Alerts',d.stats.alerts],['Blocked IPs',d.stats.blocked]].forEach(function(x){
    const c=document.createElement('div');c.className='card';const b=document.createElement('b');b.textContent=x[1];const s=document.createElement('small');s.textContent=x[0];c.append(b,s);cards.appendChild(c)});
  const ch=document.getElementById('chart');ch.replaceChildren();const peak=Math.max.apply(null,d.series.concat([1]));
  d.series.forEach(function(v){const b=document.createElement('div');b.className='bar';b.style.height=Math.max(2,Math.round(100*v/peak))+'%';ch.appendChild(b)});
  fill('att',d.attempts);fill('ips',d.attackers);fill('alerts',d.alerts);
  const sv=d.stats.services||{};fill('svc',Object.keys(sv).sort().map(function(k){return [k,sv[k].events,sv[k].failed,sv[k].alerts]}));
}
load();setInterval(load,3000);
</script></body></html>"""


class WebServer:
    def __init__(self, core, host, port):
        self.core, self.host, self.port = core, host, port
        self.httpd = None

    def start(self):
        core, bind = self.core, self.host
        loopback = bind in ("127.0.0.1", "localhost", "::1")

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def _send(self, code, ctype, body, csp):
                data = body.encode("utf-8") if isinstance(body, str) else body
                self.send_response(code)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(data)))
                self.send_header("Content-Security-Policy", csp)
                self.send_header("X-Content-Type-Options", "nosniff")
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):
                if loopback:  # DNS-rebinding protection for a loopback-only service
                    host = (self.headers.get("Host") or "").rsplit(":", 1)[0].strip("[]")
                    if host not in ("127.0.0.1", "localhost", "::1"):
                        return self._send(403, "text/plain", "forbidden", "default-src 'none'")
                u = urlparse(self.path)
                if u.path == "/":
                    self._send(200, "text/html; charset=utf-8", DASH_HTML,
                               "default-src 'none'; style-src 'unsafe-inline'; "
                               "script-src 'unsafe-inline'; connect-src 'self'")
                elif u.path == "/api/state":
                    st, rows, _users, series = core.snapshot()
                    state = {
                        "stats": st, "series": series,
                        "attackers": [list(r) for r in rows[:15]],
                        "attempts": [list(r) for r in core.store.recent_attempts(25)],
                        "alerts": [[str(x)[:19].replace("T", " ") if i == 0 else x
                                    for i, x in enumerate(r)]
                                   for r in core.store.recent_alerts(15)[::-1]],
                    }
                    self._send(200, "application/json", json.dumps(state), "default-src 'none'")
                elif u.path == "/metrics":
                    self._send(200, "text/plain; version=0.0.4; charset=utf-8", core.metrics_text(),
                               "default-src 'none'")
                elif u.path == "/report":
                    try:
                        hours = int(parse_qs(u.query).get("hours", ["24"])[0])
                    except ValueError:
                        hours = 24
                    hours = max(1, min(hours, 2160))
                    self._send(200, "text/html; charset=utf-8",
                               render_report_html(core.store.report_data(hours)),
                               "default-src 'none'; style-src 'unsafe-inline'")
                else:
                    self._send(404, "text/plain", "not found", "default-src 'none'")

        self.httpd = ThreadingHTTPServer((self.host, self.port), Handler)
        self.port = self.httpd.server_address[1]
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def stop(self):
        if self.httpd:
            self.httpd.shutdown()
            self.httpd.server_close()


# ==========================================================================
# Live network sensor: raw packet capture (AF_PACKET) or pcap/pcapng replay, stdlib only
# ==========================================================================
# What it can see on the wire:
#   cleartext logins  - Telnet, FTP, HTTP (basic auth, login forms, attack signatures), SMTP AUTH, POP3, IMAP,
#                       MySQL, PostgreSQL, MSSQL, Redis, SIP: real "login failed" replies, usernames only
#   encrypted/binary  - SSH, RDP, VNC, SMB, HTTPS, TLS mail, ...: connection rates, TLS alerts, scanner banners
#   any port          - SYN / stealth port scans
# Passwords and tokens are parsed away and never stored, logged or forwarded.
NET_PARSERS = ("conn", "tls", "http", "telnet", "ftp", "smtp", "pop3", "imap", "mysql", "postgres", "mssql",
               "redis", "sip")
NET_TCP_DEFAULTS = (
    ("ssh", "conn", (22, 2222)),
    ("telnet", "telnet", (23, 2323)),
    ("ftp", "ftp", (21,)),
    ("smtp", "smtp", (25, 587, 2525)), ("smtp", "tls", (465,)),
    ("pop3", "pop3", (110,)), ("pop3", "tls", (995,)),
    ("imap", "imap", (143,)), ("imap", "tls", (993,)),
    ("http", "http", (80, 81, 591, 8000, 8008, 8080, 8081, 8088, 8888, 3128, 5984, 9200, 2375, 5985)),
    ("https", "tls", (443, 8443, 9443, 6443, 10250)),
    ("mysql", "mysql", (3306,)), ("postgres", "postgres", (5432,)), ("mssql", "mssql", (1433,)),
    ("oracle", "conn", (1521,)), ("redis", "redis", (6379,)), ("mongodb", "conn", (27017,)),
    ("memcached", "conn", (11211,)),
    ("rdp", "conn", (3389,)), ("vnc", "conn", (5900, 5901, 5902, 5903)), ("smb", "conn", (445, 139)),
    ("ldap", "conn", (389,)), ("ldaps", "tls", (636,)),
    ("sip", "sip", (5060,)), ("sip", "tls", (5061,)),
    ("mqtt", "conn", (1883,)), ("rsync", "conn", (873,)), ("irc", "conn", (6667,)), ("x11", "conn", (6000,)),
    ("svn", "conn", (3690,)), ("nfs", "conn", (2049,)),
)
NET_UDP_DEFAULTS = (("sip", "sip", (5060,)), ("snmp", "conn", (161,)))
_NET_PORT_CACHE = {}


def net_port_map(text=""):
    """(tcp, udp) maps  port -> (service, parser).  `text` adds or overrides ports:
    'ssh=2200; http=8081,8082; smtp=2526; imap=1993/tls' (the optional /parser picks how the payload is read)."""
    hit = _NET_PORT_CACHE.get(text)
    if hit:
        return hit
    tcp = {p: (svc, parser) for svc, parser, ports in NET_TCP_DEFAULTS for p in ports}
    udp = {p: (svc, parser) for svc, parser, ports in NET_UDP_DEFAULTS for p in ports}
    default_parser = {}
    for svc, parser, _ in NET_TCP_DEFAULTS:
        default_parser.setdefault(svc, parser)
    for entry in re.split(r"[;\n]+", text or ""):
        svc, sep, ports = entry.partition("=")
        svc = svc.strip().lower()
        if not sep or not re.fullmatch(r"[a-z0-9_-]{1,20}", svc):
            continue
        for tok in re.split(r"[,\s]+", ports.strip()):
            m = re.fullmatch(r"(\d{1,5})(?:/(\w+))?", tok)
            if not m or not 0 < int(m.group(1)) < 65536:
                continue
            parser = (m.group(2) or default_parser.get(svc, "conn")).lower()
            if parser not in NET_PARSERS:
                parser = "conn"
            tcp[int(m.group(1))] = (svc, parser)
            if parser == "sip" or svc == "snmp":
                udp[int(m.group(1))] = (svc, parser)
    if len(_NET_PORT_CACHE) > 50:
        _NET_PORT_CACHE.clear()
    _NET_PORT_CACHE[text] = (tcp, udp)
    return tcp, udp


def local_addresses():
    """Addresses of this machine (the sensor treats traffic to them as 'attacks on me')."""
    addrs = {"127.0.0.1", "::1"}
    try:
        out = subprocess.run(["ip", "-o", "addr"], capture_output=True, text=True, timeout=5).stdout
        for ln in out.splitlines():
            m = re.search(r"\binet6? ([0-9a-fA-F:.]+)/", ln)
            if m:
                addrs.add(norm_ip(m.group(1)) or m.group(1))
    except (OSError, subprocess.SubprocessError):
        pass
    try:
        addrs.update(norm_ip(i[4][0]) or i[4][0] for i in socket.getaddrinfo(HOSTNAME, None))
    except OSError:
        pass
    return addrs


# ---- frame decoding -------------------------------------------------------
_ETH_LINKS = (1,)                       # DLT_EN10MB
_RAW_LINKS = (12, 14, 101, 228, 229)    # DLT_RAW variants
HATYPE_LINK = {1: 1, 772: 1, 65534: 101, 768: 101, 769: 101, 776: 101, 778: 101}  # AF_PACKET sockaddr_ll.hatype


def _ip_start(frame, link):
    """Offset of the IP header inside a captured frame, or None if it is not IPv4/IPv6."""
    n = len(frame)
    if link in _ETH_LINKS:
        if n < 15:
            return None
        et, off = (frame[12] << 8) | frame[13], 14
        while et in (0x8100, 0x88A8, 0x9100) and n >= off + 5:     # 802.1Q / QinQ
            et, off = (frame[off + 2] << 8) | frame[off + 3], off + 4
        return off if et in (0x0800, 0x86DD) else None
    if link == 113:                       # Linux cooked v1
        if n < 17:
            return None
        return 16 if ((frame[14] << 8) | frame[15]) in (0x0800, 0x86DD) else None
    if link == 276:                       # Linux cooked v2
        if n < 21:
            return None
        return 20 if ((frame[0] << 8) | frame[1]) in (0x0800, 0x86DD) else None
    if link == 0:                         # BSD loopback: 4-byte address family
        off = 4
    elif link in _RAW_LINKS:
        off = 0
    else:
        return None
    return off if n > off and (frame[off] >> 4) in (4, 6) else None


def _decode_ip(frame, off):
    """-> (family, src_off, dst_off, proto, l4_off, end) for unfragmented TCP/UDP, else None."""
    n = len(frame)
    v = frame[off] >> 4
    if v == 4:
        ihl = (frame[off] & 15) * 4
        if ihl < 20 or n < off + ihl:
            return None
        if ((frame[off + 6] & 0x1F) << 8) | frame[off + 7]:        # not the first fragment
            return None
        proto = frame[off + 9]
        total = (frame[off + 2] << 8) | frame[off + 3]
        end = off + total if ihl <= total <= n - off else n        # trims Ethernet padding; 0 = TSO/GRO frame
        return 4, off + 12, off + 16, proto, off + ihl, end
    if v == 6 and n >= off + 40:
        proto, p = frame[off + 6], off + 40
        plen = (frame[off + 4] << 8) | frame[off + 5]
        end = p + plen if plen and p + plen <= n else n
        for _ in range(6):                                          # skip extension headers
            if proto in (0, 43, 60):
                if n < p + 8:
                    return None
                proto, p = frame[p], p + (frame[p + 1] + 1) * 8
            elif proto == 51:
                if n < p + 8:
                    return None
                proto, p = frame[p], p + (frame[p + 1] + 2) * 4
            else:
                break
        if proto == 44:
            return None
        return 6, off + 8, off + 24, proto, p, end
    return None


# ---- pcap / pcapng reader -------------------------------------------------
def iter_pcap(path):
    """Yield (timestamp, linktype, frame) from a classic pcap or a pcapng file."""
    with open(path, "rb") as f:
        head = f.read(4)
        if head == b"\x0a\x0d\x0d\x0a":
            f.seek(0)
            yield from _iter_pcapng(f)
            return
        magics = {b"\xd4\xc3\xb2\xa1": ("<", 1e-6), b"\xa1\xb2\xc3\xd4": (">", 1e-6),
                  b"\x4d\x3c\xb2\xa1": ("<", 1e-9), b"\xa1\xb2\x3c\x4d": (">", 1e-9)}
        if head not in magics:
            raise ValueError("not a pcap/pcapng capture file")
        end, unit = magics[head]
        hdr = f.read(20)
        if len(hdr) < 20:
            return
        link = struct.unpack(end + "I", hdr[16:20])[0] & 0x0FFFFFFF
        while True:
            rec = f.read(16)
            if len(rec) < 16:
                return
            sec, frac, incl, _orig = struct.unpack(end + "IIII", rec)
            data = f.read(incl)
            if len(data) < incl:
                return
            yield sec + frac * unit, link, data


def _iter_pcapng(f):
    links, end = [], "<"
    while True:
        h = f.read(8)
        if len(h) < 8:
            return
        btype = struct.unpack("<I", h[:4])[0]
        if btype == 0x0A0D0D0A:                                     # section header: learn endianness
            body = f.read(struct.unpack("<I", h[4:])[0] - 8)
            end = "<" if body[:4] == b"\x4d\x3c\x2b\x1a" else ">"
            links = []
            continue
        btype, blen = struct.unpack(end + "II", h)
        body = f.read(blen - 8)
        if len(body) < blen - 8:
            return
        body = body[:-4]                                            # trailing length
        if btype == 1 and len(body) >= 8:                           # interface description
            link = struct.unpack(end + "H", body[:2])[0]
            unit, i = 1e-6, 8
            while i + 4 <= len(body):                               # options: find if_tsresol (9)
                code, ln = struct.unpack(end + "HH", body[i:i + 4])
                if code == 0:
                    break
                if code == 9 and ln >= 1:
                    r = body[i + 4]
                    unit = 2.0 ** -(r & 0x7F) if r & 0x80 else 10.0 ** -r
                i += 4 + ((ln + 3) & ~3)
            links.append((link, unit))
        elif btype == 6 and len(body) >= 20:                        # enhanced packet
            ifid, hi, lo, cap, _orig = struct.unpack(end + "IIIII", body[:20])
            if ifid < len(links):
                link, unit = links[ifid]
                yield ((hi << 32) | lo) * unit, link, body[20:20 + cap]


# ---- cleartext protocol helpers -------------------------------------------
HTTP_REQ_LINE = re.compile(r"^([A-Z]{3,10}) (\S+)(?: HTTP/\d(?:\.\d)?)?$")
HTTP_START = re.compile(rb"[A-Z]{3,10} \S")
HTTP_STATUS = re.compile(rb"HTTP/\d(?:\.\d)? (\d{3})")
SSH_SCANNER = re.compile(r"(?i)^SSH-1\.|^SSH-\d\.\d-(?:Nmap|zgrab|masscan|libssh[_-]|paramiko|AsyncSSH|"
                         r"sshscan|ssh-scan|hydra|medusa|ncrack|patator)")
SIP_SCANNER = re.compile(r"(?i)friendly-scanner|sipvicious|sipcli|sundayddr|iwar|vaxsipuseragent|sip-scan|"
                         r"pplsip|sipscan")
REDIS_ABUSE = re.compile(rb"(?i)(?:config(?:\s+|\r\n\$\d+\r\n)set(?:\s+|\r\n\$\d+\r\n)(?:dir|dbfilename)\b|"
                         rb"(?:slaveof|replicaof)\s+\d|module(?:\s+|\r\n\$\d+\r\n)load)")
TELNET_FAIL = ("login incorrect", "login failed", "authentication failed", "access denied", "incorrect password",
               "bad password", "invalid password", "login invalid", "wrong password", "authentication failure")
TLS_FATAL = {10, 20, 40, 47, 50, 70, 71, 112}
BODY_CATEGORIES = ("sql_injection", "command_injection", "log4shell", "shellshock", "php_injection")
_FORM_KEYS = ("log", "username", "user", "uname", "userid", "login", "email", "j_username", "name")


def _strip_iac(data):
    """Remove Telnet option negotiation (IAC ...) from a byte string."""
    if 0xFF not in data:
        return data
    out, i, n = bytearray(), 0, len(data)
    while i < n:
        b = data[i]
        if b != 0xFF or i + 1 >= n:
            out.append(b)
            i += 1
            continue
        c = data[i + 1]
        if c == 0xFF:
            out.append(0xFF)
            i += 2
        elif c == 0xFA:                                              # subnegotiation .. IAC SE
            j = data.find(b"\xff\xf0", i + 2)
            i = n if j < 0 else j + 2
        elif 0xFB <= c <= 0xFE:
            i += 3
        else:
            i += 2
    return bytes(out)


def _b64(s):
    try:
        return base64.b64decode(s.strip() + "=" * (-len(s.strip()) % 4), validate=False)
    except ValueError:
        return b""


def _plain_user(s):
    """User name from a SASL PLAIN blob (authzid NUL authcid NUL password). The password is dropped."""
    parts = _b64(s).split(b"\x00")
    return (parts[1] if len(parts) >= 3 else parts[0]).decode("utf-8", "replace")[:64]


def _form_user(body):
    try:
        q = {k.lower(): v for k, v in parse_qs(body).items()}
        for k in _FORM_KEYS:
            if q.get(k):
                return q[k][0][:64]
    except ValueError:
        pass
    m = re.search(r'"(?:username|user|login|email)"\s*:\s*"([^"]{1,64})"', body)
    return m.group(1) if m else ""


class _NetFlow:
    __slots__ = ("cip", "cport", "sip", "sport", "svc", "t", "nxt", "buf", "user", "state", "pend", "skip",
                 "line", "tags")

    def __init__(self, cip, cport, sip, sport, svc, ts):
        self.cip, self.cport, self.sip, self.sport, self.svc, self.t = cip, cport, sip, sport, svc, ts
        self.nxt, self.buf, self.user, self.state = [None, None], b"", "", ""
        self.pend, self.skip, self.line, self.tags = deque(), 0, b"", {}


class NetSensor(threading.Thread):
    """Reads packets, follows TCP conversations and turns them into the same events the log parsers produce."""

    def __init__(self, core, scope_all=None, replay=False):
        super().__init__(daemon=True, name="net-sensor")
        self.core, self.cfg, self.det = core, core.cfg, core.netdet
        self.scope_all = (core.cfg.net_scope == "all") if scope_all is None else scope_all
        self.tcp, self.udp = net_port_map(core.cfg.net_ports)
        self.stop_evt = threading.Event()
        self.replay = replay
        self.local, self.local_t = set(), 0.0
        self.flows, self.sip = {}, {}
        self.n = 0
        self.stats = Counter()
        self.proc = None
        self._err_t = 0.0

    # -- lifecycle -----------------------------------------------------------
    def stop(self):
        self.stop_evt.set()
        if self.proc:
            try:
                self.proc.terminate()
            except OSError:
                pass

    def log(self, msg):
        self.core.log(msg)

    def run(self):
        try:
            self._capture()
        except Exception as e:
            self.log(f"Network sensor stopped: {type(e).__name__}: {e}")

    def _open(self):
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        if self.cfg.net_iface:
            s.bind((self.cfg.net_iface, 0))
        try:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8 * 1024 * 1024)
        except OSError:
            pass
        s.settimeout(1.0)
        return s

    def _capture(self):
        where = self.cfg.net_iface or "all interfaces"
        try:
            sock = self._open()
        except PermissionError:
            if os.geteuid() != 0 and shutil.which("sudo"):
                self.log("Network sensor: no raw-socket permission - trying a small capture helper via 'sudo -n'")
                return self._capture_helper(where)
            self.log("Network sensor NOT started: packet capture needs root. Run with sudo "
                     "(sudo ./run.sh) or install the service (deploy/install.sh).")
            return
        except (OSError, AttributeError) as e:
            self.log(f"Network sensor NOT started: raw packet sockets unavailable ({e}). Linux only.")
            return
        self.log(f"Network sensor capturing on {where} ({'whole segment' if self.scope_all else 'traffic to this host'})")
        last_report = time.time()
        try:
            while not self.stop_evt.is_set():
                try:
                    data, addr = sock.recvfrom(65535)
                except socket.timeout:
                    continue
                self._feed(data, HATYPE_LINK.get(addr[3]), time.time(), addr[2], addr[0])
                if time.time() - last_report > 3600:
                    last_report = time.time()
                    self.log(f"Network sensor: {self.stats['packets']} packets, {self.stats['events']} events so far")
        finally:
            sock.close()

    def _capture_helper(self, where):
        cmd = ["sudo", "-n", sys.executable or "python3", os.path.abspath(__file__), "--capture-helper"]
        if self.cfg.net_iface:
            cmd.append(self.cfg.net_iface)
        try:
            self.proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except OSError as e:
            self.log(f"Network sensor NOT started: {e}")
            return
        out, hdr = self.proc.stdout, struct.Struct("!dHBBI")
        self.log(f"Network sensor capturing on {where} through the sudo helper")
        while not self.stop_evt.is_set():
            raw = out.read(hdr.size)
            if len(raw) < hdr.size:
                err = (self.proc.stderr.read() or b"").decode("utf-8", "replace").strip()[-200:]
                if not self.stop_evt.is_set():
                    self.log("Network sensor helper ended"
                             + (f": {err}" if err else " - 'sudo -n' needs passwordless sudo; otherwise start with sudo"))
                return
            ts, hatype, pkttype, nlen, flen = hdr.unpack(raw)
            ifname = out.read(nlen).decode("ascii", "replace")
            frame = out.read(flen)
            if len(frame) < flen:
                return
            self._feed(frame, HATYPE_LINK.get(hatype), ts, pkttype, ifname)

    def replay_pcap(self, path):
        """Feed a capture file through the sensor. Returns the number of packets read."""
        count = 0
        for ts, link, frame in iter_pcap(path):
            self._feed(frame, link, ts, None, "")
            count += 1
        return count

    def _feed(self, frame, link, ts, pkttype, ifname):
        if link is None:
            return
        self.stats["packets"] += 1
        try:
            self.process_frame(frame, link, ts, pkttype, ifname)
        except Exception as e:      # a malformed packet must never stop the sensor
            if time.time() - self._err_t > 10:
                self._err_t = time.time()
                self.log(f"Network sensor: skipped a packet ({type(e).__name__}: {e})")

    # -- helpers -------------------------------------------------------------
    @staticmethod
    def _addr(frame, fam, o):
        if fam == 4:
            return socket.inet_ntoa(frame[o:o + 4])
        a = socket.inet_ntop(socket.AF_INET6, frame[o:o + 16])
        return norm_ip(a) if a.startswith("::ffff:") else a

    def _is_local(self, ip):
        return ip in self.local or ip.startswith("127.")

    def _housekeeping(self, ts):
        if not self.replay and not self.scope_all and time.time() - self.local_t > 60:
            self.local, self.local_t = local_addresses(), time.time()
        for k in [k for k, f in self.flows.items() if ts - f.t > 300]:
            del self.flows[k]
        if len(self.flows) > 20000:
            for k in sorted(self.flows, key=lambda k: self.flows[k].t)[:5000]:
                del self.flows[k]
        for k in [k for k, v in self.sip.items() if ts - v[2] > 120]:
            del self.sip[k]

    @staticmethod
    def _fresh(f, d, seq, data):
        """Drop retransmitted bytes so a repeated 'login failed' is counted once."""
        nxt = f.nxt[d]
        end = (seq + len(data)) & 0xFFFFFFFF
        if nxt is not None:
            behind = (nxt - seq) & 0xFFFFFFFF
            if 0 < behind < 0x80000000:
                if behind >= len(data):
                    return b""
                data = data[behind:]
        f.nxt[d] = end
        return data

    def _ev(self, ts, f, etype, user, note="", **kw):
        raw = f"[net] {f.svc} {f.cip}:{f.cport} -> {f.sip}:{f.sport} {note}"
        return _net_event(ts, etype, f.cip, user or "<unknown>", f.svc, raw, f.cport, f.sport, **kw)

    def _emit(self, evs):
        for ev in evs:
            self.stats["events"] += 1
            self.core.handle_event(ev)

    # -- packet path -----------------------------------------------------------
    def _orient(self, src, dst, svc_s, svc_d, sport, dport, probe, flags):
        """True: client -> server, False: server -> client, None: not interesting."""
        dl, sl = self._is_local(dst), self._is_local(src)
        if self.scope_all or (dl and sl):
            if svc_d and not svc_s:
                return True
            if svc_s and not svc_d:
                return False
            if svc_s and svc_d:
                return True if flags & 0x12 == 0x02 else (False if flags & 0x12 == 0x12 else dport <= sport)
            return True if probe else None
        if dl:
            return True
        if sl:
            return False
        return None

    def process_frame(self, frame, link, ts, pkttype=None, ifname=""):
        self.n += 1
        if self.n % 4000 == 1:
            self._housekeeping(ts)
        if pkttype == 0 and ifname == "lo":          # loopback frames are captured twice (out + in)
            return
        off = _ip_start(frame, link)
        if off is None:
            return
        h = _decode_ip(frame, off)
        if h is None:
            return
        fam, so, do, proto, l4, end = h
        if proto == 6:
            self._tcp(frame, fam, so, do, l4, end, ts)
        elif proto == 17 and end - l4 >= 8:
            self._udp(frame, fam, so, do, l4, end, ts)

    def _tcp(self, frame, fam, so, do, l4, end, ts):
        if end - l4 < 20:
            return
        sport, dport = (frame[l4] << 8) | frame[l4 + 1], (frame[l4 + 2] << 8) | frame[l4 + 3]
        flags = frame[l4 + 13]
        svc_s, svc_d = self.tcp.get(sport), self.tcp.get(dport)
        syn = flags & 0x12 == 0x02
        stealth = (not syn) and (flags == 0 or flags & 0x3F == 0x29 or flags & 0x17 == 0x01)
        if not (svc_s or svc_d or syn or stealth):
            return
        src, dst = self._addr(frame, fam, so), self._addr(frame, fam, do)
        c2s = self._orient(src, dst, svc_s, svc_d, sport, dport, syn or stealth, flags)
        if c2s is None:
            return
        if c2s:
            cip, cport, sip, sprt, svc = src, sport, dst, dport, svc_d
        else:
            cip, cport, sip, sprt, svc = dst, dport, src, sport, svc_s
        if c2s and (syn or stealth):
            self.flows.pop((cip, cport, sip, sprt), None)
            for ev, alerts in self.det.syn(ts, cip, sip, sprt, svc[0] if svc else None,
                                           svc[1] if svc else None, stealth):
                self.core.handle_net(ev, alerts)
            return
        if not svc:
            return
        key = (cip, cport, sip, sprt)
        doff = (frame[l4 + 12] >> 4) * 4
        payload = frame[l4 + doff:end] if doff >= 20 else b""
        if payload and self.cfg.net_inspect:
            self._payload(key, cip, cport, sip, sprt, svc, c2s, payload,
                          struct.unpack_from("!I", frame, l4 + 4)[0], ts)
        if flags & 0x05:                               # FIN / RST: conversation over
            self.flows.pop(key, None)

    def _udp(self, frame, fam, so, do, l4, end, ts):
        sport, dport = (frame[l4] << 8) | frame[l4 + 1], (frame[l4 + 2] << 8) | frame[l4 + 3]
        svc_s, svc_d = self.udp.get(sport), self.udp.get(dport)
        if not (svc_s or svc_d):
            return
        src, dst = self._addr(frame, fam, so), self._addr(frame, fam, do)
        c2s = self._orient(src, dst, svc_s, svc_d, sport, dport, False, 0)
        if c2s is None:
            return
        if c2s:
            cip, cport, sip, sprt, svc = src, sport, dst, dport, svc_d
        else:
            cip, cport, sip, sprt, svc = dst, dport, src, sport, svc_s
        if not svc:
            return
        payload = frame[l4 + 8:end]
        if svc[1] == "sip":
            if self.cfg.net_inspect and payload:
                self._emit(self._p_sip(cip, cport, sip, sprt, svc[0], c2s, payload, ts))
        elif c2s:                                       # e.g. SNMP: every datagram is a guess
            for ev, alerts in self.det.syn(ts, cip, sip, sprt, svc[0], svc[1]):
                self.core.handle_net(ev, alerts)

    def _payload(self, key, cip, cport, sip, sprt, svc, c2s, payload, seq, ts):
        name, parser = svc
        if parser == "tls":
            if not c2s:
                self._emit(self._tls(ts, cip, cport, sip, sprt, name, payload))
            return
        if parser == "conn":
            if c2s and name == "ssh" and payload[:4] == b"SSH-":
                banner = payload[:80].split(b"\r")[0].split(b"\n")[0].decode("latin-1")
                if SSH_SCANNER.search(banner):
                    self._emit([_net_event(ts, "probe", cip, "<n/a>", name,
                                           f"[net] ssh {cip}:{cport} -> {sip}:{sprt} client banner {banner}",
                                           cport, sprt, detail=banner, category="scanner_ua", ua=banner)])
            return
        f = self.flows.get(key)
        if f is None:
            f = self.flows[key] = _NetFlow(cip, cport, sip, sprt, name, ts)
        f.t = ts
        if parser == "sip":
            self._emit(self._p_sip(cip, cport, sip, sprt, name, c2s, payload, ts))
            return
        data = self._fresh(f, 0 if c2s else 1, seq, payload)
        if data:
            self._emit(getattr(self, "_p_" + parser)(f, c2s, data, ts))

    # -- TLS ---------------------------------------------------------------------
    def _tls(self, ts, cip, cport, sip, sprt, name, d):
        """Server-side fatal alerts / plain-HTTP replies mean a client that cannot (or will not) do TLS."""
        if (len(d) >= 7 and d[0] == 0x15 and d[1] == 3 and d[3] == 0 and d[4] == 2 and d[5] == 2
                and d[6] in TLS_FATAL) or d[:12] == b"HTTP/1.1 400":
            return [_net_event(ts, "preauth_close", cip, "<n/a>", name,
                               f"[net] {name} {cip}:{cport} -> {sip}:{sprt} TLS handshake refused", cport, sprt,
                               category="tls_error")]
        return []

    # -- HTTP --------------------------------------------------------------------
    def _p_http(self, f, c2s, data, ts):
        out = []
        if c2s:
            buf = f.buf + data
            while buf:
                if f.skip:
                    n = min(f.skip, len(buf))
                    buf, f.skip = buf[n:], f.skip - n
                    continue
                i = buf.find(b"\r\n\r\n")
                if i < 0:
                    if len(buf) > 16384 or not HTTP_START.match(buf):
                        buf = b""
                    break
                head, buf = buf[:i], buf[i + 4:]
                f.skip = self._http_request(f, head, buf, ts, out)
            f.buf = buf
            return out
        m = HTTP_STATUS.match(data)
        if not m:
            return out
        status = int(m.group(1))
        if status < 200 and status != 101:
            return out
        p = f.pend.popleft() if f.pend else None
        if p is None:
            if status in (400, 403, 404, 405, 414, 444):
                out.append(self._ev(ts, f, "web_404", "<n/a>", f"HTTP {status}", status=status))
        elif p["done"]:
            pass
        elif status == 401 and p["auth_user"]:
            out.append(self._ev(ts, f, "failed", p["auth_user"], f"HTTP 401 {p['target'][:80]}", method="basic",
                                detail=f"{p['method']} {p['target']}", category="basic_auth", status=401, ua=p["ua"]))
        elif p["login"] and status in (200, 401, 403, 429):
            out.append(self._ev(ts, f, "failed", p["form_user"] or "<form login>", f"login form {p['target'][:80]}",
                                method="form", detail=f"{p['method']} {p['target']}", category="login_post",
                                status=status, ua=p["ua"]))
        elif status in (400, 403, 404, 405, 414, 444):
            out.append(self._ev(ts, f, "web_404", "<n/a>", f"HTTP {status}", status=status))
        return out

    def _http_request(self, f, head, rest, ts, out):
        """Inspect one request head (+ whatever of the body is already here). Returns body bytes still to skip."""
        lines = head.decode("latin-1").split("\r\n")
        m = HTTP_REQ_LINE.match(lines[0][:2000])
        if not m:
            return 0
        method, target = m.group(1), m.group(2)
        hdr = {}
        for ln in lines[1:80]:
            k, _, v = ln.partition(":")
            hdr.setdefault(k.strip().lower(), v.strip())
        ua = hdr.get("user-agent", "")[:200]
        try:
            clen = max(0, min(int(hdr.get("content-length", "0")), 1 << 24))
        except ValueError:
            clen = 0
        decoded = unquote(unquote(target))[:500]
        body = rest[:min(clen, 4096)].decode("latin-1") if method in ("POST", "PUT", "PATCH") else ""
        blob = "\n".join(lines[1:])[:8000]
        body_dec = unquote(unquote(body))
        category = next((n for n, rx in WEB_ATTACKS
                         if rx.search(decoded) or (n in ("log4shell", "shellshock") and rx.search(blob))
                         or (n in BODY_CATEGORIES and body_dec and rx.search(body_dec))), None)
        auth_user, auth = "", hdr.get("authorization", "")
        if auth[:6].lower() == "basic ":
            auth_user = _b64(auth[6:]).split(b":", 1)[0].decode("utf-8", "replace")[:64] or "<empty>"
        elif auth[:7].lower() == "digest ":
            am = re.search(r'username="([^"]*)"', auth)
            auth_user = am.group(1)[:64] if am else "<digest>"
        login = method == "POST" and bool(LOGIN_PATHS.search(decoded))
        detail = f"{method} {decoded}".strip()
        done = True
        if category:
            out.append(self._ev(ts, f, "web_attack", "<n/a>", f"{category} {decoded[:80]}", method=method,
                                detail=detail, category=category, ua=ua))
        elif SENSITIVE_PATHS.search(decoded):
            out.append(self._ev(ts, f, "probe", "<n/a>", f"sensitive path {decoded[:80]}", method=method,
                                detail=detail, category="sensitive_path", ua=ua))
        elif BAD_UA.search(ua):
            out.append(self._ev(ts, f, "probe", "<n/a>", f"scanner user-agent {ua[:60]}", method=method,
                                detail=detail, category="scanner_ua", ua=ua))
        else:
            done = False
        f.pend.append({"method": method, "target": decoded, "auth_user": auth_user, "login": login,
                       "form_user": _form_user(body) if login else "", "ua": ua, "done": done})
        if len(f.pend) > 32:
            f.pend.popleft()
        return clen

    # -- Telnet ------------------------------------------------------------------
    def _p_telnet(self, f, c2s, data, ts):
        out, clean = [], _strip_iac(data)
        if c2s:
            for b in clean:
                if b in (10, 13):
                    if f.line:
                        if f.state == "user":
                            f.user = f.line.decode("latin-1")[:64]
                            f.state = ""
                        elif f.state == "pass":            # the password is thrown away right here
                            f.state = "passed"
                        f.line = b""
                elif b in (8, 127):
                    f.line = f.line[:-1]
                elif 32 <= b < 127 and len(f.line) < 64:
                    f.line += bytes((b,))
            return out
        text = clean.decode("latin-1")
        low = text.lower()
        failed = any(k in low for k in TELNET_FAIL)
        tail = low.rstrip("\x00 \r\n\t")
        user_prompt = bool(re.search(r"(?:login|username|user name)\s*:?$", tail))
        pass_prompt = bool(re.search(r"password\s*:?$", tail))
        if f.state == "passed" and pass_prompt and not failed:   # Cisco-style: password asked again
            failed = True
        if failed:
            out.append(self._ev(ts, f, "failed", f.user, "login rejected", method="password"))
            f.state, f.user = "", ""
        elif f.state == "passed" and ("last login" in low or "welcome" in low or re.search(r"[#$%>]$", tail)):
            out.append(self._ev(ts, f, "accepted", f.user, "login accepted", method="password"))
            f.state = "ok"
        if user_prompt:
            f.state = "user"
        elif pass_prompt:
            f.state = "pass"
        return out

    # -- FTP ---------------------------------------------------------------------
    def _p_ftp(self, f, c2s, data, ts):
        out = []
        for ln in data.decode("latin-1").split("\r\n"):
            ln = ln.strip()
            if not ln:
                continue
            if c2s:
                cmd, _, arg = ln.partition(" ")
                if cmd.upper() == "USER":
                    f.user = arg[:64]
                # PASS is deliberately ignored
            elif ln[:3] == "230" and ln[3:4] == " ":
                out.append(self._ev(ts, f, "accepted", f.user, "230 login ok", method="password"))
            elif ln[:3] == "530" and ln[3:4] == " " and "please login" not in ln.lower():
                out.append(self._ev(ts, f, "failed", f.user, "530 login incorrect", method="password"))
        return out

    # -- SMTP / POP3 / IMAP --------------------------------------------------------
    def _p_smtp(self, f, c2s, data, ts):
        out = []
        for ln in data.decode("latin-1").split("\r\n"):
            ln = ln.strip()
            if not ln:
                continue
            if c2s:
                st = f.state
                if st == "auth_plain":
                    f.user, f.state = _plain_user(ln), ""
                elif st == "auth_login_user":
                    f.user, f.state = _b64(ln).decode("utf-8", "replace")[:64], "auth_login_pass"
                elif st == "auth_login_pass":
                    f.state = ""
                elif st == "auth_cram":
                    f.user, f.state = (_b64(ln).decode("utf-8", "replace").split(" ")[0])[:64], ""
                elif ln[:5].upper() == "AUTH ":
                    parts = ln.split()
                    mech, arg = parts[1].upper(), (parts[2] if len(parts) > 2 else "")
                    if mech == "PLAIN":
                        if arg:
                            f.user = _plain_user(arg)
                        else:
                            f.state = "auth_plain"
                    elif mech == "LOGIN":
                        if arg:
                            f.user, f.state = _b64(arg).decode("utf-8", "replace")[:64], "auth_login_pass"
                        else:
                            f.state = "auth_login_user"
                    elif mech == "CRAM-MD5":
                        f.state = "auth_cram"
            else:
                code = ln[:3]
                if code == "235":
                    out.append(self._ev(ts, f, "accepted", f.user, "235 authenticated", method="sasl"))
                elif code in ("535", "534"):
                    out.append(self._ev(ts, f, "failed", f.user, f"{code} authentication failed", method="sasl"))
                elif code in ("550", "554") and "relay" in ln.lower():
                    out.append(self._ev(ts, f, "preauth_close", "<empty>", "relay denied", category="relay"))
        return out

    def _p_pop3(self, f, c2s, data, ts):
        out = []
        for ln in data.decode("latin-1").split("\r\n"):
            ln = ln.strip()
            if not ln:
                continue
            if c2s:
                cmd, _, arg = ln.partition(" ")
                cmd = cmd.upper()
                if cmd == "USER":
                    f.user, f.state = arg[:64], "user"
                elif cmd == "PASS":
                    f.state = "pass"
            elif ln.startswith("-ERR") and f.state in ("user", "pass"):
                out.append(self._ev(ts, f, "failed", f.user, "-ERR", method="password"))
                f.state = ""
            elif ln.startswith("+OK") and f.state == "pass":
                out.append(self._ev(ts, f, "accepted", f.user, "+OK logged in", method="password"))
                f.state = "ok"
        return out

    def _p_imap(self, f, c2s, data, ts):
        out = []
        for ln in data.decode("latin-1").split("\r\n"):
            ln = ln.strip()
            if not ln:
                continue
            if c2s:
                m = re.match(r'(\S+) LOGIN ("[^"]*"|\S+)', ln, re.I)
                if m:
                    f.tags[m.group(1)] = m.group(2).strip('"')[:64]
                else:
                    m = re.match(r"(\S+) AUTHENTICATE PLAIN (\S+)", ln, re.I)
                    if m:
                        f.tags[m.group(1)] = _plain_user(m.group(2))
                if len(f.tags) > 8:
                    f.tags.pop(next(iter(f.tags)))
            else:
                m = re.match(r"(\S+) (OK|NO)\b", ln)
                if m and m.group(1) in f.tags:
                    user = f.tags.pop(m.group(1))
                    ok = m.group(2) == "OK"
                    out.append(self._ev(ts, f, "accepted" if ok else "failed", user,
                                        "LOGIN " + m.group(2), method="password"))
        return out

    # -- databases ---------------------------------------------------------------------
    def _p_mysql(self, f, c2s, data, ts):
        out = []
        if len(data) < 5:
            return out
        seq, pl = data[3], data[4:]
        if not c2s:
            if f.state == "" and pl[0] == 10:
                f.state = "greeted"
            elif f.state == "authing":
                if pl[0] == 0x00:
                    out.append(self._ev(ts, f, "accepted", f.user, "OK packet", method="password"))
                    f.state = "done"
                elif pl[0] == 0xFF and len(pl) >= 3:
                    code = pl[1] | (pl[2] << 8)
                    msg = pl[3:].decode("latin-1")
                    um = re.search(r"for user '([^']*)'", msg)
                    if code == 1129:
                        out.append(self._ev(ts, f, "preauth_close", "<empty>", "host blocked", category="blocked"))
                    elif code in (1045, 1044, 1130, 1698):
                        out.append(self._ev(ts, f, "failed", um.group(1) if um else f.user,
                                            f"error {code}", method="password"))
                    f.state = "done"
        elif f.state == "greeted" and seq in (1, 2) and len(pl) >= 32:
            if len(pl) == 32:
                f.state = "tls"                                   # SSLRequest: the rest is encrypted
            elif int.from_bytes(pl[:4], "little") & 0x200:        # CLIENT_PROTOCOL_41
                end = pl.find(b"\x00", 32)
                f.user = pl[32:end if end > 0 else 96].decode("utf-8", "replace")[:64]
                f.state = "authing"
        return out

    def _p_postgres(self, f, c2s, data, ts):
        out = []
        if c2s:
            if f.state == "" and len(data) >= 8:
                ln, proto = struct.unpack("!II", data[:8])
                if proto == 196608:
                    parts = data[8:ln].split(b"\x00")
                    kv = dict(zip(parts[0::2], parts[1::2]))
                    f.user = kv.get(b"user", b"").decode("utf-8", "replace")[:64]
                    f.state = "authing"
                elif proto == 80877103:
                    f.state = "sslreq"
        elif f.state == "sslreq":
            f.state = "tls" if data[:1] == b"S" else ""
        elif f.state == "authing":
            if data[:1] == b"E" and (b"C28P01" in data or b"C28000" in data):
                um = re.search(rb'for user "([^"]*)"', data)
                out.append(self._ev(ts, f, "failed", um.group(1).decode("utf-8", "replace") if um else f.user,
                                    "FATAL 28P01", method="password"))
                f.state = "done"
            elif b"R\x00\x00\x00\x08\x00\x00\x00\x00" in data:
                out.append(self._ev(ts, f, "accepted", f.user, "AuthenticationOk", method="password"))
                f.state = "done"
        return out

    def _p_mssql(self, f, c2s, data, ts):
        if not c2s:
            i = data.find("Login failed for user".encode("utf-16-le"))
            if i >= 0:
                msg = data[i:i + 240].decode("utf-16-le", "ignore")
                um = re.search(r"Login failed for user '([^']*)'", msg)
                return [self._ev(ts, f, "failed", um.group(1) if um else "", "Login failed", method="password")]
        return []

    def _p_redis(self, f, c2s, data, ts):
        out = []
        if c2s:
            if REDIS_ABUSE.search(data):
                out.append(self._ev(ts, f, "web_attack", "<n/a>", "redis config/replication abuse",
                                    detail="redis CONFIG SET / SLAVEOF / MODULE LOAD", category="redis_abuse"))
            up = data.upper()
            i = up.find(b"AUTH")
            if i >= 0:
                args = [t for t in data[i + 4:].split(b"\r\n") if t and not t.startswith(b"$")][:2]
                args = [a.strip().decode("utf-8", "replace") for a in args]
                f.user = args[0][:64] if len(args) == 2 else "default"
                f.state = "authing"
        elif f.state == "authing":
            if data.startswith((b"-WRONGPASS", b"-ERR invalid password", b"-ERR invalid username-password")):
                out.append(self._ev(ts, f, "failed", f.user, "WRONGPASS", method="password"))
                f.state = ""
            elif data.startswith(b"+OK"):
                out.append(self._ev(ts, f, "accepted", f.user, "AUTH ok", method="password"))
                f.state = ""
        return out

    # -- SIP (UDP or TCP) --------------------------------------------------------------------
    def _p_sip(self, cip, cport, sip, sprt, name, c2s, data, ts):
        text = data[:4096].decode("latin-1")
        head, _, _ = text.partition("\r\n\r\n")
        lines = head.split("\r\n")
        hdr = {}
        for ln in lines[1:]:
            k, _, v = ln.partition(":")
            hdr.setdefault(k.strip().lower(), v.strip())
        cid = hdr.get("call-id") or hdr.get("i") or ""
        out = []
        fl = _NetFlow(cip, cport, sip, sprt, name, ts)
        if c2s:
            method = lines[0].split(" ", 1)[0]
            if not re.fullmatch(r"[A-Z]{3,10}", method):
                return out
            ua = hdr.get("user-agent", "")[:100]
            if SIP_SCANNER.search(ua):
                out.append(self._ev(ts, fl, "probe", "<n/a>", f"SIP scanner {ua}", method=method,
                                    detail=f"{method} {ua}", category="scanner_ua", ua=ua))
            auth = hdr.get("authorization") or hdr.get("proxy-authorization") or ""
            um = re.search(r'username="([^"]*)"', auth)
            if um and cid:
                if len(self.sip) > 4096:
                    self.sip.clear()
                self.sip[(cip, cid)] = (um.group(1)[:64], method, ts)
            return out
        m = re.match(r"SIP/2\.0 (\d{3})", lines[0])
        if not m:
            return out
        status = int(m.group(1))
        ent = self.sip.pop((cip, cid), None)
        if status in (401, 403, 407) and ent:
            out.append(self._ev(ts, fl, "failed", ent[0], f"SIP {status}", method="digest"))
        elif status == 403 and not ent:
            to = re.search(r"sip:([^@>;]+)@", hdr.get("to") or hdr.get("t") or "")
            out.append(self._ev(ts, fl, "failed", to.group(1) if to else "", "SIP 403", method="none"))
        elif status == 200 and ent and ent[1] == "REGISTER":
            out.append(self._ev(ts, fl, "accepted", ent[0], "SIP registered", method="digest"))
        return out


def capture_helper(iface=""):
    """Tiny privileged side of the sensor: reads raw frames and writes them to stdout (run through sudo)."""
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    if iface:
        s.bind((iface, 0))
    hdr, out = struct.Struct("!dHBBI"), sys.stdout.buffer
    try:
        while True:
            data, addr = s.recvfrom(65535)
            name = addr[0].encode("ascii", "replace")[:15]
            out.write(hdr.pack(time.time(), addr[3], addr[2], len(name), len(data)) + name + data)
            out.flush()
    except (BrokenPipeError, KeyboardInterrupt):
        pass


# ==========================================================================
# Core: wires everything together; shared by GUI and headless mode
# ==========================================================================
class Core:
    def __init__(self, cfg, emit, store):
        self.cfg, self.emit, self.store = cfg, emit, store
        self.allow = parse_allowlist(cfg.allowlist)
        self.dets = {}
        self.det = self._det("ssh")
        self.webdet = WebDetector(cfg, self.allow)
        self.netdet = NetDetector(cfg, self.allow, self._annotate)
        self.sensor = None
        self._pipe_lock = threading.Lock()  # several log sources feed one pipeline
        self.svc = defaultdict(lambda: {"events": 0, "failed": 0, "alerts": 0})
        self.blocker = Blocker(cfg, store, self.allow, self.log)
        self.sink = None
        self.geo = None
        self.notifier = None
        self.web = None
        self.engine = None
        self.janitor = None
        self.stop_evt = threading.Event()
        self.lock = threading.Lock()
        self.stats = {"events": 0, "failed": 0, "accepted": 0, "alerts": 0}
        self.attackers = {}
        self.users = Counter()
        self.buckets = Counter()
        self.attempts = deque(maxlen=500)
        self.seq = 0
        self._stopped = False
        self.syslog = None
        self._last_err = 0.0
        self.alert_types = Counter()
        self.feed = ThreatFeed(cfg, self.log)
        self.canary = set()
        self._rules()

    def _rules(self):
        self.canary = {u.strip().lower() for u in re.split(r"[,\s]+", self.cfg.canary_users) if u.strip()}

    def log(self, msg):
        self.emit("log", msg)

    def add_allow(self, ip):
        try:
            self.allow.append(ipaddress.ip_network(ip, strict=False))
        except ValueError:
            pass

    def start(self, engine=True):
        if self.cfg.geoip_db:
            try:
                self.geo = GeoIP(self.cfg.geoip_db)
                self.log(f"GeoIP database loaded: {self.cfg.geoip_db}")
            except Exception as e:
                self.log(f"GeoIP unavailable ({e})")
        if self.cfg.es_enabled:
            try:
                s = ESSink(self.cfg, self.log)
                s.start()
                self.sink = s
            except Exception as e:
                self.log(f"Elasticsearch unavailable ({e}) - running locally")
        self.notifier = Notifier(self.cfg, self.log)
        if self.cfg.syslog_target:
            try:
                self.syslog = SyslogForwarder(self.cfg.syslog_target, self.log)
                self.log(f"Forwarding alerts as CEF to {self.cfg.syslog_target}")
            except Exception as e:
                self.log(f"Syslog forwarding disabled: {e}")
        threading.Thread(target=self._feed_loop, daemon=True).start()
        if self.notifier.active:
            self.log("Notifications enabled" + (" (email)" if self.notifier.email_ready else "")
                     + (" (webhook)" if self.cfg.webhook_url else ""))
        if self.cfg.web_enabled:
            try:
                self.web = WebServer(self, self.cfg.web_host, self.cfg.web_port)
                self.web.start()
                self.log(f"Web dashboard: http://{self.cfg.web_host}:{self.web.port}/")
            except OSError as e:
                self.web = None
                self.log(f"Web dashboard failed to start: {e}")
        self.janitor = threading.Thread(target=self._janitor, daemon=True)
        self.janitor.start()
        if engine:
            self.engine = Engine(self)
            self.engine.start()
            if self.cfg.net_enabled:
                self.sensor = NetSensor(self)
                self.sensor.start()

    def _janitor(self):
        while not self.stop_evt.wait(5):
            try:
                self.blocker.expire()
                self.store.flush()
            except Exception as e:
                self.log(f"Janitor error: {e}")

    def stop(self):
        if self._stopped:
            return
        self._stopped = True
        self.stop_evt.set()
        if self.sensor:
            self.sensor.stop()
        if self.engine:
            self.engine.stop()
            self.engine.join(timeout=3)
        if self.web:
            self.web.stop()
        self.feed.wake.set()
        if self.syslog:
            self.syslog.close()
        if self.notifier:
            self.notifier.close()
        if self.sink:
            self.sink.close()
        self.store.flush()

    # -- event pipeline (engine thread)
    def handle_line(self, line, kind="syslog"):
        try:
            with self._pipe_lock:
                self._handle_line(line, kind)
        except Exception as e:  # one bad line (or a full disk) must never stop monitoring
            now = time.time()
            if now - self._last_err > 10:
                self._last_err = now
                self.log(f"Error processing a log line ({type(e).__name__}: {e}) - continuing")

    def _det(self, service):
        d = self.dets.get(service)
        if d is None:
            d = self.dets[service] = Detector(self.cfg, self.allow, service)
        return d

    def _handle_line(self, line, kind="syslog"):
        if kind.startswith("web"):
            ev = parse_web_line(line, "https" if kind == "web-https" else "http")
        else:
            ev = parse_line(line)
        if ev:
            self._handle_event(ev)

    def handle_event(self, ev):
        """Entry point for events that did not come from a text log (the network sensor)."""
        try:
            with self._pipe_lock:
                self._handle_event(ev)
        except Exception as e:
            now = time.time()
            if now - self._last_err > 10:
                self._last_err = now
                self.log(f"Error processing an event ({type(e).__name__}: {e}) - continuing")

    def handle_net(self, ev, alerts):
        """Alerts the network detector built from packet headers alone (connection rates, port scans)."""
        try:
            with self._pipe_lock:
                ip = ev["source_ip"]
                with self.lock:
                    self.stats["events"] += 1
                    a = self.attackers.setdefault(
                        ip, {"count": 0, "last": "", "users": set(), "risk": 0, "services": set()})
                    a["count"] += 1
                    a["country"] = ev.get("_geo", "")
                    a["last"] = ev["@timestamp"][11:19]
                    a["services"].add(ev["service"])
                alerts = alerts + self._rule_alerts(ev, ip, "probe")
                statuses = [self._on_alert(al) for al in alerts]
                result = next((s for s in statuses if s.startswith("BLOCKED")), "ALERT")
                self._log_attempt(ev, "probe", result, max((al["attempts"] for al in alerts), default=1))
                with self.lock:
                    self.attackers[ip]["risk"] = max(d.risk(ip) for d in (*self.dets.values(), self.webdet, self.netdet))
        except Exception as e:
            self.log(f"Error processing a network alert ({type(e).__name__}: {e}) - continuing")

    def _handle_event(self, ev):
        ip, et, ts = ev["source_ip"], ev["event_type"], ev["_ts"]
        self._annotate(ev)
        if et == "web_404":  # quiet: only counted for scanner detection, never stored
            for al in self.webdet.process_web(ev):
                self._on_alert(al)
            return
        self._record(ev)
        if self.sink:
            self.sink.add("event", ev)
        det = self._det(ev["service"])
        prior = det.fast_count(ip, ts) if et == "accepted" else 0
        base = self.webdet.process_web(ev) if et in WEB_TYPES else det.process(ev)
        statuses = [self._on_alert(al) for al in base + self._rule_alerts(ev, ip, et)]
        if et in ("failed", "accepted", "probe", "web_attack"):
            if et == "accepted":
                result, attempts = "Accepted", prior
            elif et == "failed":
                result, attempts = "Failed", det.fast_count(ip, ts)
            else:
                result, attempts = ("Attack" if et == "web_attack" else "Probe"), 1
            if any(s.startswith("BLOCKED") for s in statuses):
                result = next(s for s in statuses if s.startswith("BLOCKED"))
            elif statuses:
                result = "ALERT"
            self._log_attempt(ev, et, result, attempts)
        if et == "accepted":
            self.store.add_known_login(ev["username"], ip, ts)
        with self.lock:
            if ip in self.attackers:
                self.attackers[ip]["risk"] = max(d.risk(ip) for d in (*self.dets.values(), self.webdet, self.netdet))

    def _annotate(self, ev):
        try:
            a = ipaddress.ip_address(ev["source_ip"])
        except ValueError:
            return
        if not a.is_global:
            ev["_geo"] = LOCAL_LABEL
        elif self.geo:
            ev.update(geo_fields(self.geo.lookup(ev["source_ip"])))

    def _log_attempt(self, ev, kind, result, attempts):
        who = (ev.get("detail") or ev["username"]) if kind in ("probe", "web_attack") else ev["username"]
        geo, svc = ev.get("_geo", ""), ev["service"]
        self.store.add_attempt(ev["_ts"], ev["@timestamp"], ev["source_ip"], who, kind, result, attempts,
                               ev["auth_method"], geo, svc)
        row = (ev["@timestamp"][:19].replace("T", " "), ev["source_ip"], who, result, attempts, geo, svc)
        with self.lock:
            self.seq += 1
            self.attempts.append((self.seq, row))

    def _record(self, ev):
        et, svc, ip = ev["event_type"], ev["service"], ev["source_ip"]
        with self.lock:
            self.stats["events"] += 1
            sv = self.svc[svc]
            sv["events"] += 1
            if et in ("failed", "web_attack", "probe"):
                if et == "failed":
                    self.stats["failed"] += 1
                    sv["failed"] += 1
                    self.users[ev["username"]] += 1
                    self.buckets[int(time.time() // 60)] += 1
                a = self.attackers.setdefault(
                    ip, {"count": 0, "last": "", "users": set(), "risk": 0, "services": set()})
                a["count"] += 1
                a["country"] = ev.get("_geo", "")
                a["last"] = ev["@timestamp"][11:19]
                a["services"].add(svc)
                if et == "failed":
                    a["users"].add(ev["username"])
                if len(self.attackers) > 5000:
                    for k in sorted(self.attackers, key=lambda k: self.attackers[k]["count"])[:1000]:
                        del self.attackers[k]
                if len(self.users) > 5000:
                    self.users = Counter(dict(self.users.most_common(1000)))
            elif et == "accepted":
                self.stats["accepted"] += 1

    def _on_alert(self, al):
        status = "ALERT"
        ip = al["source_ip"]
        stale = time.time() - al["_ts"] > 3600  # replaying an old log: record it, never act on it
        if (self.cfg.auto_block and not stale
                and SEV_RANK[al["severity"]] >= SEV_RANK[self.cfg.block_min_severity]):
            if self.cfg.protect_known_logins and self.store.ip_trusted(ip, al["_ts"] - 86400):
                status = "ALERT (trusted IP)"
                self.log(f"Not auto-blocking {ip}: it has a successful login history")
            else:
                ok, msg = self.blocker.block(ip, al["alert_type"])
                if ok:
                    status = "BLOCKED (dry-run)" if self.cfg.block_dry_run else "BLOCKED"
                elif "already blocked" in msg:
                    status = "BLOCKED"
                else:
                    self.log(msg)
        if stale:
            status = "ALERT (historical)"
        al["status"] = status
        self.store.offender_alert(ip, al["_ts"])
        with self.lock:
            self.stats["alerts"] += 1
            self.alert_types[al["alert_type"]] += 1
            self.svc[al.get("service", "ssh")]["alerts"] += 1
        self.store.add_alert(al)
        if self.sink:
            self.sink.add("alert", al)
        self.emit("alert", al)
        if self.syslog:
            self.syslog.send(al)
        if self.notifier and not stale:
            self.notifier.notify(al)
        return status

    # -- rules that need more than the sliding windows
    def _rule_alerts(self, ev, ip, et):
        out, det, user = [], self._det(ev["service"]), ev["username"]

        def add(a):
            if a:
                out.append(a)

        if et in ("failed", "invalid_user", "accepted") and user.lower() in self.canary:
            if et == "accepted":
                add(det.extra_alert(ev, "honeypot_login", "critical",
                                    f"login SUCCEEDED on canary account '{user}'", target=user))
            else:
                add(det.extra_alert(ev, "honeypot_user", "high",
                                    f"attempt on canary account '{user}'", target=user))
        if et == "accepted":
            if self.cfg.alert_root_login and user == "root" and ev["service"] in ROOT_SERVICES:
                add(det.extra_alert(ev, "root_login", "high", "direct root login over SSH", target=user))
            if (self.cfg.new_source_alerts and self.store.user_has_logins(user)
                    and not self.store.login_known(user, ip)):
                add(det.extra_alert(ev, "new_login_source", "medium",
                                    f"first login for '{user}' from this IP", target=user))
        if (et in ("failed", "invalid_user", "accepted", "preauth_close", "max_auth", "probe", "web_attack")
                and self.feed.contains(ip)):
            det.bonus[ip] = max(det.bonus[ip], 30)
            add(det.extra_alert(ev, "known_bad_ip", "high",
                                f"IP is listed in a threat feed ({self.feed.count} entries)"))
        return out

    def _feed_loop(self):
        while not self.stop_evt.is_set():
            try:
                self.feed.refresh()
            except Exception as e:
                self.log(f"Threat feed error: {type(e).__name__}")
            self.feed.wake.wait(max(1, self.cfg.feed_refresh_hours) * 3600)
            self.feed.wake.clear()

    def reload(self, new):
        """Apply a freshly loaded Config in place (SIGHUP). Secrets are left untouched."""
        changed = []
        for f in fields(Config):
            if f.name not in SECRETS and getattr(self.cfg, f.name) != getattr(new, f.name):
                setattr(self.cfg, f.name, getattr(new, f.name))
                changed.append(f.name)
        self.allow[:] = parse_allowlist(self.cfg.allowlist)
        self._rules()
        self.feed.request_refresh()
        need = [n for n in changed if n.startswith(("log_path", "use_journal", "from_start", "web_",
                                                    "es_", "geoip", "syslog", "net_"))]
        self.log(f"Configuration reloaded ({len(changed)} change(s))"
                 + (f"; restart to apply: {', '.join(need)}" if need else ""))

    def metrics_text(self):
        st = self.snapshot()[0]
        with self.lock:
            types = dict(self.alert_types)
        lines = []
        for name, helptext, kind, val in (
                ("events_total", "SSH log events processed", "counter", st["events"]),
                ("failed_logins_total", "Failed SSH logins", "counter", st["failed"]),
                ("accepted_logins_total", "Accepted SSH logins", "counter", st["accepted"]),
                ("alerts_total", "Alerts raised", "counter", st["alerts"]),
                ("blocked_ips", "IPs currently tracked as blocked", "gauge", st["blocked"]),
                ("threat_feed_entries", "Entries loaded from threat feeds", "gauge", self.feed.count)):
            lines += [f"# HELP ssh_guard_{name} {helptext}", f"# TYPE ssh_guard_{name} {kind}",
                      f"ssh_guard_{name} {val}"]
        lines.append("# TYPE ssh_guard_alerts_by_type_total counter")
        for k, v in sorted(types.items()):
            lines.append(f'ssh_guard_alerts_by_type_total{{type="{k.replace(chr(34), "")}"}} {v}')
        return "\n".join(lines) + "\n"

    # -- GUI / web snapshots
    def snapshot(self):
        now = int(time.time() // 60)
        with self.lock:
            st = dict(self.stats)
            st["services"] = {k: dict(v) for k, v in self.svc.items()}
            top = sorted(self.attackers.items(),
                         key=lambda kv: (kv[1]["risk"], kv[1]["count"]), reverse=True)[:100]
            rows = [(ip, a["count"], a["last"], len(a["users"]), a["risk"], a.get("country", ""),
                     ",".join(sorted(a.get("services", ()))))
                    for ip, a in top]
            users = self.users.most_common(10)
            series = [self.buckets.get(now - 59 + i, 0) for i in range(60)]
            for k in [k for k in self.buckets if k < now - 120]:
                del self.buckets[k]
        st["blocked"] = self.store.count_blocks()
        return st, rows, users, series

    def new_attempts(self, last_seq):
        with self.lock:
            return self.seq, [r for s, r in self.attempts if s > last_seq]


# ==========================================================================
# Tkinter GUI
# ==========================================================================
SETTINGS_SPEC = {
    "Source": [
        ("log_path", "Log file", "str"),
        ("use_journal", "Use journald instead of file", "bool"),
        ("from_start", "Replay from start of log", "bool"),
        ("geoip_db", "GeoIP database (.mmdb, optional)", "str"),
        ("auto_sources", "Auto-detect service logs (nginx, apache, ftp, mail, db...)", "bool"),
        ("extra_sources", "More logs: kind=path; ... (web=, https=, syslog=)", "str")],
    "Detection": [
        ("threshold", "Fast threshold (failures)", "int"),
        ("window", "Fast window (s)", "int"),
        ("slow_threshold", "Slow threshold (failures)", "int"),
        ("slow_window", "Slow window (s)", "int"),
        ("spray_users", "Spray: distinct usernames", "int"),
        ("distributed_ips", "Distributed: distinct IPs", "int"),
        ("distributed_window", "Distributed window (s)", "int"),
        ("allowlist", "Allowlist (IP/CIDR, comma sep.)", "str")],
    "Response": [
        ("auto_block", "Auto-block offenders", "bool"),
        ("block_dry_run", "Dry-run (log only, no firewall change)", "bool"),
        ("block_ttl", "Block TTL (s, 0 = permanent)", "int"),
        ("block_backend", "Firewall backend", "choice:iptables,nft"),
        ("block_min_severity", "Auto-block min severity", "choice:medium,high,critical")],
    "Notifications": [
        ("gui_popup", "Pop-up window on high/critical alerts", "bool"),
        ("email_enabled", "Send email alerts", "bool"),
        ("smtp_host", "SMTP host", "str"),
        ("smtp_port", "SMTP port", "int"),
        ("smtp_security", "SMTP security", "choice:starttls,ssl,none"),
        ("smtp_user", "SMTP user", "str"),
        ("smtp_password", "SMTP password (not saved)", "secret"),
        ("mail_from", "From address", "str"),
        ("mail_to", "To address(es)", "str"),
        ("email_min_severity", "Notify min severity", "choice:medium,high,critical"),
        ("webhook_url", "Webhook URL (Slack/Discord)", "str")],
    "Elasticsearch": [
        ("es_enabled", "Send to Elasticsearch", "bool"),
        ("es_url", "URL", "str"),
        ("es_user", "User", "str"),
        ("es_password", "Password (not saved)", "secret"),
        ("es_api_key", "API key (not saved)", "secret"),
        ("es_verify", "Verify TLS certificates", "bool"),
        ("es_prefix", "Index prefix", "str")],
    "Web dashboard": [
        ("web_enabled", "Enable web dashboard", "bool"),
        ("web_host", "Bind address (keep 127.0.0.1)", "str"),
        ("web_port", "Port", "int")],
}

ADVANCED_SPEC = {
    "Advanced detection": [
        ("enum_users", "User enumeration: distinct invalid usernames", "int"),
        ("scan_threshold", "Scanner: pre-auth drops in window", "int"),
        ("canary_users", "Canary usernames (comma sep., must not exist)", "str"),
        ("alert_root_login", "Alert on direct root login", "bool"),
        ("new_source_alerts", "Alert on first login from a new IP (per user)", "bool")],
    "Response intelligence": [
        ("block_escalate", "Escalating bans for repeat offenders", "bool"),
        ("protect_known_logins", "Never auto-block IPs with prior successful logins", "bool")],
    "Threat intelligence": [
        ("feed_file", "Local blocklist file (IP/CIDR per line)", "str"),
        ("feed_urls", "Feed URLs (comma sep.)", "str"),
        ("feed_refresh_hours", "Refresh every (hours)", "int")],
    "Integrations": [
        ("syslog_target", "Syslog/CEF target (udp://host:514)", "str"),
        ("telegram_token", "Telegram bot token (not saved)", "secret"),
        ("telegram_chat_id", "Telegram chat ID", "str")],
    "Network sensor (live packets)": [
        ("net_enabled", "Watch the network (HTTP, HTTPS, Telnet, FTP, mail, DBs, RDP...) - needs root", "bool"),
        ("net_iface", "Interface (empty = all)", "str"),
        ("net_scope", "Scope (local = this host, all = whole segment)", "choice:local,all"),
        ("net_inspect", "Read cleartext protocols (usernames only, never passwords)", "bool"),
        ("net_ports", "Ports: service=port,port; ... (e.g. ssh=2200; http=8081)", "str"),
        ("net_conn_threshold", "Connections/window to a login service = guessing", "int"),
        ("net_flood_threshold", "Connections/window to any other service = flood", "int"),
        ("net_scan_ports", "Distinct ports probed = port scan", "int"),
        ("net_rate_override", "Per-service connection limits (ssh=10,rdp=10)", "str")],
    "Web & services": [
        ("web_attack_alerts", "Alert on web attack signatures (SQLi, XSS, traversal, RCE...)", "bool"),
        ("web_probe_threshold", "Probes of sensitive paths before alert", "int"),
        ("web_scan_threshold", "404/403/400 responses before scanner alert", "int"),
        ("thresholds_override", "Failure threshold per service (http=10,ftp=5)", "str")],
}

GUIDE_TEXT = """DESCRIPTION
This tool monitors SSH login attempts and detects brute force attacks by identifying multiple failed login attempts from the same IP. It also watches HTTP/HTTPS (nginx, Apache), Telnet, FTP, mail, MySQL, PostgreSQL, RDP, SIP and any PAM-based service.

HOW IT WORKS
 1. Monitors SSH authentication logs (/var/log/auth.log, /var/log/secure or journald)
 2. Analyzes failed login attempts
 3. Detects brute force patterns by threshold matching (fast, slow, spray, distributed)
 4. Blocks suspicious IPs (optional, iptables or nftables)
 5. Generates alerts and reports (pop-up, email, webhook, HTML reports, web dashboard)

FEATURES
 - Detects multiple failed SSH logins
 - Identifies suspicious IP addresses (risk score 0-100)
 - Real-time attack monitoring
 - Logs every failed login attempt (Attempts tab)
 - Auto blocking (optional, dry-run by default)
 - Email / alert notifications
 - Detailed reports and analytics (Reports tab)
 - User-friendly interface
 - Extra detections: user enumeration, scanners, canary users, root login, new login source
 - Web: SQLi/XSS/traversal/RCE signatures, sensitive-path probing, scanner user-agents, 404 floods
 - Many log sources at once: auto-detected (nginx, apache, vsftpd, mail, mysql...) or listed in Settings
 - Threat feeds, escalating bans, lock-out protection
 - SIEM export (CEF/syslog), Telegram, Prometheus /metrics, SIGHUP reload

TIPS
 - Use strong SSH credentials (prefer key-based authentication)
 - Change the default SSH port
 - Enable fail2ban for auto protection
 - Regularly review access logs

USE CASES
 - Protect SSH servers from brute force attacks
 - System administrators monitoring login attempts
 - Detecting unauthorized access attempts
 - Automated IP blocking and firewall integration
 - Security analytics and compliance monitoring
"""

if TK_OK:
    class App(tk.Tk):
        def __init__(self):
            super().__init__()
            self.title("SSH Brute Force Detector")
            self.geometry("1260x800")
            try:
                ttk.Style().theme_use("clam")
            except tk.TclError:
                pass
            self.cfg = load_config()
            self.store = Store()
            self.q = queue.Queue()
            self.core = None
            self.stopping = False
            self.vars = {}
            self.alert_rows = []
            self.ctx_ip = None
            self.attempt_seq = 0
            self.popup = None
            self.popup_lbl = None
            self._tick_n = 0
            self._dirty = False
            self._console_lines = 0
            self._build()
            self.alert_rows = list(self.store.recent_alerts(300))
            self._render_alerts()
            self._render_blocks()
            for row in reversed(self.store.recent_attempts(200)):
                self._add_attempt(row)
            self.after(200, self._poll)
            self.after(1000, self._tick)
            self.protocol("WM_DELETE_WINDOW", self._close)

        # ---------------- layout
        def _build(self):
            bar = ttk.Frame(self)
            bar.pack(fill="x", padx=8, pady=6)
            self.btn_start = ttk.Button(bar, text="Start monitoring", command=self.start)
            self.btn_stop = ttk.Button(bar, text="Stop", command=self.stop, state="disabled")
            self.btn_start.pack(side="left", padx=2)
            self.btn_stop.pack(side="left", padx=2)
            ttk.Button(bar, text="ES: top attackers (24h)", command=self.query_es).pack(side="left", padx=12)
            self.lbl_state = ttk.Label(bar, text="Idle", font=("TkDefaultFont", 10, "bold"))
            self.lbl_state.pack(side="right")

            cards = ttk.Frame(self)
            cards.pack(fill="x", padx=8)
            self.card = {}
            for key, title in (("events", "SSH events"), ("failed", "Failed logins"),
                               ("accepted", "Accepted"), ("alerts", "Alerts"), ("blocked", "Blocked IPs")):
                f = ttk.LabelFrame(cards, text=title)
                f.pack(side="left", fill="x", expand=True, padx=3)
                lbl = ttk.Label(f, text="0", font=("TkDefaultFont", 18, "bold"))
                lbl.pack(padx=10, pady=4)
                self.card[key] = lbl

            nb = ttk.Notebook(self)
            nb.pack(fill="both", expand=True, padx=8, pady=8)
            self._tab_dashboard(nb)
            self._tab_attempts(nb)
            self._tab_alerts(nb)
            self._tab_blocks(nb)
            self._tab_reports(nb)
            self._tab_settings(nb)
            self._tab_advanced(nb)
            self._tab_guide(nb)
            self._tab_console(nb)

            self.menu = tk.Menu(self, tearoff=0)
            self.menu.add_command(label="Block IP…", command=lambda: self._block_ip(self.ctx_ip))
            self.menu.add_command(label="Add to allowlist", command=lambda: self._allow_ip(self.ctx_ip))
            self.menu.add_command(label="Copy IP", command=self._copy_ip)

        def _tree(self, parent, cols, widths, height=10, titles=None):
            fr = ttk.Frame(parent)
            t = ttk.Treeview(fr, columns=cols, show="headings", height=height)
            for i, (c, w) in enumerate(zip(cols, widths)):
                t.heading(c, text=(titles[i] if titles else c.replace("_", " ").title()))
                t.column(c, width=w, anchor="w")
            sb = ttk.Scrollbar(fr, orient="vertical", command=t.yview)
            t.configure(yscrollcommand=sb.set)
            t.pack(side="left", fill="both", expand=True)
            sb.pack(side="right", fill="y")
            return fr, t

        def _bind_ctx(self, tree, use_iid=False, col=3):
            def popup(e):
                iid = tree.identify_row(e.y)
                if not iid:
                    return
                tree.selection_set(iid)
                self.ctx_ip = iid if use_iid else str(tree.item(iid, "values")[col])
                self.menu.tk_popup(e.x_root, e.y_root)
            tree.bind("<Button-3>", popup)
            tree.bind("<Button-2>", popup)

        def _tab_dashboard(self, nb):
            tab = ttk.Frame(nb)
            nb.add(tab, text="Dashboard")
            self.chart = tk.Canvas(tab, height=170, bg="white", highlightthickness=1,
                                   highlightbackground="#bbb")
            self.chart.pack(fill="x", padx=4, pady=4)
            paned = ttk.PanedWindow(tab, orient="horizontal")
            paned.pack(fill="both", expand=True)
            lf = ttk.LabelFrame(paned, text="Attackers (right-click for actions)")
            fr, self.t_att = self._tree(lf, ("ip", "failures", "last_seen", "users", "risk", "country", "services"),
                                         (140, 60, 75, 50, 45, 140, 100))
            fr.pack(fill="both", expand=True)
            self._bind_ctx(self.t_att, use_iid=True)
            self.t_att.tag_configure("hot", background="#f8c9c9")
            self.t_att.tag_configure("warm", background="#fde8c8")
            paned.add(lf, weight=3)
            rf = ttk.LabelFrame(paned, text="Targeted usernames")
            fr2, self.t_users = self._tree(rf, ("username", "failures"), (150, 70))
            fr2.pack(fill="both", expand=True)
            paned.add(rf, weight=1)
            sf = ttk.LabelFrame(paned, text="Services")
            fr3, self.t_svc = self._tree(sf, ("service", "events", "failures", "alerts"), (80, 55, 60, 55))
            fr3.pack(fill="both", expand=True)
            paned.add(sf, weight=1)

        def _tab_attempts(self, nb):
            tab = ttk.Frame(nb)
            nb.add(tab, text="Login attempts")
            ttk.Label(tab, text="Every failed / accepted SSH login, with the running attempt count per IP "
                                "(times in UTC).").pack(anchor="w", padx=6, pady=4)
            fr, self.t_attempts = self._tree(
                tab, ("time", "ip", "username", "result", "attempts", "country", "service"),
                (160, 150, 230, 130, 70, 170, 70),
                height=20, titles=("Time", "IP Address", "Username / request", "Result", "Attempts", "Country", "Service"))
            fr.pack(fill="both", expand=True)
            self.t_attempts.tag_configure("Failed", foreground="#c77700")
            self.t_attempts.tag_configure("Accepted", foreground="#1f8f3a")
            self.t_attempts.tag_configure("ALERT", foreground="#d11a2a")
            self.t_attempts.tag_configure("BLOCKED", foreground="#d11a2a", background="#fde0e0")
            self.t_attempts.tag_configure("Attack", foreground="#d11a2a")
            self.t_attempts.tag_configure("Probe", foreground="#c77700")
            self._bind_ctx(self.t_attempts, col=1)

        def _tab_alerts(self, nb):
            tab = ttk.Frame(nb)
            nb.add(tab, text="Alerts")
            top = ttk.Frame(tab)
            top.pack(fill="x", pady=4)
            ttk.Label(top, text="Min severity:").pack(side="left", padx=4)
            self.v_filter = tk.StringVar(value="all")
            cb = ttk.Combobox(top, textvariable=self.v_filter, state="readonly", width=10,
                              values=("all", "medium", "high", "critical"))
            cb.pack(side="left")
            cb.bind("<<ComboboxSelected>>", lambda e: self._render_alerts())
            ttk.Button(top, text="Export CSV", command=self.export_csv).pack(side="left", padx=10)
            fr, self.t_alerts = self._tree(
                tab, ("time", "severity", "type", "ip", "country", "service", "attempts", "risk", "who", "status", "note"),
                (150, 70, 140, 120, 140, 70, 70, 50, 130, 110, 240), height=18)
            fr.pack(fill="both", expand=True)
            self.t_alerts.tag_configure("critical", background="#f5a3a3")
            self.t_alerts.tag_configure("high", background="#fde8c8")
            self.t_alerts.tag_configure("medium", background="#fff6c8")
            self._bind_ctx(self.t_alerts, col=3)

        def _tab_blocks(self, nb):
            tab = ttk.Frame(nb)
            nb.add(tab, text="Blocklist")
            top = ttk.Frame(tab)
            top.pack(fill="x", pady=4)
            self.v_manual = tk.StringVar()
            ttk.Entry(top, textvariable=self.v_manual, width=28).pack(side="left", padx=4)
            ttk.Button(top, text="Block IP", command=lambda: self._block_ip(self.v_manual.get())).pack(side="left")
            ttk.Button(top, text="Unblock selected", command=self.unblock_selected).pack(side="left", padx=10)
            fr, self.t_blocks = self._tree(tab, ("ip", "blocked_at", "expires", "reason", "mode"),
                                           (170, 150, 150, 220, 90), height=18)
            fr.pack(fill="both", expand=True)

        def _tab_reports(self, nb):
            tab = ttk.Frame(nb)
            nb.add(tab, text="Reports")
            ttk.Label(tab, text="Detailed analytics: totals, timeline, top attackers and usernames, "
                                "alerts, blocks and recommendations.").pack(anchor="w", padx=8, pady=8)
            row = ttk.Frame(tab)
            row.pack(anchor="w", padx=8)
            ttk.Label(row, text="Period:").pack(side="left")
            self.v_hours = tk.StringVar(value="24 hours")
            ttk.Combobox(row, textvariable=self.v_hours, state="readonly", width=12,
                         values=("24 hours", "7 days", "30 days")).pack(side="left", padx=6)
            ttk.Button(row, text="Generate HTML report", command=self.make_report).pack(side="left", padx=6)
            ttk.Button(row, text="Open web dashboard", command=self.open_web).pack(side="left", padx=6)
            self.lbl_report = ttk.Label(tab, text="")
            self.lbl_report.pack(anchor="w", padx=8, pady=8)

        def _tab_settings(self, nb):
            tab = ttk.Frame(nb)
            nb.add(tab, text="Settings")
            grid = ttk.Frame(tab)
            grid.pack(fill="both", expand=True, padx=8, pady=8)
            wide = ("log_path", "geoip_db", "extra_sources", "es_url", "allowlist", "webhook_url", "mail_to", "mail_from")
            for n, (title, specs) in enumerate(SETTINGS_SPEC.items()):
                lf = ttk.LabelFrame(grid, text=title)
                lf.grid(row=n // 2, column=n % 2, sticky="nsew", padx=6, pady=4)
                for r, (attr, label, kind) in enumerate(specs):
                    val = getattr(self.cfg, attr)
                    if kind == "bool":
                        var = tk.BooleanVar(value=bool(val))
                        ttk.Checkbutton(lf, text=label, variable=var).grid(
                            row=r, column=0, columnspan=2, sticky="w", padx=6, pady=1)
                    else:
                        var = tk.StringVar(value=str(val))
                        ttk.Label(lf, text=label).grid(row=r, column=0, sticky="e", padx=6, pady=1)
                        if kind.startswith("choice:"):
                            w = ttk.Combobox(lf, textvariable=var, state="readonly", width=24,
                                             values=kind.split(":")[1].split(","))
                        else:
                            w = ttk.Entry(lf, textvariable=var, width=38 if attr in wide else 24,
                                          show="*" if kind == "secret" else "")
                        w.grid(row=r, column=1, sticky="w", padx=6, pady=1)
                    self.vars[attr] = (var, kind)
            grid.columnconfigure(0, weight=1)
            grid.columnconfigure(1, weight=1)
            btns = ttk.Frame(tab)
            btns.pack(pady=4)
            ttk.Button(btns, text="Save settings", command=self._save_settings).pack(side="left", padx=6)
            ttk.Button(btns, text="Send test notification", command=self.test_notify).pack(side="left", padx=6)

        def _tab_advanced(self, nb):
            tab = ttk.Frame(nb)
            nb.add(tab, text="Advanced")
            grid = ttk.Frame(tab)
            grid.pack(fill="both", expand=True, padx=8, pady=8)
            wide = ("canary_users", "feed_file", "feed_urls", "syslog_target", "thresholds_override", "net_ports",
                    "net_rate_override", "net_iface")
            for n, (title, specs) in enumerate(ADVANCED_SPEC.items()):
                lf = ttk.LabelFrame(grid, text=title)
                lf.grid(row=n // 2, column=n % 2, sticky="nsew", padx=6, pady=4)
                for r, (attr, label, kind) in enumerate(specs):
                    val = getattr(self.cfg, attr)
                    if kind == "bool":
                        var = tk.BooleanVar(value=bool(val))
                        ttk.Checkbutton(lf, text=label, variable=var).grid(
                            row=r, column=0, columnspan=2, sticky="w", padx=6, pady=1)
                    else:
                        var = tk.StringVar(value=str(val))
                        ttk.Label(lf, text=label).grid(row=r, column=0, sticky="e", padx=6, pady=1)
                        w = ttk.Entry(lf, textvariable=var, width=40 if attr in wide else 12,
                                      show="*" if kind == "secret" else "")
                        w.grid(row=r, column=1, sticky="w", padx=6, pady=1)
                    self.vars[attr] = (var, kind)
            grid.columnconfigure(0, weight=1)
            grid.columnconfigure(1, weight=1)
            ttk.Label(tab, text="Click 'Save settings' on the Settings tab to keep these. "
                                "Headless: kill -HUP reloads config.json.").pack(pady=6)

        def _tab_guide(self, nb):
            tab = ttk.Frame(nb)
            nb.add(tab, text="Guide")
            t = ScrolledText(tab, font=("monospace", 10), wrap="word")
            t.insert("1.0", GUIDE_TEXT)
            t.config(state="disabled")
            t.pack(fill="both", expand=True)

        def _tab_console(self, nb):
            tab = ttk.Frame(nb)
            nb.add(tab, text="Console")
            self.console = ScrolledText(tab, state="disabled", font=("monospace", 9))
            self.console.pack(fill="both", expand=True)

        # ---------------- config
        def _read_cfg(self):
            vals = {}
            for attr, (var, kind) in self.vars.items():
                v = var.get()
                if kind == "int":
                    vals[attr] = max(0, int(v))
                elif kind == "bool":
                    vals[attr] = bool(v)
                else:
                    vals[attr] = str(v).strip()
            for k in ("threshold", "window", "slow_threshold", "slow_window", "spray_users",
                      "distributed_ips", "distributed_window"):
                vals[k] = max(1, vals[k])
            return Config(**vals)

        def _save_settings(self):
            try:
                self.cfg = self._read_cfg()
                save_config(self.cfg)
                self.log("Settings saved (passwords and API keys are never written to disk)")
            except ValueError:
                messagebox.showerror("Invalid settings", "Numeric fields must contain whole numbers.")

        # ---------------- helpers
        def log(self, msg):
            self.console.config(state="normal")
            self.console.insert("end", f"{datetime.now():%H:%M:%S}  {msg}\n")
            self._console_lines += 1
            if self._console_lines > 3000:  # keep the console bounded
                self.console.delete("1.0", "501.0")
                self._console_lines -= 500
            self.console.see("end")
            self.console.config(state="disabled")

        def _copy_ip(self):
            if self.ctx_ip:
                self.clipboard_clear()
                self.clipboard_append(self.ctx_ip)

        def _blocker(self):
            if self.core:
                return self.core.blocker
            return Blocker(self.cfg, self.store, parse_allowlist(self.cfg.allowlist), self.log)

        def _block_ip(self, ip):
            ip = norm_ip((ip or "").strip())
            if not ip:
                messagebox.showinfo("Block IP", "Enter or select a valid IP address.")
                return
            if not messagebox.askyesno(
                    "Confirm block",
                    f"Add a {self.cfg.block_backend} DROP rule for {ip}?\n\n"
                    "Make sure this is not your own address or a trusted host."):
                return
            blocker = self._blocker()

            def work():
                ok, msg = blocker.block(ip, "manual", dry=False)
                self.q.put(("log", msg))
                self.q.put(("blocks", None))
            threading.Thread(target=work, daemon=True).start()

        def _allow_ip(self, ip):
            if not ip:
                return
            var, _ = self.vars["allowlist"]
            var.set((var.get().strip().rstrip(",") + ", " + ip).strip(", "))
            if self.core:
                self.core.add_allow(ip)
            self.log(f"{ip} added to allowlist (click 'Save settings' to keep it)")

        def unblock_selected(self):
            sel = self.t_blocks.selection()
            if not sel:
                return
            ip = sel[0]
            row = next((r for r in self.store.active_blocks() if r[0] == ip), None)
            if row:
                threading.Thread(
                    target=lambda: (self._blocker().unblock(ip, bool(row[4]), row[5]),
                                    self.q.put(("blocks", None))), daemon=True).start()

        def export_csv(self):
            path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV", "*.csv")])
            if not path:
                return
            with open(path, "w", newline="") as f:
                w = csv.writer(f)
                w.writerow(["time", "severity", "type", "ip", "country", "service", "attempts", "risk", "who", "status", "note"])
                w.writerows(self.alert_rows)
            self.log(f"Exported {len(self.alert_rows)} alerts to {path}")

        def make_report(self):
            hours = {"24 hours": 24, "7 days": 168, "30 days": 720}[self.v_hours.get()]
            self.store.flush()

            def work():
                try:
                    self.q.put(("report", write_report(self.store, hours)))
                except Exception as e:
                    self.q.put(("log", f"Report failed: {e}"))
            threading.Thread(target=work, daemon=True).start()

        def open_web(self):
            if self.core and self.core.web:
                webbrowser.open(f"http://{self.cfg.web_host}:{self.core.web.port}/")
            else:
                messagebox.showinfo("Web dashboard",
                                    "Enable 'Web dashboard' in Settings, then restart monitoring.")

        def test_notify(self):
            try:
                cfg = self._read_cfg()
            except ValueError:
                return
            sample = {"@timestamp": datetime.now(timezone.utc).isoformat(), "alert_type": "brute_force",
                      "severity": "high", "source_ip": "192.0.2.10", "attempts": 12,
                      "window_seconds": 60, "usernames": ["root"], "target_user": "", "risk_score": 80,
                      "note": "Test notification", "status": "BLOCKED"}

            def work():
                n = Notifier(cfg, lambda m: None, start_thread=False)
                if not n.active:
                    self.q.put(("log", "Test: enable email (host + To address) or set a webhook URL first"))
                    return
                errs = n.send(sample)
                self.q.put(("log", "Test notification sent" if not errs else
                            "Test notification failed: " + "; ".join(errs)))
            threading.Thread(target=work, daemon=True).start()

        def query_es(self):
            try:
                cfg = self._read_cfg()
            except ValueError:
                return

            def work():
                try:
                    ips, users = es_top(cfg)
                    self.q.put(("log", "ES top IPs: " + (", ".join(f"{k} ({v})" for k, v in ips) or "none")))
                    self.q.put(("log", "ES top users: " + (", ".join(f"{k} ({v})" for k, v in users) or "none")))
                except Exception as e:
                    self.q.put(("log", f"ES query failed: {e}"))
            threading.Thread(target=work, daemon=True).start()

        # ---------------- start / stop
        def start(self):
            if self.core:
                return
            try:
                self.cfg = self._read_cfg()
            except ValueError:
                messagebox.showerror("Invalid settings", "Numeric fields must contain whole numbers.")
                return
            save_config(self.cfg)
            self.core = Core(self.cfg, lambda k, d: self.q.put((k, d)), self.store)
            self.stopping = False
            self.attempt_seq = 0
            self.core.start()
            self.btn_start.config(state="disabled")
            self.btn_stop.config(state="normal")
            self.lbl_state.config(text="Monitoring")

        def stop(self):
            if not self.core or self.stopping:
                return
            self.stopping = True
            self.btn_stop.config(state="disabled")
            self.lbl_state.config(text="Stopping…")
            core = self.core

            def work():
                core.stop()
                self.q.put(("shutdown_done", None))
            threading.Thread(target=work, daemon=True).start()

        # ---------------- queue + periodic refresh
        def _poll(self):
            try:
                for _ in range(300):
                    kind, data = self.q.get_nowait()
                    if kind == "log":
                        self.log(data)
                    elif kind == "alert":
                        self._on_alert(data)
                    elif kind == "blocks":
                        self._render_blocks()
                    elif kind == "report":
                        self.lbl_report.config(text=f"Report saved: {data}")
                        self.log(f"Report saved: {data}")
                        webbrowser.open("file://" + data)
                    elif kind == "stopped":
                        if self.core and not self.stopping:
                            self.stop()
                    elif kind == "shutdown_done":
                        self.core = None
                        self.stopping = False
                        self.btn_start.config(state="normal")
                        self.btn_stop.config(state="disabled")
                        self.lbl_state.config(text="Idle")
                        self.log("Stopped")
            except queue.Empty:
                pass
            self.after(250, self._poll)

        def _on_alert(self, al):
            who = al["target_user"] or ",".join(al["usernames"][:4])
            row = (al["@timestamp"], al["severity"], al["alert_type"], al["source_ip"], al.get("country", ""), al.get("service", "ssh"),
                   al["attempts"], al["risk_score"], who, al.get("status", ""), al["note"])
            self.alert_rows.append(row)
            self.alert_rows = self.alert_rows[-2000:]
            self._dirty = True  # re-rendered once per second, not once per alert
            self.log(f"ALERT [{al['severity']}] {al['alert_type']} from {al['source_ip']} "
                     f"({al['attempts']} in {al['window_seconds']}s, risk {al['risk_score']}) "
                     f"{al.get('status', '')} {al['note']}")
            if not str(al.get("status", "")).endswith("(historical)"):
                self.bell()
                self._popup(al)

        def _popup(self, al):
            if not self.cfg.gui_popup or SEV_RANK[al["severity"]] < SEV_RANK["high"]:
                return
            text = format_alert(al)
            if self.popup is not None and self.popup.winfo_exists():
                self.popup_lbl.config(text=text)
                self.popup.lift()
                return
            w = tk.Toplevel(self)
            w.title("SSH Guard alert")
            w.configure(bg="#0b0b0f")
            w.attributes("-topmost", True)
            self.popup = w
            self.popup_lbl = tk.Label(w, text=text, justify="left", anchor="w", bg="#0b0b0f",
                                      fg="#ff4d4d", font=("monospace", 11), padx=18, pady=14)
            self.popup_lbl.pack()
            ttk.Button(w, text="Dismiss", command=w.destroy).pack(pady=(0, 12))

        def _add_attempt(self, row):
            tag = str(row[3]).split()[0]
            self.t_attempts.insert("", 0, values=row, tags=(tag,))
            kids = self.t_attempts.get_children()
            for iid in kids[1000:]:
                self.t_attempts.delete(iid)

        def _render_alerts(self):
            min_rank = -1 if self.v_filter.get() == "all" else SEV_RANK[self.v_filter.get()]
            self.t_alerts.delete(*self.t_alerts.get_children())
            for r in reversed(self.alert_rows):
                if SEV_RANK.get(r[1], 0) >= min_rank:
                    self.t_alerts.insert("", "end", tags=(r[1],),
                                         values=(str(r[0])[:19].replace("T", " "),) + tuple(r[1:]))

        def _render_blocks(self):
            self.t_blocks.delete(*self.t_blocks.get_children())

            def fmt(t):
                return datetime.fromtimestamp(t).strftime("%Y-%m-%d %H:%M:%S") if t else "never"
            for ip, at, exp, reason, dry, backend in self.store.active_blocks():
                self.t_blocks.insert("", "end", iid=ip, values=(
                    ip, fmt(at), fmt(exp), reason, "dry-run" if dry else backend))

        def _tick(self):
            if self._dirty:
                self._dirty = False
                self._render_alerts()
                self._render_blocks()
            if self.core:
                st, rows, users, series = self.core.snapshot()
                for k, lbl in self.card.items():
                    lbl.config(text=str(st.get(k, 0)))
                self._update_tree(self.t_att, rows, key=0, tag=lambda r: (
                    "hot" if r[4] >= 70 else ("warm" if r[4] >= 40 else "")))
                self._update_tree(self.t_users, users, key=0)
                self._update_tree(self.t_svc, [(k, v['events'], v['failed'], v['alerts'])
                                               for k, v in sorted(st.get('services', {}).items())], key=0)
                self._draw_chart(series)
                self.attempt_seq, new = self.core.new_attempts(self.attempt_seq)
                for row in new[-200:]:
                    self._add_attempt(row)
                self._tick_n += 1
                if self._tick_n % 5 == 0:
                    self._render_blocks()
            self.after(1000, self._tick)

        @staticmethod
        def _update_tree(tree, rows, key, tag=None):
            wanted = {str(r[key]): r for r in rows}
            for iid in tree.get_children():
                if iid not in wanted:
                    tree.delete(iid)
            for pos, (iid, r) in enumerate(wanted.items()):
                tags = (tag(r),) if tag and tag(r) else ()
                if tree.exists(iid):
                    tree.item(iid, values=r, tags=tags)
                else:
                    tree.insert("", "end", iid=iid, values=r, tags=tags)
                tree.move(iid, "", pos)

        def _draw_chart(self, series):
            c = self.chart
            c.delete("all")
            w, h = max(c.winfo_width(), 200), max(c.winfo_height(), 100)
            pad = 26
            peak = max(max(series), 1)
            bw = (w - 2 * pad) / len(series)
            for i, v in enumerate(series):
                if v:
                    y1 = h - pad
                    y0 = y1 - (h - 2 * pad - 10) * v / peak
                    c.create_rectangle(pad + i * bw + 1, y0, pad + (i + 1) * bw - 1, y1,
                                       fill="#d9534f", outline="")
            c.create_line(pad, h - pad, w - pad, h - pad, fill="#888")
            c.create_text(pad, 10, anchor="w", fill="#333",
                          text=f"Failed logins per minute, last 60 min (peak {peak})")
            c.create_text(pad, h - 10, anchor="w", text="-60m", fill="#666")
            c.create_text(w - pad, h - 10, anchor="e", text="now", fill="#666")

        def _close(self):
            if self.core:
                self.core.stop()
            self.store.close()
            self.destroy()


# ==========================================================================
# Headless mode, replay, self-test
# ==========================================================================
def run_headless(cfg, replay=None, kind="syslog", pcap=None):
    def emit(kind, data):
        if kind == "alert":
            print("\n" + format_alert(data) + "\n", file=sys.stderr, flush=True)
            print(json.dumps({k: v for k, v in data.items() if not k.startswith("_")}), flush=True)
        elif kind == "log":
            print("#", data, file=sys.stderr, flush=True)

    store = Store()
    core = Core(cfg, emit, store)
    if pcap:
        core.start(engine=False)
        sensor = NetSensor(core, scope_all=True, replay=True)
        count = sensor.replay_pcap(pcap)
        st = core.snapshot()[0]
        core.stop()
        print(f"# pcap replay done: {count} packets, {sensor.stats['events']} protocol events, {st}", file=sys.stderr)
        return
    if replay:
        core.start(engine=False)
        with open(replay, errors="replace") as f:
            for line in f:
                core.handle_line(line, kind)
        st = core.snapshot()[0]
        core.stop()
        print(f"# replay done: {st}", file=sys.stderr)
        return
    stop, hup = threading.Event(), threading.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: stop.set())
    if hasattr(signal, "SIGHUP"):
        signal.signal(signal.SIGHUP, lambda *_: hup.set())
    core.start()
    while not stop.wait(1):
        if hup.is_set():
            hup.clear()
            core.reload(load_config())
        if core.engine and not core.engine.is_alive() and not (core.sensor and core.sensor.is_alive()):
            break
    core.stop()


def _build_test_mmdb(first_octet, record):
    """Tiny hand-made MaxMind DB covering one IPv4 /8, used to verify the reader."""
    def enc(v):
        if isinstance(v, str):
            b = v.encode()
            assert len(b) < 29
            return bytes([(2 << 5) | len(b)]) + b
        if isinstance(v, int):
            return bytes([(6 << 5) | 4]) + v.to_bytes(4, "big")
        out = bytes([(7 << 5) | len(v)])
        for k, x in v.items():
            out += enc(k) + enc(x)
        return out

    node_count = 8
    tree = b""
    for i in range(8):
        bit = (first_octet >> (7 - i)) & 1
        nxt = i + 1 if i < 7 else node_count + 16
        left, right = (node_count, nxt) if bit else (nxt, node_count)
        tree += left.to_bytes(3, "big") + right.to_bytes(3, "big")
    meta = enc({"node_count": node_count, "record_size": 24, "ip_version": 4,
                "binary_format_major_version": 2})
    return tree + b"\x00" * 16 + enc(record) + GeoIP.MARKER + meta


def selftest():
    cfg = Config(threshold=5, window=60, slow_threshold=10, slow_window=3600,
                 spray_users=4, distributed_ips=4, distributed_window=300)
    base = datetime.now(timezone.utc).replace(microsecond=0) - timedelta(minutes=10)

    def line(sec, kind, user, ip, inv=False):
        ts = (base + timedelta(seconds=sec)).strftime("%Y-%m-%dT%H:%M:%S+00:00")
        word = "Failed" if kind == "f" else "Accepted"
        return (f"{ts} host sshd[99]: {word} password for {'invalid user ' if inv else ''}"
                f"{user} from {ip} port 4000 ssh2")

    def run(lines, allow="10.0.0.0/8"):
        det = Detector(cfg, parse_allowlist(allow))
        types = []
        for ln in lines:
            ev = parse_line(ln)
            assert ev, f"unparsed: {ln}"
            types += [a["alert_type"] for a in det.process(ev)]
        return types

    ok = 0

    def check(name, got, want):
        nonlocal ok
        status = "PASS" if got == want else "FAIL"
        print(f"[{status}] {name}: {got}")
        assert got == want, f"{name}: expected {want}"
        ok += 1

    check("brute force", run([line(i, "f", "root", "203.0.113.5") for i in range(5)]), ["brute_force"])
    check("below threshold", run([line(i, "f", "root", "203.0.113.5") for i in range(4)]), [])
    check("password spray", run([line(i, "f", f"user{i}", "203.0.113.6", True) for i in range(6)]),
          ["password_spray"])
    check("compromise", run([line(i, "f", "admin", "203.0.113.7") for i in range(3)]
                            + [line(10, "a", "admin", "203.0.113.7")]), ["possible_compromise"])
    check("allowlisted", run([line(i, "f", "root", "10.1.1.1") for i in range(20)]), [])
    check("distributed", run([line(i * 10, "f", "admin", f"198.51.100.{i}") for i in range(4)]),
          ["distributed_attack"])
    check("slow brute force", run([line(i * 120, "f", "ubuntu", "203.0.113.8") for i in range(10)]),
          ["slow_brute_force"])

    e1 = parse_line("Nov  3 10:00:00 h sshd[1]: Failed password for root from ::ffff:1.2.3.4 port 22 ssh2")
    check("syslog + mapped IPv6", (e1["source_ip"], e1["username"]), ("1.2.3.4", "root"))
    e2 = parse_line("2026-11-03T10:00:00+0530 h sshd-session[1]: Failed publickey for bob from 9.9.9.9 port 1 ssh2")
    check("journald tz + sshd-session", (e2["source_ip"], e2["@timestamp"][:19]), ("9.9.9.9", "2026-11-03T04:30:00"))
    e3 = parse_line("Nov  3 10:00:00 h sshd[1]: Invalid user admin from 8.8.8.8 port 5")
    check("invalid_user event", e3["event_type"], "invalid_user")
    check("non-ssh line ignored", parse_line("Nov  3 10:00:00 h cron[1]: hello"), None)

    # --- parser: real-world OpenSSH variants and log-injection resistance
    pfx = "Nov  3 10:00:00 kali sshd[1]: "
    variants = {
        "keyboard-interactive/pam": ("Failed keyboard-interactive/pam for root from 203.0.113.5 port 22 ssh2", "failed", "root"),
        "kbd-interactive invalid user": ("Failed keyboard-interactive/pam for invalid user bob from 203.0.113.5 port 22 ssh2", "failed", "bob"),
        "username with space": ("Failed password for invalid user john smith from 203.0.113.5 port 22 ssh2", "failed", "john smith"),
        "accepted kbd/pam": ("Accepted keyboard-interactive/pam for kali from 203.0.113.5 port 22 ssh2", "accepted", "kali"),
        "max auth error": ("error: maximum authentication attempts exceeded for root from 203.0.113.5 port 5 ssh2 [preauth]", "max_auth", "root"),
        "bare connection closed": ("Connection closed by 203.0.113.5 port 5 [preauth]", "preauth_close", "<empty>"),
        "no identification string": ("Did not receive identification string from 203.0.113.5 port 5", "preauth_close", "<empty>"),
        "cannot negotiate": ("Unable to negotiate with 203.0.113.5 port 5: no matching key exchange method found.", "preauth_close", "<empty>"),
    }
    for name, (msg, etype, user) in variants.items():
        e = parse_line(pfx + msg)
        check(f"parse {name}", (e["event_type"], e["username"], e["source_ip"]) if e else None,
              (etype, user, "203.0.113.5"))
    inj = parse_line(pfx + "Failed password for invalid user a from 8.8.8.8 port 1 from 203.0.113.5 port 55 ssh2")
    check("log injection cannot spoof the source IP", (inj["source_ip"], inj["username"]),
          ("203.0.113.5", "a from 8.8.8.8 port 1"))

    # --- resilience: fuzzing, bad lines, replaying old logs
    import random
    rnd = random.Random(1)
    fcore = Core(Config(auto_block=True, block_dry_run=True, canary_users="x"),
                 lambda k, d: None, Store(":memory:"))
    errs = 0
    for _ in range(3000):
        junk = "".join(rnd.choice("abc :.%[]<>'\"\\\x00\u00e90123456789") for _ in range(rnd.randint(0, 120)))
        try:
            fcore._handle_line(rnd.choice(["", "Nov  3 10:00:00 h sshd[1]: ", "sshd[1]: Failed password for "]) + junk)
        except Exception:
            errs += 1
    check("fuzz: no exceptions", errs, 0)
    fcore._handle_line = lambda ln: 1 / 0
    fcore.handle_line("anything")
    check("a bad line cannot stop monitoring", True, True)

    score = Core(Config(threshold=5, window=60, auto_block=True, block_dry_run=True),
                 lambda k, d: None, Store(":memory:"))
    for i in range(5):
        old = (base - timedelta(hours=3) + timedelta(seconds=i)).strftime("%Y-%m-%dT%H:%M:%S+00:00")
        score.handle_line(f"{old} host sshd[99]: Failed password for root from 203.0.113.80 port 4000 ssh2")
    check("historical alert is never auto-blocked", (score.store.recent_attempts(1)[0][3],
                                                      score.store.active_blocks()), ("ALERT", []))

    # --- advanced detections and rules
    def stamp(sec):
        return (base + timedelta(seconds=sec)).strftime("%Y-%m-%dT%H:%M:%S+00:00")

    def inv(sec, user, ip):
        return f"{stamp(sec)} host sshd[99]: Invalid user {user} from {ip} port 4000"

    def pre(sec, ip):
        return f"{stamp(sec)} host sshd[99]: Connection closed by invalid user x {ip} port 4000 [preauth]"

    check("user enumeration", run([inv(i, f"u{i}", "203.0.113.30") for i in range(8)]), ["user_enumeration"])
    check("ssh scanner", run([pre(i, "203.0.113.31") for i in range(15)]), ["ssh_scanner"])

    seen = []
    rcore = Core(Config(threshold=100, canary_users="oracle", new_source_alerts=True),
                 lambda k, d: seen.append(d["alert_type"]) if k == "alert" else None, Store(":memory:"))
    rcore.feed.set_entries(*ThreatFeed.parse("# comment\n198.51.100.0/24 ; bad net\n192.0.2.7\n"))
    for ln in (line(0, "f", "oracle", "203.0.113.60"), line(1, "a", "root", "203.0.113.61"),
               line(2, "a", "alice", "203.0.113.62"), line(3, "a", "alice", "203.0.113.63"),
               line(4, "f", "bob", "198.51.100.9")):
        rcore.handle_line(ln)
    check("rule alerts", seen, ["honeypot_user", "root_login", "new_login_source", "known_bad_ip"])
    check("feed lookup", (rcore.feed.contains("198.51.100.200"), rcore.feed.contains("192.0.2.7"),
                          rcore.feed.contains("192.0.2.8")), (True, True, False))

    est = Store(":memory:")
    blk = Blocker(Config(block_ttl=100), est, [], lambda m: None)
    spans = []
    for _ in range(3):
        blk.block("203.0.113.70", "test", dry=True)
        _ip, at, exp = est.active_blocks()[0][:3]
        spans.append(round(exp - at))
        blk.unblock("203.0.113.70", dry=True)
    check("escalating bans", spans, [100, 200, 400])

    tcore = Core(Config(threshold=5, window=60, auto_block=True, block_dry_run=True),
                 lambda k, d: None, Store(":memory:"))
    tcore.store.add_known_login("alice", "203.0.113.71", (base - timedelta(days=3)).timestamp())
    for ip in ("203.0.113.71", "203.0.113.72"):
        for i in range(5):
            tcore.handle_line(line(i, "f", "root", ip))
    res = {r[1]: r[3] for r in tcore.store.recent_attempts(20) if r[4] == 5}
    check("lockout protection", res, {"203.0.113.71": "ALERT", "203.0.113.72": "BLOCKED (dry-run)"})

    # --- many services: telnet, FTP, mail, databases, RDP, SIP, webmin, generic PAM
    sv = {
        "telnet failed": ("Nov  3 10:00:00 h login[1]: FAILED LOGIN 1 FROM 203.0.113.5 FOR root, Authentication failure", ("telnet", "failed", "root")),
        "telnet root login": ("Nov  3 10:00:00 h login[1]: ROOT LOGIN ON pts/1 FROM 203.0.113.5", ("telnet", "accepted", "root")),
        "telnet login": ("Nov  3 10:00:00 h login[1]: LOGIN ON pts/1 BY bob FROM 203.0.113.5", ("telnet", "accepted", "bob")),
        "telnetd connect": ("Nov  3 10:00:00 h in.telnetd[1]: connect from 203.0.113.5 (203.0.113.5)", ("telnet", "preauth_close", "<empty>")),
        "vsftpd fail": ('Mon Nov  3 10:15:01 2026 [pid 123] [bob] FAIL LOGIN: Client "203.0.113.5"', ("ftp", "failed", "bob")),
        "vsftpd ok": ('Mon Nov  3 10:15:01 2026 [pid 123] [bob] OK LOGIN: Client "203.0.113.5"', ("ftp", "accepted", "bob")),
        "proftpd fail": ("Nov  3 10:00:00 h proftpd[1]: srv (host[203.0.113.5]): USER bob (Login failed): Incorrect password", ("ftp", "failed", "bob")),
        "pure-ftpd fail": ("Nov  3 10:00:00 h pure-ftpd: (?@203.0.113.5) [WARNING] Authentication failed for user [bob]", ("ftp", "failed", "bob")),
        "postfix sasl": ("Nov  3 10:00:00 h postfix/smtpd[1]: warning: unknown[203.0.113.5]: SASL LOGIN authentication failed: UGFzc3dvcmQ6", ("smtp", "failed", "<unknown>")),
        "postfix relay": ("Nov  3 10:00:00 h postfix/smtpd[1]: NOQUEUE: reject: RCPT from unknown[203.0.113.5]: 454 4.7.1 <x@y.z>: Relay access denied; from=<a@b.c>", ("smtp", "preauth_close", "<empty>")),
        "dovecot imap": ("Nov  3 10:00:00 h dovecot: imap-login: Disconnected (auth failed, 1 attempts in 2 secs): user=<bob>, method=PLAIN, rip=203.0.113.5, lip=10.0.0.1, TLS", ("imap", "failed", "bob")),
        "dovecot submission ok": ("Nov  3 10:00:00 h dovecot: submission-login: Login: user=<bob>, method=PLAIN, rip=203.0.113.5, lip=10.0.0.1", ("smtp", "accepted", "bob")),
        "mysql": ("2026-11-03T10:00:00.123456Z 12 [Warning] [MY-010926] [Server] Access denied for user 'root'@'203.0.113.5' (using password: YES)", ("mysql", "failed", "root")),
        "postgres": ('2026-11-03 10:00:00.123 UTC [123] 203.0.113.5(5432) postgres@db FATAL:  password authentication failed for user "postgres"', ("postgres", "failed", "postgres")),
        "postgres pg_hba": ('2026-11-03 10:00:00.123 UTC [123] FATAL:  no pg_hba.conf entry for host "203.0.113.5", user "bob", database "x"', ("postgres", "failed", "bob")),
        "xrdp": ("Nov  3 10:00:00 h xrdp-sesman[1]: [INFO ] AUTHFAIL: user=bob ip=::ffff:203.0.113.5 time=1", ("rdp", "failed", "bob")),
        "asterisk": ("[Nov  3 10:00:00] NOTICE[1] chan_sip.c: Registration from '\"100\" <sip:100@10.0.0.1>' failed for '203.0.113.5:5060' - Wrong password", ("sip", "failed", "100")),
        "webmin": ("Nov  3 10:00:00 h webmin[1]: Invalid login as root from 203.0.113.5", ("webmin", "failed", "root")),
        "pam login -> telnet": ("Nov  3 10:00:00 h login[1]: pam_unix(login:auth): authentication failure; logname= uid=0 euid=0 tty=/dev/pts/0 ruser= rhost=203.0.113.5  user=root", ("telnet", "failed", "root")),
        "pam cockpit (generic)": ("Nov  3 10:00:00 h cockpit-ws[1]: pam_unix(cockpit:auth): authentication failure; logname= uid=0 euid=0 tty= ruser= rhost=203.0.113.5  user=bob", ("cockpit", "failed", "bob")),
    }
    for name, (ln, want) in sv.items():
        e = parse_line(ln)
        check(f"service: {name}", (e["service"], e["event_type"], e["username"]) if e else None, want)
    check("pam sshd lines are skipped (no double counting)", parse_line(
        "Nov  3 10:00:00 h sshd[1]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=203.0.113.5  user=root"), None)
    check("pam with empty rhost is local, ignored", parse_line(
        "Nov  3 10:00:00 h sudo: pam_unix(sudo:auth): authentication failure; logname=bob uid=1000 euid=0 tty=/dev/pts/1 ruser=bob rhost=  user=bob"), None)

    # --- web servers (nginx/Apache access + error logs), HTTP and HTTPS
    def wl(req, status=200, user="-", ua="Mozilla/5.0", vhost=""):
        return f'{vhost}203.0.113.5 - {user} [{base:%d/%b/%Y:%H:%M:%S} +0000] "{req}" {status} 512 "-" "{ua}"'

    web = {
        "basic-auth 401": (wl("GET /admin HTTP/1.1", 401, "admin"), ("http", "failed", "admin")),
        "login POST": (wl("POST /wp-login.php HTTP/1.1", 200), ("http", "failed", "<form login>")),
        "sql injection": (wl("GET /index.php?id=1%20UNION%20SELECT%20username,password%20FROM%20users-- HTTP/1.1"), ("http", "web_attack", "<n/a>")),
        "sql injection (raw spaces)": (wl("GET /?id=1' OR 1=1-- HTTP/1.1", 400), ("http", "web_attack", "<n/a>")),
        "path traversal": (wl("GET /../../etc/passwd HTTP/1.1", 400), ("http", "web_attack", "<n/a>")),
        "xss": (wl("GET /search?q=%3Cscript%3Ealert(1)%3C/script%3E HTTP/1.1"), ("http", "web_attack", "<n/a>")),
        "command injection": (wl("GET /ping?host=1.1.1.1;cat%20/etc/hosts HTTP/1.1"), ("http", "web_attack", "<n/a>")),
        "log4shell in user-agent": (wl("GET / HTTP/1.1", 200, ua="${jndi:ldap://x/a}"), ("http", "web_attack", "<n/a>")),
        "sensitive path": (wl("GET /.env HTTP/1.1", 404), ("http", "probe", "<n/a>")),
        "scanner user-agent": (wl("GET / HTTP/1.1", 200, ua="sqlmap/1.5"), ("http", "probe", "<n/a>")),
        "404 (quiet)": (wl("GET /nope HTTP/1.1", 404), ("http", "web_404", "<n/a>")),
        "https vhost": (wl("GET /.env HTTP/1.1", 404, vhost="example.com:443 "), ("https", "probe", "<n/a>")),
        "TLS bytes sent to HTTP port": (wl("\\x16\\x03\\x01", 400), ("http", "web_404", "<n/a>")),
        "nginx error: basic auth": ('2026/11/03 10:00:00 [error] 12#12: *3 user "admin": password mismatch, client: 203.0.113.5, server: x, request: "GET / HTTP/1.1", host: "x"', ("http", "failed", "admin")),
        "apache error: basic auth": ('[Mon Nov 03 10:00:00.123456 2026] [auth_basic:error] [pid 1] [client 203.0.113.5:5555] AH01617: user admin: authentication failure for "/": Password Mismatch', ("http", "failed", "admin")),
        "nginx error: TLS handshake": ("2026/11/03 10:00:00 [crit] 12#12: *3 SSL_do_handshake() failed (SSL: error:1408F10B:SSL routines:ssl3_get_record:wrong version number) while SSL handshaking, client: 203.0.113.5, server: 0.0.0.0:443", ("https", "preauth_close", "<n/a>")),
    }
    for name, (ln, want) in web.items():
        e = parse_web_line(ln)
        check(f"web: {name}", (e["service"], e["event_type"], e["username"]) if e else None, want)
    check("web: normal request ignored", parse_web_line(wl("GET /index.html HTTP/1.1")), None)
    check("web: timestamps with offsets are exact (locale-independent)",
          (_parse_web_ts("03/Nov/2026:10:15:01 +0530").isoformat(), _parse_web_ts("31/Dec/2026:23:59:59 -0800").isoformat()),
          ("2026-11-03T04:45:01+00:00", "2027-01-01T07:59:59+00:00"))
    check("web: bad timestamp falls back instead of crashing",
          parse_web_line('203.0.113.5 - - [garbage] "GET /.env HTTP/1.1" 404 1 "-" "x"')["event_type"], "probe")
    check("web: legit 200 on a login page is not a failure", parse_web_line(wl("GET /wp-login.php HTTP/1.1")), None)

    def run_core(lines, **cfg_kw):
        got = []
        c = Core(Config(**cfg_kw), lambda k, d: got.append((d["alert_type"], d["service"])) if k == "alert" else None,
                 Store(":memory:"))
        for ln, kind in lines:
            c.handle_line(ln, kind)
        return got

    def wline(i, req, status=200, user="-", ua="Mozilla/5.0"):
        return (f'203.0.113.6 - {user} [{base + timedelta(seconds=i):%d/%b/%Y:%H:%M:%S} +0000] '
                f'"{req}" {status} 1 "-" "{ua}"')

    check("http brute force (basic auth, threshold 10)",
          run_core([(wline(i, "GET /admin HTTP/1.1", 401, "admin"), "web") for i in range(10)]), [("brute_force", "http")])
    check("http below threshold", run_core([(wline(i, "GET /admin HTTP/1.1", 401, "admin"), "web") for i in range(9)]), [])
    check("per-service threshold override", run_core(
        [(wline(i, "GET /admin HTTP/1.1", 401, "admin"), "web") for i in range(3)], thresholds_override="http=3"),
        [("brute_force", "http")])
    check("web attack alert", run_core([(wline(0, "GET /?id=1' OR 1=1-- HTTP/1.1"), "web")]), [("web_attack", "http")])
    check("web probe alert", run_core([(wline(i, "GET /.env HTTP/1.1", 404), "web") for i in range(5)]), [("web_probe", "http")])
    check("web scanner alert (error flood)", run_core(
        [(wline(i, f"GET /x{i} HTTP/1.1", 404), "web") for i in range(30)]), [("web_scanner", "http")])
    check("bad user-agent alert", run_core([(wline(0, "GET / HTTP/1.1", 200, ua="Nikto/2.1.6"), "web")]),
          [("bad_user_agent", "http")])
    telnet = [(f"{stamp(i)} h login[1]: FAILED LOGIN {i + 1} FROM 203.0.113.7 FOR root, Authentication failure", "syslog")
              for i in range(5)]
    check("telnet brute force", run_core(telnet), [("brute_force", "telnet")])
    mixed = ([(line(i, "f", "root", "203.0.113.8"), "syslog") for i in range(3)]
             + [(f'{stamp(5 + i)} h vsftpd: [pid 1] [bob] FAIL LOGIN: Client "203.0.113.8"', "syslog") for i in range(3)])
    check("services are counted separately", run_core(mixed), [])
    box2 = format_alert({"@timestamp": stamp(0), "alert_type": "web_attack", "severity": "high",
                         "source_ip": "203.0.113.9", "attempts": 1, "risk_score": 50, "usernames": ["GET /x"],
                         "target_user": "", "note": "sql_injection", "service": "http"})
    check("alert box names the service", ("HTTP Attack Detected!" in box2, "Service    : http" in box2), (True, True))

    # --- everything wired together: one Core, three log sources, each in its own thread
    import tempfile
    with tempfile.TemporaryDirectory() as td2:
        auth, access, ftplog = (os.path.join(td2, n) for n in ("auth.log", "access.log", "vsftpd.log"))
        nowz = datetime.now(timezone.utc)
        with open(auth, "w") as f:
            f.writelines(f"{nowz.isoformat()} h sshd[1]: Failed password for root from 203.0.113.20 port 22 ssh2\n"
                         for _ in range(5))
        with open(access, "w") as f:
            f.write(f'203.0.113.21 - - [{nowz:%d/%b/%Y:%H:%M:%S} +0000] "GET /?id=1 UNION SELECT 1,2 HTTP/1.1" 200 5 "-" "x"\n')
        with open(ftplog, "w") as f:
            f.writelines(f'{nowz.isoformat()} h vsftpd: [pid 1] [bob] FAIL LOGIN: Client "203.0.113.22"\n'
                         for _ in range(5))
        got2 = []
        ecore = Core(Config(log_path=auth, extra_sources=f"web={access}; syslog={ftplog}", auto_sources=False,
                            from_start=True),
                     lambda k, d: got2.append((d["alert_type"], d["service"])) if k == "alert" else None,
                     Store(":memory:"))
        ecore.start()
        deadline = time.time() + 8
        while len(got2) < 3 and time.time() < deadline:
            time.sleep(0.1)
        ecore.stop()
        check("multi-source engine (ssh + http + ftp)", sorted(got2),
              [("brute_force", "ftp"), ("brute_force", "ssh"), ("web_attack", "http")])
        check("report breaks activity down by service", sorted(ecore.store.report_data(24 * 3650)["by_service"]),
              ["ftp", "http", "ssh"])
        check("source plan parsing", parse_sources("web=/a/access.log; https=/b/x.log;bogus; syslog=/c/d.log;web=/e/ssl_access.log"),
              [("web", "/a/access.log"), ("web-https", "/b/x.log"), ("syslog", "/c/d.log"), ("web-https", "/e/ssl_access.log")])

    usock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    usock.bind(("127.0.0.1", 0))
    usock.settimeout(3)
    fw = SyslogForwarder(f"udp://127.0.0.1:{usock.getsockname()[1]}", print)
    fw.send({"@timestamp": stamp(0), "alert_type": "brute_force", "severity": "high",
             "source_ip": "203.0.113.9", "attempts": 5, "risk_score": 60, "usernames": ["root"],
             "target_user": "", "note": "a=b|c", "status": "BLOCKED", "country": "DE", "_ts": time.time()})
    data, _ = usock.recvfrom(65535)
    fw.close()
    usock.close()
    check("syslog CEF", (data.startswith(b"<35>"), b"CEF:0|SSHGuard|SSHGuard|1.0|brute_force|" in data,
                         b"src=203.0.113.9" in data, b"msg=a\\=b|c" in data), (True, True, True, True))

    # --- attempts log, alert box, report, web dashboard
    store = Store(":memory:")
    core = Core(Config(threshold=5, window=60), lambda k, d: None, store)
    evil = "<script>alert(1)</script>"
    for i in range(6):
        core.handle_line(line(i * 5, "f", evil if i else "root", "203.0.113.50"))
    rows = store.recent_attempts(10)[::-1]
    check("attempt counter + ALERT result", [(r[3], r[4]) for r in rows],
          [("Failed", 1), ("Failed", 2), ("Failed", 3), ("Failed", 4), ("ALERT", 5), ("Failed", 6)])

    al = store.recent_alerts(1)[0]
    box = format_alert({"@timestamp": al[0], "alert_type": al[2], "severity": al[1], "source_ip": al[3],
                        "attempts": al[6], "risk_score": al[7], "usernames": [evil], "target_user": "",
                        "note": ""}, "BLOCKED")
    check("alert box format", ("SSH Brute Force Attempt Detected!" in box, "IP Address : 203.0.113.50" in box,
                               "Status     : BLOCKED" in box, "<" not in box), (True, True, True, True))

    rep_html = render_report_html(store.report_data(24 * 3650))
    check("report escapes attacker input", ("&lt;script&gt;" in rep_html, "<script" in rep_html.lower()),
          (True, False))

    web = WebServer(core, "127.0.0.1", 0)
    web.start()
    base_url = f"http://127.0.0.1:{web.port}"
    with urllib.request.urlopen(base_url + "/api/state", timeout=5) as r:
        state = json.loads(r.read())
    check("web api", (state["stats"]["failed"], len(state["attempts"])), (6, 6))
    with urllib.request.urlopen(base_url + "/report?hours=24", timeout=5) as r:
        check("web report", r.status, 200)
    with urllib.request.urlopen(base_url + "/metrics", timeout=5) as r:
        mtxt = r.read().decode()
    check("web metrics", ("ssh_guard_failed_logins_total 6" in mtxt,
                          'ssh_guard_alerts_by_type_total{type="brute_force"} 1' in mtxt), (True, True))
    try:
        urllib.request.urlopen(urllib.request.Request(base_url + "/", headers={"Host": "evil.example"}), timeout=5)
        blocked = False
    except urllib.error.HTTPError as e:
        blocked = e.code == 403
    check("web DNS-rebinding guard", blocked, True)
    web.stop()
    # --- GeoIP (hand-built MaxMind DB), enrichment, Kibana export
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        dbp = os.path.join(td, "test.mmdb")
        with open(dbp, "wb") as f:
            f.write(_build_test_mmdb(5, {"country": {"iso_code": "DE", "names": {"en": "Germany"}},
                                         "city": {"names": {"en": "Berlin"}},
                                         "autonomous_system_number": 64500}))
        geo = GeoIP(dbp)
        gf = geo_fields(geo.lookup("5.6.7.8"))
        check("geoip hit", (gf["_geo"], gf["city"], gf["asn"]), ("Germany (DE)", "Berlin", 64500))
        check("geoip miss + ipv6", (geo.lookup("6.0.0.1"), geo.lookup("2001:db8::1")), ({}, {}))
        core.geo = geo
        core.handle_line(line(100, "f", "root", "5.6.7.8"))
        core.handle_line(line(101, "f", "root", "10.9.9.9"))
        check("country in attempts log", [r[5] for r in store.recent_attempts(2)[::-1]],
              ["Germany (DE)", LOCAL_LABEL])
        check("country in report", "Germany (DE)" in render_report_html(store.report_data(24 * 3650)), True)
        kb = os.path.join(td, "kb.ndjson")
        kibana_export(kb, "ssh-guard")
        with open(kb) as f:
            objs = [json.loads(ln) for ln in f]
        ids = {o["id"] for o in objs}
        refs_ok = all(r["id"] in ids for o in objs for r in o["references"])
        vis_ok = all(json.loads(o["attributes"]["visState"])["aggs"]
                     for o in objs if o["type"] == "visualization")
        check("kibana export", (len(objs) == 14, refs_ok, vis_ok), (True, True, True))
    # ---------------- live network sensor, driven with synthetic packets
    T0 = time.time() - 300

    def pkt(src, dst, sport, dport, flags=0x18, seq=1000, payload=b"", udp=False, vlan=False):
        v6 = ":" in src
        if udp:
            l4, proto = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload, 17
        else:
            l4, proto = struct.pack("!HHIIBBHHH", sport, dport, seq, 0, 5 << 4, flags, 65535, 0, 0) + payload, 6
        if v6:
            ip = (struct.pack("!IHBB", 6 << 28, len(l4), proto, 64) + socket.inet_pton(socket.AF_INET6, src)
                  + socket.inet_pton(socket.AF_INET6, dst) + l4)
        else:
            ip = (struct.pack("!BBHHHBBH", 0x45, 0, 20 + len(l4), 0, 0, 64, proto, 0)
                  + socket.inet_aton(src) + socket.inet_aton(dst) + l4)
        return (b"\x00" * 12 + (b"\x81\x00\x00\x05" if vlan else b"")
                + struct.pack("!H", 0x86DD if v6 else 0x0800) + ip)

    class Wire:
        """One TCP/UDP conversation; every call appends (time, frame) to a shared list."""
        def __init__(self, frames, cip, sip, sport, cport=40000, udp=False, vlan=False):
            self.f, self.cip, self.sip, self.sport, self.cport = frames, cip, sip, sport, cport
            self.udp, self.vlan, self.sc, self.ss = udp, vlan, 1000, 9000

        def c2s(self, data, dup=False):
            fr = pkt(self.cip, self.sip, self.cport, self.sport, 0x18, self.sc, data, self.udp, self.vlan)
            self.sc += len(data)
            self.f.append((len(self.f) * 0.5, fr))
            if dup:
                self.f.append((len(self.f) * 0.5, fr))

        def s2c(self, data, dup=False):
            fr = pkt(self.sip, self.cip, self.sport, self.cport, 0x18, self.ss, data, self.udp, self.vlan)
            self.ss += len(data)
            self.f.append((len(self.f) * 0.5, fr))
            if dup:
                self.f.append((len(self.f) * 0.5, fr))

    def run_net(frames, scope_all=True, local=None, sensor_kw=None, **cfg_kw):
        got, evs = [], []
        c = Core(Config(net_enabled=False, **cfg_kw),
                 lambda k, d: got.append((d["alert_type"], d["service"])) if k == "alert" else None, Store(":memory:"))
        orig = c.handle_event
        c.handle_event = lambda ev: (evs.append(ev), orig(ev))[1]
        sn = NetSensor(c, scope_all=scope_all, replay=True)
        if local:
            sn.local = set(local)
        for t, fr in frames:
            sn.process_frame(fr, 1, T0 + t, **(sensor_kw or {}))
        return got, evs, c

    def etypes(evs):
        return Counter(e["event_type"] for e in evs)

    A = "203.0.113.50"
    SERVER = "192.0.2.10"

    def convo(n, port, step, **kw):
        fr = []
        for i in range(n):
            step(Wire(fr, A, SERVER, port, 40000 + i, **kw), i)
        return fr

    # telnet: failures, usernames only, character-at-a-time typing, success
    def telnet_try(w, i, user=b"root", pw=b"hunter2"):
        w.s2c(b"\xff\xfd\x18\r\nhost login: ")
        w.c2s(user + b"\r\x00")
        w.s2c(b"Password: ")
        w.c2s(pw + b"\r\x00")
        w.s2c(b"\r\nLogin incorrect\r\n\r\n")
    got, evs, c = run_net(convo(5, 23, telnet_try))
    check("net telnet: brute force from 'Login incorrect' replies", got, [("brute_force", "telnet")])
    leak = json.dumps(evs, default=str) + str(c.store.recent_attempts(50))
    check("net telnet: usernames kept, password never stored",
          ({e["username"] for e in evs}, "hunter2" in leak), ({"root"}, False))

    def telnet_chars(w, i):
        w.s2c(b"login: ")
        for ch in b"admin":
            w.c2s(bytes((ch,)))
        w.c2s(b"\r\x00")
        w.s2c(b"Password: ")
        for ch in b"1234":
            w.c2s(bytes((ch,)))
        w.c2s(b"\r\x00")
        w.s2c(b"\r\nLogin incorrect\r\n")
    got, evs, _ = run_net(convo(1, 23, telnet_chars))
    check("net telnet: character-mode typing", [(e["event_type"], e["username"]) for e in evs], [("failed", "admin")])

    def telnet_ok(w, i):
        telnet_try(w, i) if i < 3 else (w.s2c(b"login: "), w.c2s(b"pi\r\x00"), w.s2c(b"Password: "),
                                        w.c2s(b"raspberry\r\x00"), w.s2c(b"\r\nLast login: Mon Nov 9 from x\r\npi@host:~$ "))
    got, evs, _ = run_net(convo(4, 23, telnet_ok), threshold=50)
    check("net telnet: login success is seen", [e["event_type"] for e in evs], ["failed"] * 3 + ["accepted"])
    fr = convo(5, 23, lambda w, i: telnet_try(w, i, b"root", b"x"))
    w = Wire(fr, A, SERVER, 23, 45000)
    w.s2c(b"login: ")
    w.c2s(b"root\r\x00")
    w.s2c(b"Password: ")
    w.c2s(b"x\r\x00")
    w.s2c(b"# ")
    check("net telnet: success after failures = possible_compromise (+ root_login rule)", [a[0] for a in run_net(fr)[0]],
          ["brute_force", "possible_compromise", "root_login"])

    # FTP
    def ftp_try(w, i):
        w.s2c(b"220 ready\r\n")
        w.c2s(b"USER bob\r\n")
        w.s2c(b"331 Please specify the password.\r\n")
        w.c2s(b"PASS letmein\r\n")
        w.s2c(b"530 Login incorrect.\r\n")
    got, evs, c = run_net(convo(5, 21, ftp_try))
    check("net ftp: brute force", (got, "letmein" in json.dumps(evs, default=str)), ([("brute_force", "ftp")], False))
    fr = convo(4, 21, ftp_try)
    fr.append(fr[-1])
    fr.append(fr[-2])  # retransmitted segments
    check("net ftp: retransmitted replies are not counted twice", run_net(fr)[0], [])

    def ftp_win(w, i):
        w.c2s(b"USER anonymous\r\n")
        w.s2c(b"230-Welcome\r\n230 Login successful.\r\n")
    check("net ftp: 230 = accepted", [e["event_type"] for e in run_net(convo(1, 21, ftp_win))[1]], ["accepted"])

    # HTTP
    def http_req(w, i, path="/admin", auth=True, status=401, ua="curl/8.0", method="GET", body=b"", split=False):
        head = f"{method} {path} HTTP/1.1\r\nHost: x\r\nUser-Agent: {ua}\r\n"
        if auth:
            head += "Authorization: Basic " + base64.b64encode(b"admin:s3cret").decode() + "\r\n"
        if body:
            head += f"Content-Length: {len(body)}\r\nContent-Type: application/x-www-form-urlencoded\r\n"
        raw = head.encode() + b"\r\n" + body
        if split:
            w.c2s(raw[:25])
            w.c2s(raw[25:])
        else:
            w.c2s(raw)
        w.s2c(f"HTTP/1.1 {status} X\r\nContent-Length: 0\r\n\r\n".encode())
    got, evs, c = run_net(convo(10, 8080, http_req))
    check("net http: basic-auth brute force (threshold 10)",
          (got, "s3cret" in json.dumps(evs, default=str), {e["username"] for e in evs}),
          ([("brute_force", "http")], False, {"admin"}))
    check("net http: 401 without credentials is just a challenge",
          run_net(convo(12, 80, lambda w, i: http_req(w, i, auth=False)))[0], [])
    got, evs, _ = run_net(convo(1, 80, lambda w, i: http_req(w, i, "/?id=1'%20OR%201=1--", auth=False, status=200, split=True)))
    check("net http: SQL injection in a request split across segments", (got, etypes(evs)),
          ([("web_attack", "http")], Counter({"web_attack": 1})))
    got, evs, _ = run_net(convo(5, 80, lambda w, i: http_req(w, i, "/.env", auth=False, status=404)))
    check("net http: sensitive-path probes", (got, etypes(evs)), ([("web_probe", "http")], Counter({"probe": 5})))
    check("net http: scanner user-agent", run_net(convo(1, 80, lambda w, i: http_req(
        w, i, "/", auth=False, status=200, ua="sqlmap/1.7")))[0], [("bad_user_agent", "http")])
    check("net http: 404 flood = web_scanner", run_net(convo(30, 80, lambda w, i: http_req(
        w, i, f"/x{i}", auth=False, status=404)))[0], [("web_scanner", "http")])
    got, evs, _ = run_net(convo(10, 80, lambda w, i: http_req(
        w, i, "/wp-login.php", auth=False, status=200, method="POST", body=b"log=editor&pwd=topsecret")))
    check("net http: login-form brute force, form user kept, password dropped",
          (got, {e["username"] for e in evs}, "topsecret" in json.dumps(evs, default=str)),
          ([("brute_force", "http")], {"editor"}, False))
    check("net http: log4shell header", run_net(convo(1, 80, lambda w, i: w.c2s(
        b"GET / HTTP/1.1\r\nHost: x\r\nX-Api-Version: ${jndi:ldap://203.0.113.9/a}\r\n\r\n")))[0],
        [("web_attack", "http")])
    check("net http: ordinary browsing is silent", run_net(convo(40, 80, lambda w, i: http_req(
        w, i, "/index.html", auth=False, status=200)))[0], [])

    # mail
    def smtp_try(w, i):
        w.s2c(b"220 mx ESMTP\r\n")
        w.c2s(b"AUTH PLAIN " + base64.b64encode(b"\x00alice\x00pw123") + b"\r\n")
        w.s2c(b"535 5.7.8 Authentication credentials invalid\r\n")
    got, evs, _ = run_net(convo(5, 587, smtp_try))
    check("net smtp: AUTH PLAIN failures", (got, {e["username"] for e in evs}, "pw123" in json.dumps(evs, default=str)),
          ([("brute_force", "smtp")], {"alice"}, False))

    def smtp_login(w, i):
        w.c2s(b"AUTH LOGIN\r\n")
        w.s2c(b"334 VXNlcm5hbWU6\r\n")
        w.c2s(base64.b64encode(b"carol") + b"\r\n")
        w.s2c(b"334 UGFzc3dvcmQ6\r\n")
        w.c2s(base64.b64encode(b"hunter") + b"\r\n")
        w.s2c(b"235 2.7.0 Authentication successful\r\n")
    check("net smtp: AUTH LOGIN success", [(e["event_type"], e["username"]) for e in run_net(convo(1, 25, smtp_login))[1]],
          [("accepted", "carol")])

    def pop_try(w, i):
        w.s2c(b"+OK Dovecot ready.\r\n")
        w.c2s(b"USER dave\r\n")
        w.s2c(b"+OK\r\n")
        w.c2s(b"PASS nope\r\n")
        w.s2c(b"-ERR [AUTH] Authentication failed.\r\n")
    check("net pop3: failures", run_net(convo(5, 110, pop_try))[0], [("brute_force", "pop3")])

    def imap_try(w, i):
        w.c2s(f'a{i} LOGIN "erin" "nope"\r\n'.encode())
        w.s2c(f"a{i} NO [AUTHENTICATIONFAILED] Authentication failed.\r\n".encode())
    check("net imap: failures", run_net(convo(5, 143, imap_try))[0], [("brute_force", "imap")])

    # databases
    def my_pkt(seq, payload):
        return len(payload).to_bytes(3, "little") + bytes((seq,)) + payload

    def mysql_try(w, i):
        w.s2c(my_pkt(0, b"\x0a8.0.36\x00" + b"\x00" * 30))
        caps = struct.pack("<I", 0x0200 | 0x8000) + struct.pack("<I", 1 << 24) + b"\x21" + b"\x00" * 23
        w.c2s(my_pkt(1, caps + b"dbuser\x00" + b"\x14" + b"\x01" * 20))
        w.s2c(my_pkt(2, b"\xff" + struct.pack("<H", 1045) + b"#28000Access denied for user 'dbuser'@'203.0.113.50' (using password: YES)"))
    got, evs, _ = run_net(convo(5, 3306, mysql_try))
    check("net mysql: access denied", (got, {e["username"] for e in evs}), ([("brute_force", "mysql")], {"dbuser"}))

    def pg_try(w, i):
        kv = b"user\x00pguser\x00database\x00app\x00\x00"
        w.c2s(struct.pack("!II", 8 + len(kv), 196608) + kv)
        w.s2c(b"R\x00\x00\x00\x08\x00\x00\x00\x03")
        body = b'SFATAL\x00VFATAL\x00C28P01\x00Mpassword authentication failed for user "pguser"\x00\x00'
        w.s2c(b"E" + struct.pack("!I", 4 + len(body)) + body)
    got, evs, _ = run_net(convo(5, 5432, pg_try))
    check("net postgres: password authentication failed", (got, {e["username"] for e in evs}),
          ([("brute_force", "postgres")], {"pguser"}))
    check("net mssql: login failed (UTF-16)", run_net(convo(5, 1433, lambda w, i: w.s2c(
        b"\xaa\x00" + "Login failed for user 'sa'.".encode("utf-16-le"))))[0], [("brute_force", "mssql")])

    def redis_try(w, i):
        w.c2s(b"*2\r\n$4\r\nAUTH\r\n$3\r\nbad\r\n")
        w.s2c(b"-WRONGPASS invalid username-password pair or user is disabled.\r\n")
    check("net redis: WRONGPASS", run_net(convo(5, 6379, redis_try))[0], [("brute_force", "redis")])
    check("net redis: CONFIG SET dir abuse", run_net(convo(1, 6379, lambda w, i: w.c2s(
        b"*4\r\n$6\r\nCONFIG\r\n$3\r\nSET\r\n$3\r\ndir\r\n$9\r\n/root/.ssh\r\n")))[0], [("web_attack", "redis")])

    # SIP over UDP
    def sip_try(w, i):
        w.c2s((f'REGISTER sip:pbx SIP/2.0\r\nCall-ID: c{i}\r\nUser-Agent: Zoiper\r\n'
               f'Authorization: Digest username="1001", realm="pbx"\r\n\r\n').encode())
        w.s2c(f"SIP/2.0 403 Forbidden\r\nCall-ID: c{i}\r\n\r\n".encode())
    got, evs, _ = run_net(convo(5, 5060, sip_try, udp=True))
    check("net sip: rejected registrations (UDP)", (got, {e["username"] for e in evs}), ([("brute_force", "sip")], {"1001"}))
    check("net sip: scanner user-agent", run_net(convo(1, 5060, lambda w, i: w.c2s(
        b"OPTIONS sip:100@pbx SIP/2.0\r\nCall-ID: z\r\nUser-Agent: friendly-scanner\r\n\r\n"), udp=True))[0],
        [("bad_user_agent", "sip")])

    # TLS / SSH
    got, evs, _ = run_net(convo(15, 443, lambda w, i: w.s2c(b"\x15\x03\x03\x00\x02\x02\x28")))
    check("net https: refused TLS handshakes", (etypes(evs), got), (Counter({"preauth_close": 15}), [("ssh_scanner", "https")]))
    check("net ssh: scanner banner", run_net(convo(1, 22, lambda w, i: w.c2s(b"SSH-2.0-Nmap-SSH2-Hostkey\r\n")))[0],
          [("bad_user_agent", "ssh")])
    check("net ssh: normal client banner is silent", run_net(convo(1, 22, lambda w, i: w.c2s(b"SSH-2.0-OpenSSH_9.6\r\n")))[0], [])

    # connection rates and port scans (headers only - works for encrypted protocols)
    def syns(n, port, ip=A, dt=0.5, flags=0x02, ports=None):
        return [(i * dt, pkt(ip, SERVER, 50000 + i, ports[i] if ports else port, flags, 1)) for i in range(n)]
    check("net ssh: connection-rate guessing", run_net(syns(20, 22))[0], [("conn_brute_force", "ssh")])
    check("net ssh: just under the limit", run_net(syns(19, 22))[0], [])
    check("net ssh: escalates at 3x the limit", run_net(syns(60, 22))[0], [("conn_brute_force", "ssh")] * 2)
    check("net rdp/vnc/smb are covered too", [run_net(syns(20, p))[0] for p in (3389, 5900, 445)],
          [[("conn_brute_force", "rdp")], [("conn_brute_force", "vnc")], [("conn_brute_force", "smb")]])
    check("net https: only a flood alerts", (run_net(syns(100, 443))[0], run_net(syns(300, 443, dt=0.1))[0]),
          ([], [("connection_flood", "https")]))
    check("net per-service limit override", run_net(syns(5, 22), net_rate_override="ssh=5")[0], [("conn_brute_force", "ssh")])
    check("net allowlisted client is never reported", run_net(syns(60, 22, ip="10.1.1.1"), allowlist="10.0.0.0/8")[0], [])
    check("net SYN port scan", run_net(syns(15, 0, ports=list(range(1000, 1015))))[0], [("port_scan", "network")])
    check("net NULL/XMAS/FIN stealth scan", run_net(syns(15, 0, flags=0x00, ports=list(range(2000, 2015))))[0],
          [("port_scan", "network")])
    check("net few ports = no scan", run_net(syns(14, 0, ports=list(range(1000, 1014))))[0], [])
    got, evs, c = run_net(syns(20, 22))
    check("net conn alert shows in the attacker table and alert box",
          (c.snapshot()[1][0][0], "Port" not in format_alert({"@timestamp": evs and "2026-01-01T00:00:00", "alert_type": "conn_brute_force",
           "severity": "medium", "source_ip": A, "attempts": 20, "risk_score": 30, "service": "ssh", "usernames": []})),
          (A, True))

    # decoding: IPv6, VLAN tags, scope handling, loopback duplicates, config
    fr = []
    for i in range(5):
        telnet_try(Wire(fr, "2001:db8::50", "2001:db8::10", 23, 41000 + i, vlan=True), i)
    check("net IPv6 + 802.1Q frames", run_net(fr)[0], [("brute_force", "telnet")])
    check("net scope=local counts traffic to this host", run_net(convo(5, 23, telnet_try), scope_all=False, local={SERVER})[0],
          [("brute_force", "telnet")])
    check("net scope=local ignores other people's traffic", run_net(convo(5, 23, telnet_try), scope_all=False,
                                                                     local={"192.0.2.99"})[0], [])
    fr = convo(1, 21, ftp_try)
    check("net loopback duplicates are dropped", (len(run_net(fr, sensor_kw={"pkttype": 0, "ifname": "lo"})[1]),
                                                  len(run_net(fr, sensor_kw={"pkttype": 4, "ifname": "lo"})[1])), (0, 1))
    check("net inspection can be switched off", (run_net(convo(5, 23, telnet_try), net_inspect=False)[0],
                                                 run_net(syns(20, 22), net_inspect=False)[0]),
          ([], [("conn_brute_force", "ssh")]))
    tcp_map, udp_map = net_port_map("ssh=2200; imap=1993/tls; foo=9999; bad=0; x=99999; ??=1")
    check("net port map overrides", (tcp_map[2200], tcp_map[1993], tcp_map[9999], 0 in tcp_map, 99999 in tcp_map),
          (("ssh", "conn"), ("imap", "tls"), ("foo", "conn"), False, False))
    check("net custom port is parsed with its protocol", run_net(convo(5, 2323, telnet_try), net_ports="telnet=2323")[0],
          [("brute_force", "telnet")])

    # capture files
    frames = convo(5, 23, telnet_try)
    with tempfile.TemporaryDirectory() as td:
        p1, p2 = os.path.join(td, "a.pcap"), os.path.join(td, "b.pcapng")
        with open(p1, "wb") as f:
            f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
            for t, fr in frames:
                f.write(struct.pack("<IIII", int(T0 + t), int((T0 + t) % 1 * 1e6), len(fr), len(fr)) + fr)
        with open(p2, "wb") as f:
            def blk(btype, body):
                body += b"\x00" * (-len(body) % 4)
                return struct.pack("<II", btype, len(body) + 12) + body + struct.pack("<I", len(body) + 12)
            f.write(blk(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1)))
            f.write(blk(1, struct.pack("<HHI", 1, 0, 65535)))
            for t, fr in frames:
                us = int((T0 + t) * 1e6)
                f.write(blk(6, struct.pack("<IIIII", 0, us >> 32, us & 0xFFFFFFFF, len(fr), len(fr)) + fr))
        for p in (p1, p2):
            got = []
            cc = Core(Config(net_enabled=False), lambda k, d: got.append(d["alert_type"]) if k == "alert" else None,
                      Store(":memory:"))
            n = NetSensor(cc, scope_all=True, replay=True).replay_pcap(p)
            check(f"net replay {os.path.basename(p)}", (n, got), (len(frames), ["brute_force"]))
    core.stop()
    print(f"\nAll {ok} self-tests passed.")


def main():
    ap = argparse.ArgumentParser(description="SSH Brute Force Detector (SSH Guard)")
    ap.add_argument("--version", action="version", version=f"ssh-guard {__version__}")
    ap.add_argument("--headless", action="store_true", help="no GUI; alert box on stderr, JSON lines on stdout")
    ap.add_argument("--replay", metavar="FILE", help="process an existing log once and exit")
    ap.add_argument("--kind", default="syslog", choices=sorted(SOURCE_KINDS),
                    help="log format for --replay: syslog (default), web/http/nginx/apache, https")
    ap.add_argument("--report", type=int, metavar="HOURS", help="write an HTML report for the last N hours and exit")
    ap.add_argument("--selftest", action="store_true", help="run built-in tests")
    ap.add_argument("--kibana-export", metavar="FILE", help="write an importable Kibana dashboard (NDJSON)")
    ap.add_argument("--init-config", action="store_true", help="write config.json from current defaults/flags and exit")
    ap.add_argument("--geoip", metavar="MMDB", help="GeoIP database (.mmdb)")
    ap.add_argument("--log", help="log file path")
    ap.add_argument("--journal", action="store_true", help="read from journald")
    ap.add_argument("--es-url", help="enable Elasticsearch at this URL")
    ap.add_argument("--web", action="store_true", help="enable the web dashboard")
    ap.add_argument("--web-port", type=int, help="web dashboard port")
    ap.add_argument("--auto-block", action="store_true", help="enable auto-block (dry-run unless --live)")
    ap.add_argument("--live", action="store_true", help="really modify the firewall when auto-blocking")
    ap.add_argument("--pcap", metavar="FILE", help="replay a pcap/pcapng capture through the network sensor and exit")
    ap.add_argument("--no-sniff", action="store_true", help="do not watch the network (log sources only)")
    ap.add_argument("--iface", help="network interface to watch (default: all)")
    ap.add_argument("--scope", choices=("local", "all"), help="local = traffic to this host (default), "
                    "all = every flow on the segment (mirror port / gateway)")
    ap.add_argument("--capture-helper", nargs="?", const="", metavar="IFACE", help=argparse.SUPPRESS)
    args = ap.parse_args()

    if args.capture_helper is not None:
        capture_helper(args.capture_helper)
        return

    if args.selftest:
        selftest()
        return
    if args.report:
        print(write_report(Store(), max(1, args.report)))
        return
    if args.kibana_export:
        print(kibana_export(args.kibana_export, load_config().es_prefix))
        return
    cfg = load_config()
    if args.geoip:
        cfg.geoip_db = args.geoip
    if args.log:
        cfg.log_path = args.log
    if args.journal:
        cfg.use_journal = True
    if args.es_url:
        cfg.es_enabled, cfg.es_url = True, args.es_url
    if args.web:
        cfg.web_enabled = True
    if args.web_port:
        cfg.web_port = args.web_port
    if args.auto_block:
        cfg.auto_block = True
    if args.live:
        cfg.block_dry_run = False
    if args.no_sniff:
        cfg.net_enabled = False
    if args.iface:
        cfg.net_iface = args.iface
    if args.scope:
        cfg.net_scope = args.scope

    if args.init_config:
        save_config(cfg)
        print(CONFIG_PATH)
        return
    if args.headless or args.replay or args.pcap:
        run_headless(cfg, args.replay, SOURCE_KINDS.get(args.kind, "syslog"), args.pcap)
    elif not TK_OK:
        sys.exit("tkinter is not available; install python3-tk or use --headless")
    else:
        App().mainloop()


if __name__ == "__main__":
    main()
