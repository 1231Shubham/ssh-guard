#!/usr/bin/env python3
"""
Append realistic FAKE log lines to files so you can demo SSH Guard without attacking anything.

    python3 tools/simulate_attack.py /tmp/demo_auth.log --web /tmp/demo_access.log
    python3 tools/simulate_attack.py /tmp/demo_auth.log --delay 0       # instant, syslog-style services only

LOGFILE gets syslog-style lines (SSH, Telnet, FTP, MySQL, SMTP); --web gets nginx/Apache access-log lines.
Only documentation-reserved addresses are used (203.0.113.0/24, 198.51.100.0/24).
It refuses to write under /var/log so your real logs are never polluted (override: --force).
"""
import argparse
import os
import socket
import sys
import time
from datetime import datetime, timezone

HOST = socket.gethostname()
PID = 4242


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("logfile", help="syslog-style demo log (SSH, Telnet, FTP, MySQL, SMTP lines)")
    ap.add_argument("--web", metavar="FILE", help="also write nginx/Apache access-log lines to FILE")
    ap.add_argument("--delay", type=float, default=0.12, help="seconds between lines (default 0.12)")
    ap.add_argument("--force", action="store_true", help="allow writing under /var/log")
    a = ap.parse_args()
    for path in filter(None, (a.logfile, a.web)):
        if os.path.abspath(path).startswith("/var/log") and not a.force:
            sys.exit("Refusing to write fake entries into /var/log. Use a file such as /tmp/demo_auth.log")

    with open(a.logfile, "a", buffering=1) as f:
        def emit(prog, msg):
            f.write(f"{datetime.now().astimezone().isoformat(timespec='microseconds')} {HOST} {prog}[{PID}]: {msg}\n")
            f.flush()
            time.sleep(a.delay)

        def ssh_fail(user, ip, invalid=False):
            emit("sshd", f"Failed password for {'invalid user ' if invalid else ''}{user} from {ip} port 4{PID % 1000} ssh2")

        print("1/10 SSH brute force on root              (203.0.113.45)")
        for _ in range(12):
            ssh_fail("root", "203.0.113.45")
        print("2/10 SSH password spraying                (203.0.113.46)")
        for u in ("admin", "test", "oracle", "ubuntu", "pi", "postgres", "git", "ftp"):
            ssh_fail(u, "203.0.113.46", invalid=True)
        print("3/10 SSH user enumeration                 (203.0.113.47)")
        for i in range(10):
            emit("sshd", f"Invalid user svc{i} from 203.0.113.47 port 5{i:03d}")
        print("4/10 distributed attack on 'admin'        (198.51.100.1-6)")
        for i in range(1, 7):
            ssh_fail("admin", f"198.51.100.{i}", invalid=True)
        print("5/10 scanner dropping connections         (203.0.113.49)")
        for i in range(18):
            emit("sshd", f"Connection closed by 203.0.113.49 port 6{i:03d} [preauth]")
        print("6/10 compromise: failures, then success   (203.0.113.48)")
        for _ in range(4):
            ssh_fail("kali", "203.0.113.48")
        emit("sshd", "Accepted password for kali from 203.0.113.48 port 4242 ssh2")
        print("7/10 Telnet brute force                   (203.0.113.50)")
        for i in range(6):
            emit("login", f"FAILED LOGIN {i + 1} FROM 203.0.113.50 FOR root, Authentication failure")
        print("8/10 FTP brute force (vsftpd)             (203.0.113.51)")
        for _ in range(6):
            emit("vsftpd", '[pid 77] [admin] FAIL LOGIN: Client "203.0.113.51"')
        print("9/10 MySQL password guessing              (203.0.113.52)")
        for _ in range(6):
            emit("mysqld", "[Warning] Access denied for user 'root'@'203.0.113.52' (using password: YES)")
        print("10/10 SMTP SASL guessing                  (203.0.113.53)")
        for _ in range(6):
            emit("postfix/smtpd", "warning: unknown[203.0.113.53]: SASL LOGIN authentication failed: UGFzc3dvcmQ6")

    if a.web:
        with open(a.web, "a", buffering=1) as w:
            def hit(ip, req, status=200, user="-", ua="Mozilla/5.0 (X11; Linux x86_64)"):
                now = datetime.now(timezone.utc).strftime("%d/%b/%Y:%H:%M:%S +0000")
                w.write(f'{ip} - {user} [{now}] "{req}" {status} 512 "-" "{ua}"\n')
                w.flush()
                time.sleep(a.delay / 4)

            print("web  SQL injection + path traversal       (203.0.113.60)")
            hit("203.0.113.60", "GET /index.php?id=1%20UNION%20SELECT%20username,password%20FROM%20users-- HTTP/1.1")
            hit("203.0.113.60", "GET /download?file=../../../../etc/passwd HTTP/1.1", 400)
            print("web  probing for sensitive files          (203.0.113.61)")
            for p in ("/.env", "/.git/config", "/phpmyadmin/", "/cgi-bin/test.cgi", "/server-status", "/actuator/env"):
                hit("203.0.113.61", f"GET {p} HTTP/1.1", 404)
            print("web  HTTP basic-auth brute force          (203.0.113.62)")
            for _ in range(12):
                hit("203.0.113.62", "GET /admin/ HTTP/1.1", 401, user="admin")
            print("web  scanner user-agent + 404 flood       (203.0.113.63)")
            hit("203.0.113.63", "GET / HTTP/1.1", 200, ua="Nikto/2.1.6")
            for i in range(35):
                hit("203.0.113.63", f"GET /page{i}.html HTTP/1.1", 404)
            print("web  WordPress login flood                (203.0.113.64)")
            for _ in range(12):
                hit("203.0.113.64", "POST /wp-login.php HTTP/1.1", 200)

    print("\nDone. Expected alert types: brute_force (ssh, telnet, ftp, mysql, smtp, http), password_spray, "
          "user_enumeration,\ndistributed_attack, ssh_scanner, possible_compromise"
          + (", web_attack, web_probe, bad_user_agent, web_scanner." if a.web else "."))


if __name__ == "__main__":
    main()
