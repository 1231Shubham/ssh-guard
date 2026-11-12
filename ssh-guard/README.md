# SSH Guard - multi-service brute-force & attack detector

Watches **SSH, Telnet, HTTP, HTTPS, FTP, SMTP/IMAP/POP3, MySQL, PostgreSQL, MSSQL, Redis, RDP, VNC, SMB, SIP, Webmin** and any
PAM-based service - from **service logs** *and* straight from **live network traffic** (raw packet capture, no tcpdump/scapy needed).
Python 3 + Linux + Elasticsearch (optional) + Tkinter. **No pip packages needed.**
Tested logic on Python 3.12; written for Kali / Debian with OpenSSH.

## 1. Quick start (Kali)

```bash
unzip ssh-guard-kali.zip && cd ssh-guard
sudo apt update && sudo apt install -y python3-tk     # the only thing to install (GUI toolkit)
./run.sh test                                         # self-test: must end with "All NN self-tests passed."
./run.sh                                              # start the GUI
```

Run the GUI as your normal user (not with `sudo`) - it works fine and only calls `sudo` for firewall changes.

> **New in 1.2 - works on a real network.** The *network sensor* reads packets directly, so it sees attacks on services that
> write no useful log (Telnet on routers/IoT, plain HTTP, RDP, VNC, SMB ...) and on traffic you only mirror. See section 2c.
> Start it with root: `sudo ./run.sh` (GUI) or `sudo ./run.sh headless`. Verify it with `sudo ./run.sh nettest`.

### Kali specifics
* **No `/var/log/auth.log`?** Recent Kali logs to journald only. SSH Guard detects this and reads journald automatically
  (it also understands the `sshd-session` name used by OpenSSH 9.8+). To get a classic auth.log instead: `sudo apt install rsyslog`.
* **Permission errors?** Your user needs to read the logs:
  `sudo usermod -aG adm,systemd-journal $USER`, then log out and back in (or run `sudo ./run.sh`).
* **No SSH server running?** `sudo systemctl enable --now ssh` (Kali ships it disabled).

## 2. Try it without attacking anything (demo)

1. `./run.sh`, open **Settings**, set **Log file** to `/tmp/demo_auth.log`, set **More logs** to `web=/tmp/demo_access.log`,
   make sure *Use journald* is **unticked**, then click **Start monitoring**.
2. In a second terminal: `python3 tools/simulate_attack.py /tmp/demo_auth.log --web /tmp/demo_access.log`
3. Watch the **Login attempts**, **Alerts** and **Dashboard** tabs fill up (the *Service* column shows ssh / telnet / ftp / http ...);
   a pop-up shows the attack box. Then open **Reports -> Generate HTML report**.

The simulator uses documentation-only IP addresses and refuses to write into `/var/log`.

## 2b. Which logs are watched

| Service | Where SSH Guard looks |
|---|---|
| SSH, Telnet (`login`, `telnetd`), generic PAM services | the main **Log file** (`/var/log/auth.log`, `/var/log/secure`) or journald |
| HTTP / HTTPS | nginx and Apache **access and error logs** (auto-detected under `/var/log/nginx`, `/var/log/apache2`, `/var/log/httpd`) |
| FTP, mail, MySQL/MariaDB, PostgreSQL, xrdp, Asterisk | auto-detected: `vsftpd.log`, `proftpd.log`, `mail.log`/`maillog`, `daemon.log`, `/var/log/messages`, `mysql/error.log`, `postgresql-*.log`, ... |
| anything else | **Settings -> Source -> More logs**: `web=/path/access.log; https=/path/ssl_access.log; syslog=/path/other.log` |

* Auto-detection can be switched off (*Auto-detect service logs*). Missing files are waited for; unreadable ones are reported in the Console.
* Without rsyslog (journald-only Kali) the service names are read from journald instead; web server logs are always files.
* PostgreSQL needs the client IP in its log lines (`log_line_prefix` with `%h` or `%r`). Apache/nginx must use the standard
  *combined* log format (a leading `vhost:port` column, as in Apache's `vhost_combined`, is understood and marks HTTPS).
* Replay an old log of any type: `python3 ssh_guard.py --replay access.log --kind web`.

> **Behind a reverse proxy, load balancer or CDN (Cloudflare, HAProxy, an nginx front end ...)?** Make sure the web server logs the
> *real client IP* (nginx `realip` module / Apache `mod_remoteip`). If the log shows the proxy's address, SSH Guard would raise
> alerts against the proxy and auto-block could cut off all visitors - allowlist the proxy addresses in *Settings -> Detection*
> and keep *Dry-run* on until the logged addresses look right.

## 2c. Watching the real network (live packets)

The sensor opens a raw `AF_PACKET` socket (Linux, stdlib only), follows each TCP conversation and turns what it sees into the
same events and alerts as the log parsers - so thresholds, allowlist, risk score, blocking, reports, Elasticsearch and notifications
all work unchanged. Alerts carry the service name (telnet, http, rdp ...).

| What it sees | How |
|---|---|
| **Telnet** | server replies *Login incorrect / Login failed*, password re-prompts (Cisco style), shell prompt = success; usernames typed char-by-char are rebuilt |
| **HTTP** (80, 8080, 8000, 8888, 3128, 9200, 5985 ...) | Basic/Digest auth answered by 401, login-form POSTs (wp-login.php, /login ...), SQLi / XSS / traversal / command injection / Log4Shell / Shellshock in URL, headers and POST bodies, sensitive-path probes, scanner user-agents, 404/403 floods |
| **HTTPS** (443, 8443 ...) | content is encrypted, so: refused TLS handshakes (fatal alerts), non-TLS clients on TLS ports, connection floods |
| **FTP, SMTP AUTH, POP3, IMAP** | `530`, `535`, `-ERR`, `NO` replies, `230`/`235`/`+OK` successes (SASL PLAIN/LOGIN/CRAM user names decoded) |
| **MySQL, PostgreSQL, MSSQL, Redis** | *Access denied* (1045), `28P01`, *Login failed for user*, `-WRONGPASS`; Redis `CONFIG SET dir` / `SLAVEOF` / `MODULE LOAD` abuse |
| **SIP** (UDP and TCP 5060) | digest REGISTERs rejected with 401/403, SIPVicious-style scanner agents |
| **SSH, RDP, VNC, SMB, LDAP, Oracle, MongoDB, MQTT, SNMP, TLS-wrapped mail ...** | encrypted/binary, so login guessing is inferred from the **connection rate** per source (`conn_brute_force`; SSH client banners of Nmap/libssh/paramiko/zgrab also flagged) |
| **Any port** | `port_scan` for SYN scans and NULL / FIN / XMAS stealth scans; `connection_flood` for very high connection rates |

**Passwords never leave the parser**: Telnet/FTP/POP3/SMTP/IMAP/HTTP/DB passwords and tokens are read only to be discarded; usernames are kept.
Untick *Read cleartext protocols* (`net_inspect`) to use headers only (rates and scans).

### Running it
* **Needs root** (`CAP_NET_RAW`). `sudo ./run.sh` / `sudo ./run.sh headless`, or the systemd service. If you start the GUI as a normal
  user with passwordless sudo (Kali's default `kali` user), the sensor launches a tiny `sudo -n` capture helper automatically;
  otherwise the Console says exactly what is missing and log monitoring carries on.
* **Scope** (*Settings -> Advanced -> Network sensor*): `local` (default) = traffic to/from this machine's own addresses.
  `all` = every flow the interface sees - use it on a gateway, a bridge or a **mirror/SPAN port** to protect a whole segment; then
  set a single *Interface* (otherwise forwarded packets are seen twice) and allowlist your internal ranges and scanners.
* **Non-standard ports**: *Ports* = `ssh=2200; http=8081,8082; telnet=2323; imap=1993/tls` (`/tls` = encrypted variant). Unknown names are
  treated as encrypted services and watched by connection rate. Rate limits: `net_conn_threshold` (login services, default 20/window),
  `net_flood_threshold` (others, default 300), `net_scan_ports` (default 15), per service `ssh=10,rdp=10`.
* **Pcap files**: `sudo ./run.sh pcap capture.pcapng` replays a Wireshark/tcpdump capture (pcap or pcapng, Ethernet/VLAN/Linux-cooked/raw IP, IPv4 + IPv6)
  through all detectors - handy for forensics and for tuning thresholds.
* **Verify it**: `sudo ./run.sh nettest` starts fake Telnet/FTP/HTTP/SSH servers on 127.0.0.1, attacks them over real sockets, scans closed ports,
  and checks the sensor raised the right alerts (loopback only, nothing leaves the machine). In your own tests remember `127.0.0.0/8` is allowlisted by default.
* Capture-time limits: encrypted payloads can't be read (only rates/handshakes), TCP is followed per direction without full reassembly
  (very fragmented or reordered streams can be missed), NAT/proxy front ends show the proxy's address. Packet decoding
  is pure Python (about 500k packets/s measured on synthetic mixed traffic, less with live capture overhead); on very busy links limit *Interface*/*Ports* or use a mirror box.

### What is detected on the web
Brute force (HTTP basic-auth 401s, floods of POSTs to login pages such as wp-login.php), attack signatures in URLs and
headers (SQL injection, XSS, path traversal, command injection, Log4Shell, Shellshock, PHP wrappers), probing for sensitive paths
(`/.env`, `/.git`, phpMyAdmin, `/cgi-bin`, actuator ...), scanner user-agents (sqlmap, nikto, nmap, ...), floods of 404/403/400 responses,
and TLS probing. Signatures are heuristics - tune *Settings -> Advanced -> Web & services* (thresholds, per-service failure limits
such as `http=10,ftp=5`) or the allowlist if a legitimate scanner or monitoring system triggers alerts.

## 3. Testing against your own servers

Only attack machines you own or are explicitly authorised to test.

* `127.0.0.0/8` is in the default **Allowlist**, so attacks from the same machine are ignored on purpose.
  For a local test remove it (Settings -> Detection -> Allowlist), or attack from another VM.
* Example from a second lab VM, e.g. Kali's hydra: `hydra -l fakeuser -p wrongpass -t 4 ssh://TARGET_IP`

## 4. Blocking

Auto-block is **off** and, when switched on, starts in **dry-run** (it only logs "would block"). To go live:
Settings -> Response -> tick *Auto-block*, untick *Dry-run*. It needs root or passwordless sudo for `iptables`/`nft`
(auto-selects nftables if iptables is missing). It never blocks allowlisted IPs, your own SSH client IP, or IPs
that logged in successfully before the attack; repeat offenders get longer bans. Old log entries (over 1 h) never trigger blocks or notifications.

## 5. What it detects

brute_force, password_spray, slow_brute_force, distributed_attack, possible_compromise (success after failures),
user_enumeration, ssh_scanner, honeypot_user/honeypot_login (canary names), root_login, new_login_source,
known_bad_ip (threat feeds), for the web: web_attack, web_probe, web_scanner, bad_user_agent,
and from the network sensor: conn_brute_force, connection_flood, port_scan.
Each alert names its **service**, carries a 0-100 risk score and a country (with a GeoIP `.mmdb`, optional).
Failures are counted per service (3 SSH + 3 FTP failures from one IP do not add up).

## 6. Optional extras

| Feature | How |
|---|---|
| Elasticsearch | Settings -> Elasticsearch (no client library needed). `deploy/ssh-guard-kibana.ndjson` = importable Kibana dashboard |
| Email / webhook / Telegram | Settings and Advanced tabs, then *Send test notification* (passwords/tokens are never saved to disk; use env vars `SMTP_PASSWORD`, `ES_PASSWORD`, `ES_API_KEY`, `TELEGRAM_TOKEN`) |
| SIEM | Advanced -> Syslog target, e.g. `udp://siem:514` (CEF format) |
| Web dashboard + Prometheus | Settings -> Web dashboard (127.0.0.1:8080, read-only, `/metrics`) |
| Reports | Reports tab, or `./run.sh report 24` |
| Run as a service | `sudo deploy/install.sh` (headless + web dashboard; `journalctl -u ssh-guard -f`; `systemctl reload ssh-guard` re-reads config) |
| GeoIP | download a free GeoLite2/DB-IP `.mmdb` country database, set its path in Settings -> Source |

## 7. Files

```
run.sh                    launcher with Kali preflight checks (gui | headless | test | nettest | pcap FILE | report)
ssh_guard.py              the whole application (stdlib only, includes the network sensor)
tools/simulate_attack.py  fake-log generator for demos
tools/net_livetest.py     live end-to-end test of the network sensor on loopback (sudo ./run.sh nettest)
deploy/                   systemd service, installer, Kibana dashboard
```
Data lives in `~/.ssh_guard/` (config.json, state.db, reports/); override with `SSH_GUARD_HOME`.

## 8. Troubleshooting

| Symptom | Fix |
|---|---|
| `Tkinter is missing` | `sudo apt install -y python3-tk` |
| GUI says "No graphical display" | start it from the desktop, or use `./run.sh headless` |
| Console: *journald ... not seeing messages* / *permission denied* | add your user to `adm,systemd-journal` and re-login, or `sudo ./run.sh` |
| Nothing is detected | check the Console tab for the source in use; make sure SSH is running and the attack is **not** from an allowlisted IP |
| Demo shows nothing | *Use journald* must be unticked, the log path must be the demo file, and the web demo needs `web=/tmp/demo_access.log` under *More logs* |
| Web server attacks are not seen | check the Console for "Tailing /var/log/nginx/access.log [web]"; the file must be readable (group `adm`) and in combined log format |
| Block button says "sudo: a password is required" | run with `sudo ./run.sh`, or give your user passwordless sudo for iptables/nft |
| Console: *Network sensor NOT started: packet capture needs root* | `sudo ./run.sh`, or passwordless sudo for the helper, or the systemd service |
| Network sensor runs but nothing alerts | check *Scope* (traffic must be to this host's own address, or use `all` on a mirror port), the *Allowlist* (127.0.0.0/8 by default) and that the service port is known (*Ports*) |
| Every packet counted twice / double alerts | scope `all` on a gateway with *Interface* empty - pick one interface |
| Elasticsearch unavailable | the tool keeps working locally; check URL/credentials; `http://localhost:9200` for a local node |

Headless / SSH-only machines: `./run.sh headless` prints an alert box on stderr and JSON lines on stdout.
