#!/usr/bin/env python3
"""
Live end-to-end test of the SSH Guard network sensor - real sockets, real packet capture.

It starts tiny fake Telnet / FTP / HTTP / SSH servers on 127.0.0.1 (loopback only, nothing leaves this machine),
logs in to them with wrong passwords, scans some closed ports, and checks that the sensor, reading raw packets
from the 'lo' interface, raised the expected alerts.   Needs root (raw packet capture):

    sudo ./run.sh nettest
"""
import os
import socket
import socketserver
import sys
import threading
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
os.environ.setdefault("SSH_GUARD_HOME", os.path.join(os.environ.get("TMPDIR", "/tmp"), "ssh_guard_nettest"))
import ssh_guard as g  # noqa: E402


def line(rf):
    return rf.readline().strip()


class Telnet(socketserver.StreamRequestHandler):
    def handle(self):
        self.wfile.write(b"\xff\xfd\x18\r\nlabhost login: ")
        line(self.rfile)
        self.wfile.write(b"Password: ")
        line(self.rfile)
        self.wfile.write(b"\r\nLogin incorrect\r\n")


class Ftp(socketserver.StreamRequestHandler):
    def handle(self):
        self.wfile.write(b"220 lab ftp\r\n")
        line(self.rfile)
        self.wfile.write(b"331 Please specify the password.\r\n")
        line(self.rfile)
        self.wfile.write(b"530 Login incorrect.\r\n")


class Http(socketserver.StreamRequestHandler):
    def handle(self):
        while line(self.rfile):
            pass
        self.wfile.write(b"HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=lab\r\nContent-Length: 0\r\n\r\n")


class Banner(socketserver.StreamRequestHandler):
    def handle(self):
        self.wfile.write(b"SSH-2.0-LabServer\r\n")


def serve(handler):
    srv = socketserver.ThreadingTCPServer(("127.0.0.1", 0), handler)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


def talk(port, script):
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=3) as s:
            for send, expect in script:
                if expect:
                    s.recv(512)
                if send:
                    s.sendall(send)
            s.settimeout(0.5)
            try:
                s.recv(512)
            except OSError:
                pass
    except OSError:
        pass


def main():
    if os.geteuid() != 0:
        sys.exit("Raw packet capture needs root:  sudo ./run.sh nettest")
    servers = {name: serve(h) for name, h in (("telnet", Telnet), ("ftp", Ftp), ("http", Http), ("ssh", Banner))}
    ports = {k: v[1] for k, v in servers.items()}
    alerts, logs = [], []

    def emit(kind, data):
        if kind == "alert":
            alerts.append((data["alert_type"], data["service"]))
        elif kind == "log":
            logs.append(data)
            print("  #", data)

    cfg = g.Config(net_enabled=True, net_iface="lo", net_scope="local", allowlist="", net_conn_threshold=20,
                   net_scan_ports=15, threshold=5, thresholds_override="http=8", auto_sources=False)
    cfg.net_ports = "; ".join(f"{k}={v}" for k, v in ports.items())
    core = g.Core(cfg, emit, g.Store(":memory:"))
    core.start(engine=False)
    sensor = g.NetSensor(core)
    sensor.start()
    time.sleep(1.5)
    if not sensor.is_alive():
        sys.exit("The network sensor did not start: " + "; ".join(logs[-2:]))

    print(f"Attacking fake services on 127.0.0.1 {ports} ...")
    auth = b"GET /admin HTTP/1.1\r\nHost: lab\r\nAuthorization: Basic YWRtaW46d3Jvbmc=\r\n\r\n"
    for _ in range(6):
        talk(ports["telnet"], [(b"root\r\n", True), (b"toor\r\n", True)])
        talk(ports["ftp"], [(b"USER admin\r\n", True), (b"PASS nope\r\n", True)])
    for _ in range(9):
        talk(ports["http"], [(auth, False)])
    for _ in range(22):
        talk(ports["ssh"], [])
    closed = []
    for p in range(1, 40):
        if p not in ports.values():
            with socket.socket() as s:
                s.settimeout(0.2)
                s.connect_ex(("127.0.0.1", 20000 + p))
                closed.append(p)
    want = {("brute_force", "telnet"), ("brute_force", "ftp"), ("brute_force", "http"),
            ("conn_brute_force", "ssh"), ("port_scan", "network")}
    deadline = time.time() + 10
    while time.time() < deadline and not want <= set(alerts):
        time.sleep(0.3)
    sensor.stop()
    core.stop()
    got = set(alerts)
    print()
    for item in sorted(want):
        print(f"[{'PASS' if item in got else 'FAIL'}] {item[0]} on {item[1]}")
    print(f"packets seen: {sensor.stats['packets']}, protocol events: {sensor.stats['events']}")
    sys.exit(0 if want <= got else 1)


if __name__ == "__main__":
    main()
