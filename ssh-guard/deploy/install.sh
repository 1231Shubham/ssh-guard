#!/usr/bin/env bash
# Installs SSH Guard as a systemd service (headless, web dashboard on 127.0.0.1:8080).
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "Run as root: sudo ./install.sh" >&2; exit 1; }

SRC="$(cd "$(dirname "$0")" && pwd)"
PY="$SRC/../ssh_guard.py"; [ -f "$SRC/ssh_guard.py" ] && PY="$SRC/ssh_guard.py"
[ -f "$PY" ] || { echo "ssh_guard.py not found next to or above this script" >&2; exit 1; }

echo "Running self-test..."
python3 "$PY" --selftest >/dev/null

install -d -m 755 /opt/ssh-guard
install -m 755 "$PY" /opt/ssh-guard/ssh_guard.py
install -d -m 750 /var/lib/ssh-guard
[ -f /etc/ssh-guard.env ] || install -m 600 "$SRC/ssh-guard.env.example" /etc/ssh-guard.env
if [ ! -f /var/lib/ssh-guard/config.json ]; then
  SSH_GUARD_HOME=/var/lib/ssh-guard python3 /opt/ssh-guard/ssh_guard.py --init-config --web >/dev/null
fi
install -m 644 "$SRC/ssh-guard.service" /etc/systemd/system/ssh-guard.service
systemctl daemon-reload
systemctl enable --now ssh-guard

echo
echo "SSH Guard is running.  Logs:    journalctl -u ssh-guard -f"
echo "                       Config:  /var/lib/ssh-guard/config.json  (restart after editing)"
echo "                       Secrets: /etc/ssh-guard.env"
echo "                       Web UI:  http://127.0.0.1:8080/  (use: ssh -L 8080:127.0.0.1:8080 yourserver)"
echo "                       Report:  SSH_GUARD_HOME=/var/lib/ssh-guard python3 /opt/ssh-guard/ssh_guard.py --report 24"
