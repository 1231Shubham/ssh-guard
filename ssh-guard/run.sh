#!/usr/bin/env bash
# SSH Guard launcher for Kali / Debian.   ./run.sh [gui|headless|test|nettest|pcap FILE|report [HOURS]]  (see README.md)
set -u
cd "$(dirname "$(readlink -f "$0")")" || exit 1
PY="${PYTHON:-python3}"
mode="${1:-gui}"; [ $# -gt 0 ] && shift

# one config + database no matter whether we run as your user or through sudo
home_dir="$HOME"
[ -n "${SUDO_USER:-}" ] && home_dir="$(getent passwd "$SUDO_USER" | cut -d: -f6)"
export SSH_GUARD_HOME="${SSH_GUARD_HOME:-$home_dir/.ssh_guard}"

can_read_logs() {
  [ "$(id -u)" -eq 0 ] && return 0
  id -nG | tr ' ' '\n' | grep -qxE 'adm|systemd-journal'
}

# the live network sensor reads raw packets: root, or passwordless sudo (Kali's default user has it)
sniff_hint() {
  [ "$(id -u)" -eq 0 ] && return 0
  sudo -n true 2>/dev/null && return 0
  echo "Heads-up: the network sensor (HTTP/Telnet/FTP/... on the wire) needs root. Run  sudo ./run.sh $mode  or"
  echo "  give your user passwordless sudo. Log monitoring works without it."
}

case "$mode" in
  test|selftest) exec "$PY" ssh_guard.py --selftest ;;
  nettest)       [ "$(id -u)" -eq 0 ] && exec "$PY" tools/net_livetest.py
                 exec sudo -E "$PY" tools/net_livetest.py ;;
  pcap)          [ $# -ge 1 ] || { echo "usage: ./run.sh pcap capture.pcap[ng]"; exit 2; }
                 exec "$PY" ssh_guard.py --pcap "$@" ;;
  report)        exec "$PY" ssh_guard.py --report "${1:-24}" ;;
  headless)      sniff_hint
                 can_read_logs || echo "Note: this user cannot read system logs (see README, Troubleshooting)." >&2
                 exec "$PY" ssh_guard.py --headless "$@" ;;
  gui)
    if ! "$PY" -c "import tkinter" 2>/dev/null; then
      echo "Tkinter is missing.  Install it with:"
      echo "    sudo apt update && sudo apt install -y python3-tk"
      exit 1
    fi
    if [ "$(id -u)" -eq 0 ] && [ -n "${SUDO_USER:-}" ]; then   # sudo strips the X11 variables
      export DISPLAY="${DISPLAY:-:0}"
      export XAUTHORITY="${XAUTHORITY:-$home_dir/.Xauthority}"
    fi
    if [ -z "${DISPLAY:-}" ] && [ -z "${WAYLAND_DISPLAY:-}" ]; then
      echo "No graphical display found.  Start this from the desktop, or use:  ./run.sh headless"
      exit 1
    fi
    sniff_hint
    if ! can_read_logs; then
      echo "Heads-up: your user cannot read system logs (needs group 'adm' or 'systemd-journal')."
      echo "  Fix:  sudo usermod -aG adm,systemd-journal \$USER   then log out and back in"
      echo "  Or:   run  sudo ./run.sh"
      echo "  (The demo log from tools/simulate_attack.py works without any of this.)"
    fi
    exec "$PY" ssh_guard.py "$@"
    ;;
  *) echo "usage: ./run.sh [gui|headless|test|nettest|pcap FILE|report [HOURS]]"; exit 2 ;;
esac
