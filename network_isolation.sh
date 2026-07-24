#!/usr/bin/env bash
set -euo pipefail

MODE="allow"
C2_IP="${C2_IP:-127.0.0.1}"

usage() {
  echo "Usage: $0 [--block-egress|--allow-egress] [--c2-ip IP]"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --block-egress)
      MODE="block"
      shift
      ;;
    --allow-egress)
      MODE="allow"
      shift
      ;;
    --c2-ip)
      C2_IP="$2"
      shift 2
      ;;
    *)
      usage >&2
      exit 2
      ;;
  esac
done

if [[ "$MODE" == "block" ]]; then
  echo "[+] Blocking egress except to $C2_IP"
  if [[ "$(uname)" == "Darwin" ]]; then
    pfctl -e >/dev/null 2>&1 || true
    echo "block drop all" | pfctl -f - >/dev/null 2>&1 || true
    echo "pass out proto tcp to $C2_IP keep state" | pfctl -f - >/dev/null 2>&1 || true
  else
    iptables -P OUTPUT DROP
    iptables -A OUTPUT -d "$C2_IP" -j ACCEPT
    iptables -A OUTPUT -d 127.0.0.1 -j ACCEPT
    iptables -A OUTPUT -o lo -j ACCEPT
  fi
else
  echo "[+] Restoring full egress"
  if [[ "$(uname)" == "Darwin" ]]; then
    pfctl -d >/dev/null 2>&1 || true
  else
    iptables -P OUTPUT ACCEPT || true
    iptables -F OUTPUT || true
  fi
fi
