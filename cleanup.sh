#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

mkdir -p "$ROOT_DIR/archive"
TS="$(date +%Y%m%d_%H%M%S)"

pkill -f "c2_server.py" 2>/dev/null || true
adb kill-server 2>/dev/null || true
adb devices 2>/dev/null | tail -n +2 | awk '{print $1}' | xargs -r -n1 adb -s "$1" disconnect 2>/dev/null || true

for name in $(ps -eo pid,cmd | awk '/emulator/ && !/awk/ {print $1}'); do
  kill "$name" 2>/dev/null || true
done

rm -rf "$ROOT_DIR/__pycache__" "$ROOT_DIR/output/traces" "$ROOT_DIR/logs" "$ROOT_DIR/test_app/app/build" "$ROOT_DIR/test_app/app/.gradle" 2>/dev/null || true
find "$ROOT_DIR" -name '*.pyc' -delete 2>/dev/null || true

if [[ -d "$ROOT_DIR/results" ]]; then
  tar -czf "$ROOT_DIR/archive/results_$TS.tgz" "$ROOT_DIR/results" >/dev/null 2>&1 || true
  rm -rf "$ROOT_DIR/results"
fi

echo "Cleanup complete"
