#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <apk-path> [extra pipeline.py args...]" >&2
  echo "Example: $0 ./research-app.apk --label research:benign" >&2
  exit 2
fi

APK_PATH="$1"
shift || true

if [[ ! -f "$APK_PATH" ]]; then
  echo "APK not found: $APK_PATH" >&2
  exit 2
fi

# Prefer project venv when present
if [[ -x "$ROOT_DIR/venv/bin/python" ]]; then
  PYTHON="$ROOT_DIR/venv/bin/python"
else
  PYTHON="${PYTHON:-python3}"
fi

export PYTHONPATH="$ROOT_DIR${PYTHONPATH:+:$PYTHONPATH}"
export GMTOOL="${GMTOOL:-$HOME/Documents/Tools/genymotion/gmtool}"
export GENYMOTION_HOME="${GENYMOTION_HOME:-$HOME/Documents/Tools/genymotion}"

# Ensure gmtool is on PATH for child tools
if [[ -d "$GENYMOTION_HOME" ]]; then
  export PATH="$GENYMOTION_HOME:$PATH"
fi

exec "$PYTHON" "$ROOT_DIR/pipeline.py" "$APK_PATH" "$@"
