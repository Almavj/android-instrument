#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

echo "[*] Android Instrumentor setup (Genymotion-first)"

# System packages (best effort)
if command -v apt-get >/dev/null 2>&1; then
  if [[ "${INSTALL_SYSTEM_DEPS:-0}" == "1" ]]; then
    sudo apt-get update
    sudo apt-get install -y openjdk-17-jdk unzip wget curl adb aapt apktool || true
  else
    echo "[*] Skipping apt installs (set INSTALL_SYSTEM_DEPS=1 to enable)"
  fi
fi

# Python venv
if [[ ! -d venv ]]; then
  python3 -m venv venv
fi
# shellcheck disable=SC1091
source venv/bin/activate
python -m pip install --upgrade pip setuptools wheel
python -m pip install -r requirements.txt

# apktool wrapper if missing
if ! command -v apktool >/dev/null 2>&1; then
  mkdir -p "$HOME/.local/bin"
  JAR="$HOME/.local/share/apktool/apktool.jar"
  mkdir -p "$(dirname "$JAR")"
  wget -q -O "$JAR" https://github.com/iBotPeaches/Apktool/releases/download/v2.9.3/apktool_2.9.3.jar
  cat > "$HOME/.local/bin/apktool" <<EOF
#!/bin/sh
exec java -jar "$JAR" "\$@"
EOF
  chmod +x "$HOME/.local/bin/apktool"
  export PATH="$HOME/.local/bin:$PATH"
  echo "[+] Installed apktool wrapper to ~/.local/bin/apktool"
fi

# Genymotion paths
GENY="${GENYMOTION_HOME:-$HOME/Documents/Tools/genymotion}"
if [[ -x "$GENY/gmtool" ]]; then
  echo "[+] Found gmtool: $GENY/gmtool"
  export PATH="$GENY:$PATH"
  export GMTOOL="$GENY/gmtool"
else
  echo "[!] gmtool not found at $GENY/gmtool — update config.yaml paths.gmtool"
fi

# Android SDK env (optional)
if [[ -z "${ANDROID_HOME:-}" ]]; then
  if [[ -d "$HOME/Android/Sdk" ]]; then
    export ANDROID_HOME="$HOME/Android/Sdk"
    export ANDROID_SDK_ROOT="$ANDROID_HOME"
  fi
fi

# Research keystore
if [[ ! -f "$ROOT_DIR/keystore.jks" ]]; then
  keytool -genkeypair -v \
    -keystore "$ROOT_DIR/keystore.jks" \
    -alias android-instrumentor \
    -keyalg RSA -keysize 2048 -validity 10000 \
    -storepass android -keypass android \
    -dname "CN=Research,OU=Lab,O=University" >/dev/null
  echo "[+] Created keystore.jks"
fi

mkdir -p "$ROOT_DIR/logs" "$ROOT_DIR/output/traces" "$ROOT_DIR/models" "$ROOT_DIR/results"

# Write/refresh config defaults for Genymotion if missing fields
if [[ ! -f "$ROOT_DIR/config.yaml" ]]; then
  cp "$ROOT_DIR/config.yaml" "$ROOT_DIR/config.yaml.bak" 2>/dev/null || true
fi

echo
python pre_flight_check.py || true
echo
echo "Setup complete."
echo "  source venv/bin/activate"
echo "  ./run_pipeline.sh ./research-app.apk --label research:benign"
echo "Start your Genymotion VM first, or the pipeline will start 'Genymotion Phone'."
