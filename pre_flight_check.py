#!/usr/bin/env python3
"""Environment preflight for android-instrumentor (Genymotion-first)."""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

from common_config import load_config

REQUIRED_PYTHON_PACKAGES = [
    ("flask", "flask"),
    ("numpy", "numpy"),
    ("pandas", "pandas"),
    ("sklearn", "scikit-learn"),
    ("yaml", "pyyaml"),
]


def run_command(cmd, timeout=20):
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return {
            "ok": result.returncode == 0,
            "stdout": (result.stdout or "").strip(),
            "stderr": (result.stderr or "").strip(),
            "returncode": result.returncode,
        }
    except FileNotFoundError:
        return {"ok": False, "stdout": "", "stderr": "not found", "returncode": 127}
    except subprocess.TimeoutExpired:
        return {"ok": False, "stdout": "", "stderr": "timed out", "returncode": 124}


def check_package(module: str) -> bool:
    try:
        __import__(module)
        return True
    except Exception:
        return False


def resolve_gmtool(cfg: dict) -> str | None:
    candidates = [
        os.environ.get("GMTOOL"),
        os.path.expanduser(str(cfg.get("paths", {}).get("gmtool", ""))),
        os.path.join(os.path.expanduser(str(cfg.get("paths", {}).get("genymotion", ""))), "gmtool"),
        os.path.expanduser("~/Documents/Tools/genymotion/gmtool"),
        "/opt/genymotion/gmtool",
        shutil.which("gmtool"),
    ]
    for c in candidates:
        if c and os.path.isfile(c) and os.access(c, os.X_OK):
            return c
    return None


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--config", default=None)
    args = parser.parse_args()

    cfg = load_config(args.config)
    report: dict = {}

    apktool = shutil.which(str(cfg.get("paths", {}).get("apktool", "apktool"))) or shutil.which("apktool")
    adb = shutil.which(str(cfg.get("paths", {}).get("adb", "adb"))) or shutil.which("adb")
    java = shutil.which("java")
    frida = shutil.which(str(cfg.get("paths", {}).get("frida", "frida"))) or shutil.which("frida")
    emulator = shutil.which("emulator")
    gmtool = resolve_gmtool(cfg)

    checks = []

    def add(name, ok, fix, details=None):
        status = {"ok": bool(ok), "fix": fix, "details": details or {}}
        report[name] = status
        checks.append((name, status))

    if apktool:
        res = run_command([apktool, "--version"])
        add("apktool", res["ok"] or bool(res["stdout"]), "Install apktool", res)
    else:
        add("apktool", False, "Install apktool: sudo apt install apktool")

    if adb:
        res = run_command([adb, "version"])
        add("adb", res["ok"], "Install Android Platform Tools", res)
    else:
        add("adb", False, "Install Android Platform Tools / adb")

    if java:
        res = run_command([java, "-version"])
        # java -version writes to stderr
        ok = res["returncode"] == 0 or "version" in (res["stderr"] + res["stdout"]).lower()
        add("java", ok, "Install OpenJDK 11+", res)
    else:
        add("java", False, "Install OpenJDK 11+")

    res = run_command([sys.executable, "--version"])
    add("python", res["ok"], "Install Python 3.10+", res)

    # Genymotion is primary
    if gmtool:
        res = run_command([gmtool, "admin", "list"], timeout=30)
        # gmtool may return non-zero without license but still list
        out = (res["stdout"] or "") + (res["stderr"] or "")
        ok = ("Name" in out) or ("ADB Serial" in out) or res["ok"] or ("Phone" in out)
        add("genymotion", ok, "Install/start Genymotion and create a VM", {
            **res,
            "gmtool": gmtool,
        })
        report["gmtool_path"] = gmtool
    else:
        add("genymotion", False,
            "Install Genymotion and set paths.gmtool in config.yaml")

    # AVD emulator is optional fallback
    if emulator:
        res = run_command([emulator, "-list-avds"])
        add("emulator", True, "Optional AVD backend available", res)
    else:
        add("emulator", False, "Optional: install Android emulator (Genymotion preferred)")

    if frida:
        res = run_command([frida, "--version"])
        add("frida", res["ok"] or bool(res["stdout"]), "pip install frida-tools", res)
    else:
        add("frida", False, "pip install frida-tools")

    pkg_status = {}
    for module, pip_name in REQUIRED_PYTHON_PACKAGES:
        ok = check_package(module)
        pkg_status[pip_name] = {
            "ok": ok,
            "fix": f"pip install {pip_name}",
            "module": module,
        }
    report["python_packages"] = pkg_status

    # Critical for Genymotion pipeline
    critical = ["apktool", "adb", "java", "python", "genymotion"]
    critical_ok = all(report.get(n, {}).get("ok") for n in critical)
    pkgs_ok = all(v["ok"] for v in pkg_status.values())
    report["summary"] = {
        "critical_ok": critical_ok,
        "packages_ok": pkgs_ok,
        "ready": critical_ok and pkgs_ok,
        "backend": "genymotion" if report.get("genymotion", {}).get("ok") else (
            "avd" if report.get("emulator", {}).get("ok") else "none"
        ),
    }

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        for name, status in checks:
            marker = "PASS" if status["ok"] else "FAIL"
            print(f"[{marker}] {name}: {status['fix']}")
        for pkg, status in pkg_status.items():
            marker = "PASS" if status["ok"] else "FAIL"
            print(f"[{marker}] python package {pkg}: {status['fix']}")
        summary = report["summary"]
        print(f"[{'PASS' if summary['ready'] else 'FAIL'}] pipeline ready "
              f"(backend={summary['backend']})")

    # Exit 0 if critical path OK (packages warned but non-fatal for --json tooling)
    return 0 if critical_ok else 1


if __name__ == "__main__":
    sys.exit(main())
