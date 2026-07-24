#!/usr/bin/env python3
"""Sandbox Orchestrator: Genymotion-first analysis with Frida capture.

Launches instrumented APKs in Genymotion (preferred) or AVD, exercises the app,
captures Frida behavioral events, pulls telemetry, and writes analysis traces.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from common_config import ROOT, ensure_dirs, file_sha256, load_config

try:
    from frida_to_db import convert as frida_log_to_db
except Exception:  # pragma: no cover
    frida_log_to_db = None


GENYMOTION_PATHS = [
    os.path.expanduser("~/Documents/Tools/genymotion"),
    "/opt/genymotion",
    os.path.expanduser("~/genymotion"),
    "/usr/bin/genymotion",
]

GMTOOL_PATHS = [
    os.path.expanduser("~/Documents/Tools/genymotion/gmtool"),
    "/opt/genymotion/gmtool",
    os.path.expanduser("~/genymotion/gmtool"),
    "/usr/bin/gmtool",
]


@dataclass
class EmulatorConfig:
    backend: str = "genymotion"  # genymotion | avd | auto
    avd_name: str = "pixel_6_api_30"
    vm_name: str = "Genymotion Phone"
    ram: str = "2048"
    cores: int = 2
    gpu: str = "swiftshader_indirect"
    no_window: bool = True
    port: int = 5554
    genymotion_path: str = ""
    gmtool_path: str = ""
    serial: str = ""
    adb_path: str = "adb"


@dataclass
class Command:
    name: str
    action: str
    args: dict = field(default_factory=dict)
    delay_after: float = 1.5


SIMULATED_C2_COMMANDS = [
    Command("enumerate_permissions", "shell", {"cmd": "pm list permissions -g"}),
    Command("list_installed_packages", "shell", {"cmd": "pm list packages -f"}),
    Command("get_device_info", "shell", {"cmd": "getprop ro.product.model"}),
    Command("get_contacts", "shell", {"cmd": "content query --uri content://com.android.contacts/contacts"}),
    Command("get_sms", "shell", {"cmd": "content query --uri content://sms"}),
    Command("get_call_log", "shell", {"cmd": "content query --uri content://call_log/calls"}),
    Command("get_location_providers", "shell", {"cmd": "settings list secure"}),
    Command("list_files_external", "shell", {"cmd": "ls -la /sdcard/"}),
    Command("get_running_services", "shell", {"cmd": "dumpsys activity services"}),
    Command("get_network_info", "shell", {"cmd": "dumpsys connectivity"}),
    Command("get_battery_info", "shell", {"cmd": "dumpsys battery"}),
    Command("get_wifi_info", "shell", {"cmd": "dumpsys wifi"}),
    Command("get_accounts", "shell", {"cmd": "dumpsys account"}),
    Command("list_filesystem", "shell", {"cmd": "ls -la /data/data/"}),
    Command("get_clipboard", "shell", {"cmd": "service call clipboard 1"}),
    Command("get_display_info", "shell", {"cmd": "dumpsys display | head -20"}),
]


class Orchestrator:
    def __init__(self, config: EmulatorConfig = None, adb_path: str = "adb",
                 app_config: dict | None = None):
        self.app_config = app_config or load_config()
        self.config = config or self._config_from_yaml(self.app_config)
        self.adb = adb_path or self.app_config.get("paths", {}).get("adb", "adb")
        self.emulator_proc = None
        self.adb_serial_id = self.config.serial or f"emulator-{self.config.port}"
        self.output_dir = str(ROOT / "output" / "traces")
        os.makedirs(self.output_dir, exist_ok=True)
        self.gmtool = None
        self.genymotion_bin = None
        self.frida_proc = None
        self.package_name: Optional[str] = None

        if self.config.backend == "auto":
            self.config.backend = self._detect_backend()
            print(f"[*] Detected backend: {self.config.backend}")

        if self.config.backend == "genymotion":
            self._init_genymotion()

    @staticmethod
    def _config_from_yaml(cfg: dict) -> EmulatorConfig:
        emu = cfg.get("emulator", {})
        paths = cfg.get("paths", {})
        return EmulatorConfig(
            backend=str(emu.get("backend", "genymotion")),
            avd_name=str(emu.get("avd_name", "pixel_6_api_30")),
            vm_name=str(emu.get("vm_name", "Genymotion Phone")),
            ram=str(emu.get("ram", 2048)),
            cores=int(emu.get("cores", 2)),
            no_window=bool(emu.get("no_window", True)),
            port=int(emu.get("port", 5554)),
            genymotion_path=os.path.expanduser(str(paths.get("genymotion", ""))),
            gmtool_path=os.path.expanduser(str(paths.get("gmtool", ""))),
            serial=str(emu.get("serial") or ""),
            adb_path=str(paths.get("adb", "adb")),
        )

    def _detect_backend(self) -> str:
        if self._find_gmtool():
            return "genymotion"
        if shutil.which("emulator"):
            return "avd"
        print("[!] No emulator backend found. Install Genymotion or Android SDK.")
        return "genymotion"

    def _find_genymotion(self) -> Optional[str]:
        if self.config.genymotion_path:
            p = os.path.expanduser(self.config.genymotion_path)
            if os.path.isfile(p):
                return p
            for binary in ("genymotion", "genymotion-player"):
                full = os.path.join(p, binary)
                if os.path.isfile(full):
                    return full
        for path in GENYMOTION_PATHS:
            if os.path.isfile(path):
                return path
            for binary in ("genymotion", "genymotion-player"):
                full = os.path.join(path, binary)
                if os.path.isfile(full):
                    return full
        return shutil.which("genymotion")

    def _find_gmtool(self) -> Optional[str]:
        candidates = []
        if self.config.gmtool_path:
            candidates.append(os.path.expanduser(self.config.gmtool_path))
        if self.config.genymotion_path:
            candidates.append(
                os.path.join(os.path.expanduser(self.config.genymotion_path), "gmtool")
            )
        candidates.extend(GMTOOL_PATHS)
        which = shutil.which("gmtool")
        if which:
            candidates.append(which)
        for path in candidates:
            if path and os.path.isfile(path) and os.access(path, os.X_OK):
                return path
        return None

    def _init_genymotion(self):
        self.gmtool = self._find_gmtool()
        if not self.gmtool:
            raise RuntimeError(
                "gmtool not found. Set paths.gmtool in config.yaml "
                "(expected ~/Documents/Tools/genymotion/gmtool)"
            )
        self.genymotion_bin = self._find_genymotion()
        print(f"[*] Genymotion: {self.genymotion_bin or 'N/A'}")
        print(f"[*] gmtool: {self.gmtool}")

        if not self.config.vm_name:
            self.config.vm_name = self._list_genymotion_vms()
        if self.config.serial:
            self.adb_serial_id = self.config.serial
        else:
            self.adb_serial_id = self._resolve_genymotion_serial()
        print(f"[*] ADB serial: {self.adb_serial_id}")

    def _gmtool(self, *args, timeout: int = 60) -> subprocess.CompletedProcess:
        cmd = [self.gmtool, *args]
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)

    def _list_genymotion_vms(self) -> str:
        result = self._gmtool("admin", "list", timeout=30)
        lines = (result.stdout or "").strip().splitlines()
        vm_names = []
        for line in lines:
            line = line.strip()
            if not line or "State" in line or "----" in line or "ADB Serial" in line:
                continue
            parts = [p.strip() for p in line.split("|") if p.strip()]
            if len(parts) >= 4:
                state = parts[0].lower()
                if state in ("on", "off"):
                    vm_names.append(parts[3])
        if not vm_names:
            raise RuntimeError("No Genymotion VMs found. Create one in Genymotion UI.")
        print("[*] Available VMs:")
        for i, name in enumerate(vm_names):
            print(f"    {i + 1}. {name}")
        selected = vm_names[0]
        print(f"[*] Using VM: {selected}")
        return selected

    def _resolve_genymotion_serial(self) -> str:
        # Prefer JSON listing when available
        result = self._gmtool("--format", "json", "admin", "list", timeout=15)
        try:
            data = json.loads(result.stdout or "{}")
            instances = data.get("instances") or data.get("devices") or []
            if isinstance(data, list):
                instances = data
            for inst in instances:
                name = inst.get("name") or inst.get("Name")
                if name and self.config.vm_name and name != self.config.vm_name:
                    continue
                serial = inst.get("adb_serial") or inst.get("serial") or inst.get("ADB Serial")
                if serial:
                    return str(serial).strip()
        except (json.JSONDecodeError, TypeError, AttributeError):
            pass

        # Table parse
        result = self._gmtool("admin", "list", timeout=15)
        for line in (result.stdout or "").splitlines():
            if self.config.vm_name and self.config.vm_name not in line:
                continue
            parts = [p.strip() for p in line.split("|")]
            for part in parts:
                if re.match(r"^\d+\.\d+\.\d+\.\d+:\d+$", part):
                    return part
                if re.match(r"^emulator-\d+$", part):
                    return part

        # Fallback common Genymotion ports
        for serial in ("127.0.0.1:6555", "127.0.0.1:6554", "127.0.0.1:5555"):
            check = subprocess.run(
                [self.adb, "-s", serial, "get-state"],
                capture_output=True, text=True, timeout=5,
            )
            if "device" in (check.stdout or ""):
                return serial

        # Any connected device
        result = subprocess.run(
            [self.adb, "devices"], capture_output=True, text=True, timeout=10
        )
        for line in (result.stdout or "").splitlines():
            if "\tdevice" in line:
                return line.split()[0]
        return "127.0.0.1:6554"

    def run_analysis(self, apk_path: str,
                     commands: list[Command] = None,
                     timeout: int = 300) -> dict:
        if commands is None:
            commands = SIMULATED_C2_COMMANDS

        analysis_cfg = self.app_config.get("analysis", {})
        frida_enabled = bool(analysis_cfg.get("frida_enabled", True))
        frida_duration = int(analysis_cfg.get("frida_duration", 45))
        monkey_events = int(analysis_cfg.get("monkey_events", 50))

        apk_path = os.path.abspath(apk_path)
        trace = {
            "apk": apk_path,
            "apk_sha256": self._sha256(apk_path),
            "backend": self.config.backend,
            "vm_name": self.config.vm_name,
            "serial": self.adb_serial_id,
            "start_time": time.time(),
            "commands": [],
            "errors": [],
            "frida": {},
        }

        print(f"[*] Starting analysis of {apk_path}")
        print(f"[*] Backend={self.config.backend} serial={self.adb_serial_id}")

        try:
            self._start_emulator()
            self._wait_for_boot(timeout=min(timeout, 180))
            self._prepare_device()
            self._install_apk(apk_path)
            self.package_name = self._get_package_name(apk_path)
            trace["package"] = self.package_name
            if self.package_name and analysis_cfg.get("grant_permissions", True):
                self._grant_permissions(self.package_name)

            # Clear old frida logs on device
            self._adb_cmd("shell rm -f /data/local/tmp/frida_events.jsonl /data/local/tmp/frida.log")
            self._adb_cmd("shell rm -f /sdcard/frida_events.jsonl /sdcard/frida.log")

            launchable = self._get_launchable_activity(apk_path)
            if frida_enabled and self.package_name:
                self._start_frida(self.package_name, spawn=True)
                time.sleep(3)
            else:
                self._launch_app(apk_path, launchable)
                time.sleep(3)

            # If Frida spawn didn't bring UI up, force start
            if self.package_name:
                self._launch_app(apk_path, launchable)
                time.sleep(2)

            print(f"[*] Sending {len(commands)} simulated analysis commands...")
            for i, cmd in enumerate(commands):
                print(f"  [{i + 1}/{len(commands)}] {cmd.name}")
                result = self._send_command(cmd)
                trace["commands"].append({
                    "name": cmd.name,
                    "action": cmd.action,
                    "args": cmd.args,
                    "result": result,
                    "timestamp": time.time(),
                })
                time.sleep(cmd.delay_after)

            if monkey_events > 0 and self.package_name:
                print(f"[*] Running monkey ({monkey_events} events)...")
                monkey_out = self._adb_cmd(
                    f"shell monkey -p {self.package_name} "
                    f"--throttle 200 --ignore-crashes --ignore-timeouts "
                    f"--ignore-security-exceptions -v {monkey_events}"
                )
                trace["monkey"] = monkey_out[:3000]

            # Keep Frida attached during exercise window
            if frida_enabled and self.frida_proc:
                print(f"[*] Collecting Frida events for {frida_duration}s...")
                time.sleep(max(5, frida_duration))
                self._stop_frida()

            print("[*] Collecting logs from device...")
            trace["device_logs"] = self._collect_logs(self.package_name)
            trace["logcat"] = self._collect_logcat()
            frida_meta = self._collect_frida_logs()
            trace["frida"] = frida_meta
            trace["sqlite_dump"] = self._dump_instrumentation_db()

            # If no smali DB but Frida log exists, convert
            db_local = os.path.join(self.output_dir, "instrumentation.db")
            frida_jsonl = frida_meta.get("local_jsonl")
            if (not os.path.exists(db_local) or os.path.getsize(db_local) == 0) and frida_jsonl:
                if frida_log_to_db and os.path.isfile(frida_jsonl):
                    counts = frida_log_to_db(frida_jsonl, db_local)
                    trace["frida_db_counts"] = counts
                    print(f"[+] Built instrumentation.db from Frida log: {counts}")
                    trace["sqlite_dump"] = self._dump_instrumentation_db()

        except Exception as e:
            trace["errors"].append(str(e))
            print(f"[!] Error: {e}")
        finally:
            self._stop_frida()
            trace["end_time"] = time.time()
            trace["duration"] = trace["end_time"] - trace["start_time"]
            trace["serial"] = self.adb_serial_id
            self._save_trace(trace)
            # Do not force-stop Genymotion by default — faster re-runs
            if os.environ.get("STOP_EMULATOR", "").lower() in {"1", "true", "yes"}:
                self._stop_emulator()

        return trace

    def _sha256(self, path: str) -> str:
        try:
            return file_sha256(path)
        except Exception:
            return ""

    def _start_emulator(self):
        if self.config.serial:
            print(f"[*] Using physical device/serial: {self.config.serial}")
            self.adb_serial_id = self.config.serial
            return
        if self.config.backend == "genymotion":
            self._start_genymotion()
        else:
            self._start_avd()

    def _start_avd(self):
        print(f"[*] Starting AVD: {self.config.avd_name}")
        cmd = [
            "emulator",
            "-avd", self.config.avd_name,
            "-memory", str(self.config.ram),
            "-cores", str(self.config.cores),
            "-gpu", self.config.gpu,
            "-no-audio",
            "-port", str(self.config.port),
        ]
        if self.config.no_window:
            cmd.append("-no-window")
        self.emulator_proc = subprocess.Popen(
            cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        self.adb_serial_id = f"emulator-{self.config.port}"
        print(f"    Emulator PID: {self.emulator_proc.pid}")

    def _start_genymotion(self):
        print(f"[*] Starting Genymotion VM: {self.config.vm_name}")
        # Already running?
        state = self._gmtool("admin", "list", timeout=20)
        if self.config.vm_name in (state.stdout or "") and re.search(
            rf"^\s*On\s*\|.*{re.escape(self.config.vm_name)}",
            state.stdout or "",
            re.MULTILINE,
        ):
            print("    VM already running")
        else:
            result = self._gmtool("admin", "start", self.config.vm_name, timeout=120)
            output = ((result.stdout or "") + (result.stderr or "")).lower()
            if result.returncode == 0 or "already" in output:
                print("    VM start issued")
            else:
                print(f"    Warning: {(result.stdout or '')} {(result.stderr or '')}")

        # Refresh serial after start
        time.sleep(3)
        self.adb_serial_id = self._resolve_genymotion_serial()
        print(f"[*] ADB serial after start: {self.adb_serial_id}")
        # Ensure adb can see it
        subprocess.run([self.adb, "connect", self.adb_serial_id],
                       capture_output=True, text=True, timeout=15)
        subprocess.run([self.adb, "start-server"], capture_output=True, text=True, timeout=15)

    def _wait_for_boot(self, timeout: int = 180, retries: int = 6):
        print("[*] Waiting for device to boot...")
        start = time.time()
        attempts = 0
        while time.time() - start < timeout:
            attempts += 1
            try:
                # reconnect periodically for Genymotion
                if ":" in self.adb_serial_id:
                    subprocess.run(
                        [self.adb, "connect", self.adb_serial_id],
                        capture_output=True, text=True, timeout=10,
                    )
                result = self._adb_cmd("shell getprop sys.boot_completed")
                if result.strip().splitlines()[-1:] == ["1"] or result.strip() == "1":
                    print("[+] Device booted")
                    time.sleep(2)
                    return
            except Exception:
                pass
            if attempts % retries == 0:
                print("[!] Boot wait retry; restarting adb server")
                subprocess.run([self.adb, "kill-server"], capture_output=True)
                subprocess.run([self.adb, "start-server"], capture_output=True)
                if ":" in self.adb_serial_id:
                    subprocess.run(
                        [self.adb, "connect", self.adb_serial_id],
                        capture_output=True, text=True, timeout=10,
                    )
            time.sleep(2)
        raise RuntimeError(f"Device boot timed out (serial={self.adb_serial_id})")

    def _prepare_device(self):
        # Prefer writable /data/local/tmp for Frida logs
        self._adb_cmd("shell mkdir -p /data/local/tmp")
        self._adb_cmd("shell chmod 777 /data/local/tmp")
        # Disable package verifier for research installs
        self._adb_cmd("shell settings put global package_verifier_enable 0")
        self._adb_cmd("shell settings put global verifier_verify_adb_installs 0")

    def _install_apk(self, apk_path: str):
        print(f"[*] Installing {os.path.basename(apk_path)}...")

        # Get package name for targeted uninstall if needed
        pkg = self._get_package_name(apk_path)

        # Strategy 1: direct adb install (most reliable, skip incremental)
        result = self._adb_cmd(f"install -r -t -d --no-incremental '{apk_path}'")
        if "Success" in result:
            print("    Installed successfully (adb install)")
            return

        # If signature mismatch, uninstall old version first
        if pkg and ("INCOMPATIBLE" in result or "INSTALL_FAILED" in result):
            print(f"    Signature mismatch, uninstalling old {pkg} first...")
            self._adb_cmd(f"shell pm uninstall '{pkg}'")
            result = self._adb_cmd(f"install -r -t -d --no-incremental '{apk_path}'")
            if "Success" in result:
                print("    Installed successfully (uninstall + reinstall)")
                return

        # Strategy 2: push + pm install (bypasses streaming issues)
        remote = "/data/local/tmp/target.apk"
        push = self._adb_cmd(f"push '{apk_path}' '{remote}'")
        result = self._adb_cmd(f"shell pm install -r -t -d '{remote}'")
        if "Success" in result:
            print("    Installed successfully (pm install)")
            return

        # Strategy 3: push + pm install with content URI (handles session issues)
        result = self._adb_cmd(
            f"shell pm install -r -t --install-location 0 '{remote}'"
        )
        if "Success" in result:
            print("    Installed successfully (pm install alt)")
            return

        print(f"    Install result: {(push + result).strip()[:500]}")
        raise RuntimeError(f"APK install failed: {result.strip()[:300]}")

    def _grant_permissions(self, package_name: str):
        print(f"[*] Pre-granting permissions for {package_name}...")
        dangerous_permissions = [
            "android.permission.READ_CONTACTS",
            "android.permission.READ_SMS",
            "android.permission.READ_CALL_LOG",
            "android.permission.CAMERA",
            "android.permission.RECORD_AUDIO",
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.ACCESS_COARSE_LOCATION",
            "android.permission.READ_PHONE_STATE",
            "android.permission.READ_EXTERNAL_STORAGE",
            "android.permission.WRITE_EXTERNAL_STORAGE",
            "android.permission.POST_NOTIFICATIONS",
            "android.permission.INTERNET",
            "android.permission.ACCESS_NETWORK_STATE",
        ]
        granted = 0
        for perm in dangerous_permissions:
            result = self._adb_cmd(f"shell pm grant {package_name} {perm}")
            if "Exception" not in result and "Error" not in result:
                granted += 1
        print(f"    Granted/attempted {granted}/{len(dangerous_permissions)} permissions")

    def _get_launchable_activity(self, apk_path: str) -> Optional[str]:
        for tool in ("aapt", "aapt2"):
            bin_path = shutil.which(tool)
            if not bin_path:
                # try SDK build-tools
                sdk = self.app_config.get("paths", {}).get("android_sdk") or os.environ.get("ANDROID_HOME", "")
                if sdk:
                    bt = os.path.join(os.path.expanduser(str(sdk)), "build-tools")
                    if os.path.isdir(bt):
                        for ver in sorted(os.listdir(bt), reverse=True):
                            candidate = os.path.join(bt, ver, tool)
                            if os.path.isfile(candidate):
                                bin_path = candidate
                                break
            if not bin_path:
                continue
            result = subprocess.run(
                [bin_path, "dump", "badging", apk_path],
                capture_output=True, text=True, timeout=30,
            )
            m = re.search(r"launchable-activity: name='([^']+)'", result.stdout or "")
            if m:
                return m.group(1)
        return None

    def _launch_app(self, apk_path: str, launchable: Optional[str] = None):
        package = self.package_name or self._get_package_name(apk_path)
        if not package:
            print("[!] Could not determine package name")
            return
        activity = launchable or self._get_launchable_activity(apk_path)
        print(f"[*] Launching {package} ({activity or 'monkey/default'})...")
        if activity:
            if activity.startswith("."):
                component = f"{package}/{package}{activity}"
            elif "/" in activity:
                component = activity
            else:
                component = f"{package}/{activity}"
            out = self._adb_cmd(f"shell am start -n {component}")
            if "Error" in out or "Exception" in out:
                self._adb_cmd(f"shell monkey -p {package} -c android.intent.category.LAUNCHER 1")
        else:
            self._adb_cmd(f"shell monkey -p {package} -c android.intent.category.LAUNCHER 1")

    def _get_package_name(self, apk_path: str) -> Optional[str]:
        for tool in ("aapt", "aapt2"):
            bin_path = shutil.which(tool)
            if not bin_path:
                continue
            result = subprocess.run(
                [bin_path, "dump", "badging", apk_path],
                capture_output=True, text=True, timeout=30,
            )
            m = re.search(r"package: name='([^']+)'", result.stdout or "")
            if m:
                return m.group(1)
        # fallback: apktool yml from prior decompile not available; try apkanalyzer-less parse
        result = subprocess.run(
            f"aapt dump badging '{apk_path}' 2>/dev/null | head -1",
            shell=True, capture_output=True, text=True,
        )
        m = re.search(r"name='([^']+)'", result.stdout or "")
        return m.group(1) if m else None

    def _start_frida(self, package: str, spawn: bool = True):
        frida_bin = (
            self.app_config.get("paths", {}).get("frida")
            or shutil.which("frida")
            or "frida"
        )
        script = self.app_config.get("analysis", {}).get("frida_script", "frida_hooks.js")
        script_path = script if os.path.isabs(script) else str(ROOT / script)
        if not os.path.isfile(script_path):
            print(f"[!] Frida script missing: {script_path}")
            return

        # Ensure frida-server if present on device (optional)
        self._ensure_frida_server()

        cmd = [frida_bin]
        if self.adb_serial_id:
            cmd.extend(["-D", self.adb_serial_id])
        else:
            cmd.append("-U")
        if spawn:
            cmd.extend(["-f", package])
        else:
            cmd.extend(["-n", package])
        cmd.extend(["-l", script_path, "--runtime=v8"])
        # frida 17 uses different no-pause flags; try modern form
        env = os.environ.copy()
        print(f"[*] Starting Frida: {' '.join(cmd)}")
        log_path = os.path.join(self.output_dir, "frida_console.log")
        log_fh = open(log_path, "w", encoding="utf-8")
        try:
            self.frida_proc = subprocess.Popen(
                cmd, stdout=log_fh, stderr=subprocess.STDOUT, env=env
            )
            self._frida_log_fh = log_fh
            print(f"    Frida PID: {self.frida_proc.pid}")
        except FileNotFoundError:
            log_fh.close()
            print("[!] frida CLI not found. Install: pip install frida-tools")
            self.frida_proc = None

    def _ensure_frida_server(self):
        check = self._adb_cmd("shell ps -A | grep frida-server")
        if "frida-server" in check:
            return
        for path in ("/data/local/tmp/frida-server", "/data/local/tmp/fs"):
            exists = self._adb_cmd(f"shell ls {path}")
            if "No such" in exists:
                continue
            self._adb_cmd(f"shell chmod 755 {path}")
            # Use nohup + redirect to avoid blocking adb shell session
            self._adb_cmd(f'shell "nohup {path} -D > /dev/null 2>&1 &"')
            time.sleep(2)
            # Verify it started
            check = self._adb_cmd("shell ps -A | grep frida")
            if "frida" in check:
                print(f"[*] Started frida-server from {path}")
                return
        print("[!] frida-server not found on device (Frida CLI may still work via spawn)")

    def _stop_frida(self):
        if self.frida_proc and self.frida_proc.poll() is None:
            try:
                self.frida_proc.terminate()
                self.frida_proc.wait(timeout=5)
            except Exception:
                try:
                    self.frida_proc.kill()
                except Exception:
                    pass
        self.frida_proc = None
        fh = getattr(self, "_frida_log_fh", None)
        if fh:
            try:
                fh.close()
            except Exception:
                pass
            self._frida_log_fh = None

    def _collect_frida_logs(self) -> dict:
        meta = {"local_jsonl": "", "local_log": "", "console_log": os.path.join(self.output_dir, "frida_console.log")}
        pairs = [
            ("/data/local/tmp/frida_events.jsonl", "frida_events.jsonl"),
            ("/data/local/tmp/frida.log", "frida.log"),
            ("/sdcard/frida_events.jsonl", "frida_events_sdcard.jsonl"),
            ("/sdcard/frida.log", "frida_sdcard.log"),
        ]
        for remote, local_name in pairs:
            local = os.path.join(self.output_dir, local_name)
            out = self._adb_cmd(f"pull '{remote}' '{local}'")
            if os.path.isfile(local) and os.path.getsize(local) > 0:
                print(f"    Pulled Frida log: {remote} -> {local}")
                if local_name.endswith(".jsonl") and not meta["local_jsonl"]:
                    meta["local_jsonl"] = local
                if local_name.endswith(".log") and "console" not in local_name and not meta["local_log"]:
                    meta["local_log"] = local
            else:
                if os.path.isfile(local) and os.path.getsize(local) == 0:
                    os.remove(local)
        # Fallback: parse console log if device pull failed
        if not meta["local_jsonl"] and os.path.isfile(meta["console_log"]):
            # Extract JSON lines from console
            extracted = os.path.join(self.output_dir, "frida_events_from_console.jsonl")
            count = 0
            with open(meta["console_log"], encoding="utf-8", errors="replace") as src, \
                    open(extracted, "w", encoding="utf-8") as dst:
                for line in src:
                    line = line.strip()
                    if line.startswith("{") and '"event"' in line:
                        dst.write(line + "\n")
                        count += 1
            if count:
                meta["local_jsonl"] = extracted
                print(f"    Extracted {count} Frida events from console log")
        return meta

    def _send_command(self, cmd: Command) -> dict:
        result = {"success": False, "output": ""}
        try:
            if cmd.action == "shell":
                output = self._adb_cmd(f"shell {cmd.args['cmd']}")
                result["output"] = output[:5000]
                result["success"] = True
            elif cmd.action == "broadcast":
                intent = cmd.args.get("intent", "")
                output = self._adb_cmd(f"shell am broadcast -a {intent}")
                result["output"] = output
                result["success"] = True
        except Exception as e:
            result["error"] = str(e)
        return result

    def _collect_logs(self, package_name: str = None) -> str:
        log_files = []
        remote_paths = [
            "/sdcard/Android/data/com.instrument.hooks/files/instrumentation.db",
            "/sdcard/instrumentation.db",
        ]
        if package_name:
            remote_paths.extend([
                f"/sdcard/Android/data/{package_name}/files/instrumentation.db",
                f"/data/data/{package_name}/databases/instrumentation.db",
                f"/data/data/{package_name}/files/instrumentation.db",
            ])

        for remote_path in remote_paths:
            local_path = os.path.join(self.output_dir, "instrumentation.db")
            result = self._adb_cmd(f"pull '{remote_path}' '{local_path}'")
            if os.path.exists(local_path) and os.path.getsize(local_path) > 0:
                log_files.append(local_path)
                print(f"    Pulled: {remote_path}")
                break
            # clean failed empty pulls
            if os.path.exists(local_path) and os.path.getsize(local_path) == 0:
                os.remove(local_path)

        all_logs = ""
        for lf in log_files:
            try:
                import sqlite3
                conn = sqlite3.connect(lf)
                cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
                tables = [row[0] for row in cursor.fetchall()]
                all_logs += f"=== {lf} ===\nTables: {tables}\n"
                for table in tables:
                    try:
                        cursor = conn.execute(f"SELECT COUNT(*) FROM {table}")
                        count = cursor.fetchone()[0]
                        all_logs += f"  {table}: {count} rows\n"
                    except Exception:
                        pass
                conn.close()
            except Exception:
                all_logs += f"=== {lf} === (binary, {os.path.getsize(lf)} bytes)\n"
        if not all_logs:
            print("    [!] No instrumentation.db found on device (Frida path may still succeed)")
        return all_logs

    def _collect_logcat(self) -> str:
        output = self._adb_cmd(
            "logcat -d -t 500 -s Instrumentation:* ApiCall:* Network:* FileIO:* AndroidRuntime:E"
        )
        log_path = os.path.join(self.output_dir, "logcat.txt")
        with open(log_path, "w", encoding="utf-8", errors="replace") as f:
            f.write(output)
        return output[:10000]

    def _dump_instrumentation_db(self) -> dict:
        db_local = os.path.join(self.output_dir, "instrumentation.db")
        if not os.path.exists(db_local):
            return {}
        try:
            import sqlite3
            conn = sqlite3.connect(db_local)
            result = {}
            for table in ["api_calls", "network_log", "file_access", "sensor_log", "events"]:
                try:
                    cursor = conn.execute(
                        f"SELECT * FROM {table} ORDER BY rowid DESC LIMIT 100"
                    )
                    columns = [d[0] for d in cursor.description] if cursor.description else []
                    rows = [dict(zip(columns, row)) for row in cursor.fetchall()]
                    count_row = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()
                    result[table] = {
                        "columns": columns,
                        "rows": rows,
                        "count": count_row[0] if count_row else len(rows),
                    }
                except Exception:
                    pass
            conn.close()
            return result
        except Exception:
            return {}

    def _adb_cmd(self, cmd: str) -> str:
        # cmd may already include subcommand words; keep shell for quoting convenience
        full_cmd = f"{self.adb} -s {self.adb_serial_id} {cmd}"
        result = subprocess.run(
            full_cmd, shell=True, capture_output=True, text=True, timeout=60
        )
        return (result.stdout or "") + (result.stderr or "")

    def _save_trace(self, trace: dict):
        ts = int(time.time())
        path = os.path.join(self.output_dir, f"trace_{ts}.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(trace, f, indent=2, default=str)
        # stable pointer for pipeline
        latest = os.path.join(self.output_dir, "latest_trace.json")
        with open(latest, "w", encoding="utf-8") as f:
            json.dump(trace, f, indent=2, default=str)
        print(f"[+] Trace saved: {path}")

    def _stop_emulator(self):
        print("[*] Stopping emulator...")
        if self.config.backend == "genymotion" and self.gmtool and self.config.vm_name:
            self._gmtool("admin", "stop", self.config.vm_name, timeout=60)
        elif self.emulator_proc:
            self.emulator_proc.terminate()
            try:
                self.emulator_proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.emulator_proc.kill()
            self._adb_cmd("emu kill")
        print("    Emulator stopped")


def main():
    ensure_dirs()
    app_cfg = load_config()
    emu = app_cfg.get("emulator", {})
    paths = app_cfg.get("paths", {})
    analysis = app_cfg.get("analysis", {})

    parser = argparse.ArgumentParser(
        description="Android Sandbox Orchestrator (Genymotion-first)"
    )
    parser.add_argument("apk", help="Path to instrumented APK")
    parser.add_argument("--backend", choices=["auto", "avd", "genymotion"],
                        default=emu.get("backend", "genymotion"))
    parser.add_argument("--avd", default=emu.get("avd_name", "pixel_6_api_30"))
    parser.add_argument("--vm", default=emu.get("vm_name", "Genymotion Phone"),
                        help="Genymotion VM name")
    parser.add_argument("--ram", default=str(emu.get("ram", 2048)))
    parser.add_argument("--timeout", type=int,
                        default=int(analysis.get("timeout", 300)))
    parser.add_argument("--port", type=int, default=int(emu.get("port", 5554)))
    parser.add_argument("--output", default=str(ROOT / "output" / "traces"))
    parser.add_argument("--genymotion-path",
                        default=os.path.expanduser(str(paths.get("genymotion", ""))))
    parser.add_argument("--gmtool",
                        default=os.path.expanduser(str(paths.get("gmtool", ""))))
    parser.add_argument("--serial", default=str(emu.get("serial") or ""),
                        help="ADB serial (skips VM start if device already up)")
    parser.add_argument("--no-frida", action="store_true")
    parser.add_argument("--stop-emulator", action="store_true",
                        help="Stop Genymotion VM after analysis")
    args = parser.parse_args()

    if args.no_frida:
        app_cfg.setdefault("analysis", {})["frida_enabled"] = False
    if args.stop_emulator:
        os.environ["STOP_EMULATOR"] = "1"

    config = EmulatorConfig(
        backend=args.backend,
        avd_name=args.avd,
        vm_name=args.vm,
        ram=str(args.ram),
        port=args.port,
        genymotion_path=args.genymotion_path,
        gmtool_path=args.gmtool,
        serial=args.serial,
    )
    orchestrator = Orchestrator(config=config, app_config=app_cfg)
    orchestrator.output_dir = args.output
    os.makedirs(args.output, exist_ok=True)

    if not os.path.isfile(args.apk):
        print(f"[!] APK not found: {args.apk}")
        sys.exit(2)

    trace = orchestrator.run_analysis(args.apk, timeout=args.timeout)

    print(f"\n{'=' * 50}")
    print("  Analysis complete")
    print(f"  Duration: {trace.get('duration', 0):.1f}s")
    print(f"  Commands sent: {len(trace.get('commands', []))}")
    print(f"  Errors: {len(trace.get('errors', []))}")
    if trace.get("errors"):
        for err in trace["errors"]:
            print(f"    - {err}")
    print(f"  Output: {args.output}")
    print(f"{'=' * 50}")
    sys.exit(1 if trace.get("errors") else 0)


if __name__ == "__main__":
    main()
