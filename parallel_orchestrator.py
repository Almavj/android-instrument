#!/usr/bin/env python3
"""Parallel Orchestrator: run multiple emulator analyses concurrently.

Uses asyncio + subprocess to manage N AVD instances, each running
orchestrator.py on isolated ports. Aggregates results into a merged DB.
"""

import argparse
import asyncio
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import time
from dataclasses import dataclass, field
from typing import Optional

try:
    from tqdm import tqdm
    HAS_TQDM = True
except ImportError:
    HAS_TQDM = False


@dataclass
class InstanceConfig:
    instance_id: int
    avd_name: str
    adb_port: int
    console_port: int
    ram: str = "2048"
    apk_path: str = ""
    status: str = "pending"
    output_dir: str = ""
    trace_path: str = ""
    error: str = ""
    start_time: float = 0
    end_time: float = 0

    @property
    def adb_serial(self) -> str:
        return f"emulator-{self.console_port}"


@dataclass
class RunConfig:
    apk_path: str
    num_instances: int = 3
    base_adb_port: int = 5555
    base_console_port: int = 5554
    avd_name: str = "pixel_6_api_30"
    ram: str = "2048"
    step_timeout: int = 60
    output_dir: str = "./output/parallel"
    merged_db: str = "./output/merged_traces.db"


class ParallelOrchestrator:
    def __init__(self, config: RunConfig):
        self.config = config
        self.instances: list[InstanceConfig] = []
        os.makedirs(config.output_dir, exist_ok=True)

    async def run_all(self) -> dict:
        print(f"[*] Parallel Orchestrator")
        print(f"[*] APK: {self.config.apk_path}")
        print(f"[*] Instances: {self.config.num_instances}")
        print(f"[*] AVD: {self.config.avd_name}")
        print()

        self._create_instances()
        self._check_prereqs()

        print(f"[*] Starting {len(self.instances)} parallel analyses...")
        tasks = [self._run_instance(inst) for inst in self.instances]

        if HAS_TQDM:
            with tqdm(total=len(tasks), desc="Analysis", unit="apk") as pbar:
                for coro in asyncio.as_completed(tasks):
                    await coro
                    pbar.update(1)
        else:
            await asyncio.gather(*tasks)

        self._merge_results()
        summary = self._print_summary()
        return summary

    def _create_instances(self):
        for i in range(self.config.num_instances):
            inst = InstanceConfig(
                instance_id=i,
                avd_name=f"{self.config.avd_name}_{i}",
                adb_port=self.config.base_adb_port + i * 2,
                console_port=self.config.base_console_port + i * 2,
                ram=self.config.ram,
                apk_path=self.config.apk_path,
                output_dir=os.path.join(self.config.output_dir, f"instance_{i}"),
            )
            os.makedirs(inst.output_dir, exist_ok=True)
            self.instances.append(inst)

    def _check_prereqs(self):
        adb = shutil.which("adb")
        if not adb:
            print("[!] adb not found")
            sys.exit(1)

        emulator = shutil.which("emulator")
        if not emulator:
            print("[!] emulator not found")
            sys.exit(1)

        sdk = os.environ.get("ANDROID_HOME", "")
        if sdk:
            tools = os.path.join(sdk, "tools", "bin", "avdmanager")
            if os.path.exists(tools):
                result = subprocess.run(
                    [tools, "list", "avd", "-c"],
                    capture_output=True, text=True
                )
                avds = result.stdout.strip().split("\n")
                base_avd = self.config.avd_name.split("_")[0]
                if not any(base_avd in a for a in avds):
                    print(f"[!] AVD '{base_avd}' not found. Available: {avds}")
                    print("[!] Creating AVD...")
                    subprocess.run([
                        tools, "create", "avd",
                        "-n", self.config.avd_name,
                        "-k", "system-images;android-30;google_apis;x86_64",
                        "-d", "pixel_6"
                    ], capture_output=True)

        print("[+] Prerequisites OK")

    async def _run_instance(self, inst: InstanceConfig):
        inst.status = "running"
        inst.start_time = time.time()

        print(f"  [Instance {inst.instance_id}] Starting on port {inst.console_port}")

        try:
            emulator_cmd = await self._start_emulator(inst)
            await self._wait_boot(inst)
            await self._install_apk(inst)
            await self._run_analysis(inst)
            inst.status = "completed"
            print(f"  [Instance {inst.instance_id}] Completed")
        except asyncio.TimeoutError:
            inst.status = "timeout"
            inst.error = "Timed out"
            print(f"  [Instance {inst.instance_id}] Timed out")
        except Exception as e:
            inst.status = "error"
            inst.error = str(e)
            print(f"  [Instance {inst.instance_id}] Error: {e}")
        finally:
            inst.end_time = time.time()
            await self._stop_emulator(inst)

    async def _start_emulator(self, inst: InstanceConfig):
        cmd = [
            "emulator",
            "-avd", inst.avd_name,
            "-memory", inst.ram,
            "-cores", "2",
            "-gpu", "swiftshader_indirect",
            "-no-audio",
            "-no-window",
            "-port", str(inst.console_port),
            "-no-snapshot",
        ]

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )

        inst._emulator_proc = proc
        print(f"  [Instance {inst.instance_id}] Emulator PID: {proc.pid}")
        return proc

    async def _wait_boot(self, inst: InstanceConfig, timeout: int = 180):
        print(f"  [Instance {inst.instance_id}] Waiting for boot...")
        start = time.time()
        while time.time() - start < timeout:
            proc = await asyncio.create_subprocess_exec(
                "adb", "-s", inst.adb_serial, "shell", "getprop", "sys.boot_completed",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            if stdout.decode().strip() == "1":
                print(f"  [Instance {inst.instance_id}] Booted")
                await asyncio.sleep(3)
                return
            await asyncio.sleep(2)
        raise TimeoutError("Emulator boot timed out")

    async def _install_apk(self, inst: InstanceConfig):
        print(f"  [Instance {inst.instance_id}] Installing APK...")
        proc = await asyncio.create_subprocess_exec(
            "adb", "-s", inst.adb_serial, "install", "-r", "-t", inst.apk_path,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await proc.communicate()
        output = stdout.decode()
        if "Success" in output:
            print(f"  [Instance {inst.instance_id}] Installed")
        else:
            print(f"  [Instance {inst.instance_id}] Install: {output.strip()}")

    async def _run_analysis(self, inst: InstanceConfig):
        print(f"  [Instance {inst.instance_id}] Running analysis...")

        package = await self._get_package(inst)
        if package:
            proc = await asyncio.create_subprocess_exec(
                "adb", "-s", inst.adb_serial, "shell",
                "am", "start", "-n", f"{package}/.MainActivity",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await proc.communicate()
            await asyncio.sleep(5)

        commands = [
            ("pm", "list", "permissions", "-g"),
            ("pm", "list", "packages", "-f"),
            ("getprop", "ro.product.model"),
            ("dumpsys", "battery"),
            ("dumpsys", "activity", "services"),
        ]

        for cmd in commands:
            proc = await asyncio.create_subprocess_exec(
                "adb", "-s", inst.adb_serial, "shell", *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await proc.communicate()
            await asyncio.sleep(1)

        await self._collect_logs(inst)

    async def _get_package(self, inst: InstanceConfig) -> Optional[str]:
        proc = await asyncio.create_subprocess_exec(
            "aapt", "dump", "badging", inst.apk_path,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await proc.communicate()
        output = stdout.decode()
        match = __import__("re").search(r"package: name='([^']+)'", output)
        return match.group(1) if match else None

    async def _collect_logs(self, inst: InstanceConfig):
        db_local = os.path.join(inst.output_dir, "instrumentation.db")
        proc = await asyncio.create_subprocess_exec(
            "adb", "-s", inst.adb_serial, "pull",
            "/sdcard/instrumentation.db", db_local,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        await proc.communicate()

        if os.path.exists(db_local):
            inst.trace_path = db_local
            print(f"  [Instance {inst.instance_id}] Log collected")

    async def _stop_emulator(self, inst: InstanceConfig):
        proc = await asyncio.create_subprocess_exec(
            "adb", "-s", inst.adb_serial, "emu", "kill",
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        await proc.communicate()

        if hasattr(inst, "_emulator_proc"):
            try:
                inst._emulator_proc.terminate()
                await asyncio.wait_for(inst._emulator_proc.wait(), timeout=5)
            except (asyncio.TimeoutError, ProcessLookupError):
                inst._emulator_proc.kill()

    def _merge_results(self):
        print("\n[*] Merging results...")
        merged_path = self.config.merged_db

        if os.path.exists(merged_path):
            os.remove(merged_path)

        merged = sqlite3.connect(merged_path)
        merged.execute("""
            CREATE TABLE IF NOT EXISTS merged_api_calls (
                id INTEGER PRIMARY KEY,
                instance_id INTEGER,
                timestamp INTEGER,
                thread_id INTEGER,
                api_name TEXT,
                args TEXT,
                result TEXT
            )
        """)
        merged.execute("""
            CREATE TABLE IF NOT EXISTS merged_network_log (
                id INTEGER PRIMARY KEY,
                instance_id INTEGER,
                timestamp INTEGER,
                thread_id INTEGER,
                url TEXT,
                method TEXT,
                headers TEXT,
                response_code INTEGER
            )
        """)
        merged.execute("""
            CREATE TABLE IF NOT EXISTS merged_file_access (
                id INTEGER PRIMARY KEY,
                instance_id INTEGER,
                timestamp INTEGER,
                thread_id INTEGER,
                path TEXT,
                operation TEXT,
                size INTEGER
            )
        """)

        total_rows = 0
        for inst in self.instances:
            if inst.status != "completed" or not inst.trace_path:
                continue

            try:
                source = sqlite3.connect(inst.trace_path)
                for table, merge_table in [
                    ("api_calls", "merged_api_calls"),
                    ("network_log", "merged_network_log"),
                    ("file_access", "merged_file_access"),
                ]:
                    try:
                        rows = source.execute(f"SELECT * FROM {table}").fetchall()
                        if not rows:
                            continue
                        cols = source.execute(f"PRAGMA table_info({table})").fetchall()
                        col_names = [c[1] for c in cols]
                        merged_cols = ["instance_id"] + col_names
                        placeholders = ", ".join(["?"] * (len(merged_cols)))
                        col_list = ", ".join(merged_cols)
                        for row in rows:
                            merged.execute(
                                f"INSERT INTO {merge_table} ({col_list}) VALUES ({placeholders})",
                                (inst.instance_id, *row)
                            )
                            total_rows += 1
                    except sqlite3.OperationalError:
                        pass
                source.close()
            except Exception as e:
                print(f"  [!] Error merging instance {inst.instance_id}: {e}")

        merged.commit()
        merged.close()
        print(f"  Merged {total_rows} rows into {merged_path}")

    def _print_summary(self) -> dict:
        completed = sum(1 for i in self.instances if i.status == "completed")
        failed = sum(1 for i in self.instances if i.status != "completed")

        print(f"\n{'='*60}")
        print(f"  PARALLEL ANALYSIS COMPLETE")
        print(f"  Total instances: {len(self.instances)}")
        print(f"  Completed: {completed}")
        print(f"  Failed: {failed}")
        print(f"  Merged DB: {self.config.merged_db}")
        print(f"{'='*60}")

        for inst in self.instances:
            duration = inst.end_time - inst.start_time
            print(f"  Instance {inst.instance_id}: {inst.status} ({duration:.1f}s)"
                  f"{' - ' + inst.error if inst.error else ''}")

        return {
            "total": len(self.instances),
            "completed": completed,
            "failed": failed,
            "merged_db": self.config.merged_db,
        }


async def run_async(config: RunConfig):
    orchestrator = ParallelOrchestrator(config)
    return await orchestrator.run_all()


def main():
    parser = argparse.ArgumentParser(
        description="Parallel Android Emulator Orchestrator"
    )
    parser.add_argument("apk", help="Path to APK to analyze")
    parser.add_argument("-n", "--instances", type=int, default=3,
                        help="Number of parallel instances")
    parser.add_argument("--avd", default="pixel_6_api_30",
                        help="Base AVD name")
    parser.add_argument("--ram", default="2048", help="RAM per instance (MB)")
    parser.add_argument("--timeout", type=int, default=300,
                        help="Per-instance timeout")
    parser.add_argument("--output", default="./output/parallel",
                        help="Output directory")
    parser.add_argument("--merged-db", default="./output/merged_traces.db",
                        help="Merged database path")
    args = parser.parse_args()

    config = RunConfig(
        apk_path=os.path.abspath(args.apk),
        num_instances=args.instances,
        avd_name=args.avd,
        ram=args.ram,
        step_timeout=args.timeout,
        output_dir=args.output,
        merged_db=args.merged_db,
    )

    summary = asyncio.run(run_async(config))
    print(f"\n[+] Done. Merged DB: {summary['merged_db']}")


if __name__ == "__main__":
    main()
