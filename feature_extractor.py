#!/usr/bin/env python3
"""Feature Extraction Pipeline: converts raw behavioral logs into ML-ready features.

Reads the SQLite instrumentation database and JSON traces, extracts
behavioral features, and outputs feature vectors for classification.
"""

import argparse
import json
import os
import re
import sqlite3
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Optional

import numpy as np


PERMISSION_FEATURES = [
    "android.permission.READ_SMS",
    "android.permission.SEND_SMS",
    "android.permission.READ_CONTACTS",
    "android.permission.READ_CALL_LOG",
    "android.permission.CAMERA",
    "android.permission.RECORD_AUDIO",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.READ_PHONE_STATE",
    "android.permission.PROCESS_OUTGOING_CALLS",
    "android.permission.ANSWER_PHONE_CALLS",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.INTERNET",
    "android.permission.ACCESS_NETWORK_STATE",
    "android.permission.WAKE_LOCK",
    "android.permission.FOREGROUND_SERVICE",
    "android.permission.RECEIVE_BOOT_COMPLETED",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.BIND_ACCESSIBILITY_SERVICE",
    "android.permission.PACKAGE_USAGE_STATS",
    "android.permission.INSTALL_PACKAGES",
    "android.permission.DELETE_PACKAGES",
    "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE",
    "android.permission.BIND_DEVICE_ADMIN",
]

SENSITIVE_APIS = [
    "getDeviceId", "getImei", "getLine1Number", "getSubscriberId",
    "getSimSerialNumber", "getAccounts", "getAccountTypes",
    "getContentResolver", "query", "insert", "delete",
    "openConnection", "getInputStream", "getOutputStream",
    "Runtime.exec", "ProcessBuilder.start",
    "LocationManager.getLastKnownLocation",
    "LocationManager.requestLocationUpdates",
    "Camera.open", "MediaRecorder.start",
    "AudioRecord.startRecording",
    "SmsManager.sendTextMessage",
    "TelephonyManager.getCallState",
    "ClipboardManager.getPrimaryClip",
    "PackageManager.getInstalledPackages",
    "File.mkdirs", "File.delete", "FileOutputStream.write",
    "WebView.loadUrl", "WebView.evaluateJavascript",
]

DANGEROUS_API_PATTERNS = [
    r"reflect\..*Method",
    r"getDeclaredMethod",
    r"setAccessible",
    r"Runtime\.getRuntime\(\)\.exec",
    r"ProcessBuilder",
    r"chmod\s+777",
    r"/system/bin",
    r"/data/data",
    r"su\b",
    r"root",
]


@dataclass
class FeatureVector:
    sample_id: str
    features: dict = field(default_factory=dict)
    label: str = "unknown"

    def to_dict(self) -> dict:
        return {
            "sample_id": self.sample_id,
            "label": self.label,
            "features": self.features,
        }

    def to_numpy(self, feature_names: list[str]) -> np.ndarray:
        return np.array([self.features.get(f, 0.0) for f in feature_names])


class FeatureExtractor:
    def __init__(self):
        self.feature_names: list[str] = []

    def extract_from_db(self, db_path: str, sample_id: str = "") -> FeatureVector:
        if not sample_id:
            sample_id = os.path.basename(db_path).replace(".db", "")

        fv = FeatureVector(sample_id=sample_id)

        if not os.path.exists(db_path):
            return fv

        conn = sqlite3.connect(db_path)

        self._extract_api_features(conn, fv)
        self._extract_network_features(conn, fv)
        self._extract_file_features(conn, fv)
        self._extract_sensor_features(conn, fv)
        self._extract_permission_features(conn, fv)
        self._extract_temporal_features(conn, fv)
        self._extract_sequence_features(conn, fv)
        self._extract_event_features(conn, fv)

        conn.close()
        return fv

    def _extract_event_features(self, conn: sqlite3.Connection, fv: FeatureVector):
        """Features from Frida-converted events table (if present)."""
        try:
            rows = conn.execute("SELECT event_type, payload FROM events").fetchall()
        except Exception:
            return
        if not rows:
            return
        fv.features["total_frida_events"] = len(rows)
        types = Counter()
        for event_type, payload in rows:
            types[event_type or "unknown"] += 1
            text = f"{event_type} {payload or ''}".lower()
            if "sms" in text:
                fv.features["frida_sms_events"] = fv.features.get("frida_sms_events", 0) + 1
            if "contact" in text:
                fv.features["frida_contacts_events"] = fv.features.get("frida_contacts_events", 0) + 1
            if "location" in text or "gps" in text:
                fv.features["frida_location_events"] = fv.features.get("frida_location_events", 0) + 1
            if "camera" in text:
                fv.features["frida_camera_events"] = fv.features.get("frida_camera_events", 0) + 1
            if "microphone" in text or "mediarecorder" in text:
                fv.features["frida_mic_events"] = fv.features.get("frida_mic_events", 0) + 1
            if "network" in text or "http" in text or "okhttp" in text:
                fv.features["frida_network_events"] = fv.features.get("frida_network_events", 0) + 1
            if "reflect" in text or "class.forname" in text:
                fv.features["frida_reflection_events"] = fv.features.get("frida_reflection_events", 0) + 1
            if "exec" in text or "runtime" in text:
                fv.features["frida_exec_events"] = fv.features.get("frida_exec_events", 0) + 1
        for name, count in types.items():
            safe = re.sub(r"[^a-zA-Z0-9]", "_", name)[:40]
            fv.features[f"frida_type_{safe}"] = count

    def extract_from_trace(self, trace_path: str) -> FeatureVector:
        with open(trace_path) as f:
            trace = json.load(f)

        sample_id = os.path.basename(trace_path).replace("trace_", "").replace(".json", "")
        fv = FeatureVector(sample_id=sample_id)

        commands = trace.get("commands", [])
        fv.features["num_commands_sent"] = len(commands)
        fv.features["analysis_duration"] = trace.get("duration", 0)

        command_types = Counter()
        for cmd in commands:
            command_types[cmd.get("name", "unknown")] += 1
        for name, count in command_types.items():
            fv.features[f"cmd_{name}"] = count

        device_logs = trace.get("device_logs", "")
        fv.features["device_log_length"] = len(device_logs)

        sqlite_dump = trace.get("sqlite_dump", {})
        for table_name, table_data in sqlite_dump.items():
            fv.features[f"table_{table_name}_count"] = table_data.get("count", 0)

        return fv

    def _extract_api_features(self, conn: sqlite3.Connection, fv: FeatureVector):
        try:
            cursor = conn.execute(
                "SELECT api_name, args, result FROM api_calls"
            )
            rows = cursor.fetchall()
        except Exception:
            return

        fv.features["total_api_calls"] = len(rows)

        api_names = Counter()
        sensitive_count = 0
        reflection_count = 0
        exec_count = 0

        for api_name, args, result in rows:
            api_names[api_name] += 1

            for sensitive in SENSITIVE_APIS:
                if sensitive.lower() in (api_name or "").lower():
                    sensitive_count += 1
                    break

            args_str = (args or "").lower()
            result_str = (result or "").lower()
            combined = f"{args_str} {result_str}"

            for pattern in DANGEROUS_API_PATTERNS:
                if re.search(pattern, combined, re.IGNORECASE):
                    reflection_count += 1
                    break

            if "exec" in (api_name or "").lower() or "process" in (api_name or "").lower():
                exec_count += 1

        fv.features["unique_api_calls"] = len(api_names)
        fv.features["sensitive_api_count"] = sensitive_count
        fv.features["reflection_api_count"] = reflection_count
        fv.features["exec_api_count"] = exec_count

        for api, count in api_names.most_common(30):
            safe_name = re.sub(r"[^a-zA-Z0-9]", "_", api)
            fv.features[f"api_{safe_name}"] = count

    def _extract_network_features(self, conn: sqlite3.Connection, fv: FeatureVector):
        try:
            cursor = conn.execute(
                "SELECT url, method, response_code FROM network_log"
            )
            rows = cursor.fetchall()
        except Exception:
            return

        fv.features["total_network_requests"] = len(rows)

        methods = Counter()
        domains = set()
        response_codes = Counter()
        has_https = 0
        has_http = 0
        has_ip_direct = 0

        for url, method, code in rows:
            methods[method or "unknown"] += 1
            response_codes[str(code)] += 1

            if url:
                if url.startswith("https"):
                    has_https += 1
                elif url.startswith("http"):
                    has_http += 1

                domain_match = re.search(r"https?://([^/]+)", url)
                if domain_match:
                    domain = domain_match.group(1)
                    domains.add(domain)
                    if re.match(r"\d+\.\d+\.\d+\.\d+", domain):
                        has_ip_direct += 1

        fv.features["unique_domains"] = len(domains)
        fv.features["https_requests"] = has_https
        fv.features["http_requests"] = has_http
        fv.features["ip_direct_requests"] = has_ip_direct

        for method, count in methods.items():
            fv.features[f"net_method_{method}"] = count

    def _extract_file_features(self, conn: sqlite3.Connection, fv: FeatureVector):
        try:
            cursor = conn.execute(
                "SELECT path, operation, size FROM file_access"
            )
            rows = cursor.fetchall()
        except Exception:
            return

        fv.features["total_file_operations"] = len(rows)

        operations = Counter()
        paths = set()
        total_bytes = 0
        external_access = 0
        system_access = 0
        data_access = 0

        for path, op, size in rows:
            operations[op or "unknown"] += 1
            if path:
                paths.add(path)
                if "/sdcard" in path or "/storage" in path:
                    external_access += 1
                if "/system" in path:
                    system_access += 1
                if "/data/data" in path:
                    data_access += 1
            total_bytes += size or 0

        fv.features["unique_files_accessed"] = len(paths)
        fv.features["total_bytes_accessed"] = total_bytes
        fv.features["external_storage_access"] = external_access
        fv.features["system_file_access"] = system_access
        fv.features["app_data_access"] = data_access

        for op, count in operations.items():
            fv.features[f"file_op_{op}"] = count

    def _extract_sensor_features(self, conn: sqlite3.Connection, fv: FeatureVector):
        try:
            cursor = conn.execute(
                "SELECT sensor_type, data FROM sensor_log"
            )
            rows = cursor.fetchall()
        except Exception:
            return

        fv.features["total_sensor_readings"] = len(rows)

        sensor_types = Counter()
        for stype, data in rows:
            sensor_types[stype or "unknown"] += 1

        for stype, count in sensor_types.items():
            fv.features[f"sensor_{stype}"] = count

    def _extract_permission_features(self, conn: sqlite3.Connection, fv: FeatureVector):
        try:
            cursor = conn.execute(
                "SELECT api_name, args FROM api_calls WHERE api_name LIKE '%permission%'"
            )
            rows = cursor.fetchall()
        except Exception:
            return

        all_text = " ".join(
            f"{name or ''} {args or ''}" for name, args in rows
        ).lower()

        for perm in PERMISSION_FEATURES:
            perm_short = perm.split(".")[-1].lower()
            fv.features[f"perm_{perm_short}"] = 1 if perm_short in all_text else 0

    def _extract_temporal_features(self, conn: sqlite3.Connection, fv: FeatureVector):
        try:
            cursor = conn.execute(
                "SELECT timestamp FROM api_calls ORDER BY timestamp"
            )
            timestamps = [row[0] for row in cursor.fetchall()]
        except Exception:
            return

        if not timestamps:
            return

        fv.features["session_duration"] = timestamps[-1] - timestamps[0] if len(timestamps) > 1 else 0

        if len(timestamps) > 1:
            intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
            fv.features["avg_call_interval"] = np.mean(intervals) if intervals else 0
            fv.features["std_call_interval"] = np.std(intervals) if intervals else 0
            fv.features["max_call_interval"] = max(intervals) if intervals else 0
            fv.features["min_call_interval"] = min(intervals) if intervals else 0

            calls_per_second = len(timestamps) / max((timestamps[-1] - timestamps[0]) / 1000.0, 0.001)
            fv.features["calls_per_second"] = calls_per_second

    def _extract_sequence_features(self, conn: sqlite3.Connection, fv: FeatureVector):
        try:
            cursor = conn.execute(
                "SELECT api_name FROM api_calls ORDER BY timestamp"
            )
            sequence = [row[0] for row in cursor.fetchall()]
        except Exception:
            return

        if not sequence:
            return

        fv.features["sequence_length"] = len(sequence)

        bigrams = Counter()
        for i in range(len(sequence) - 1):
            bigram = f"{sequence[i]}->{sequence[i+1]}"
            bigrams[bigram] += 1

        for bigram, count in bigrams.most_common(20):
            safe = re.sub(r"[^a-zA-Z0-9>_]", "_", bigram)[:50]
            fv.features[f"bigram_{safe}"] = count

        unique_transitions = len(set(
            f"{sequence[i]}->{sequence[i+1]}"
            for i in range(len(sequence) - 1)
        ))
        fv.features["unique_transitions"] = unique_transitions
        fv.features["transition_diversity"] = (
            unique_transitions / max(len(sequence) - 1, 1)
        )

    def build_dataset(self, db_paths: list[str],
                      labels: dict[str, str] = None) -> tuple[list[str], np.ndarray, list[str]]:
        if labels is None:
            labels = {}

        vectors = []
        for db_path in db_paths:
            sample_id = os.path.basename(db_path).replace(".db", "")
            label = labels.get(sample_id, "unknown")
            fv = self.extract_from_db(db_path, sample_id)
            fv.label = label
            vectors.append(fv)

        all_features = set()
        for fv in vectors:
            all_features.update(fv.features.keys())

        self.feature_names = sorted(all_features)

        X = np.array([fv.to_numpy(self.feature_names) for fv in vectors])
        y = [fv.label for fv in vectors]

        return self.feature_names, X, y

    def export_features(self, feature_names: list[str], X: np.ndarray,
                        y: list[str], output_path: str):
        data = {
            "feature_names": feature_names,
            "samples": [],
        }
        for i, label in enumerate(y):
            data["samples"].append({
                "label": label,
                "features": {
                    name: float(X[i][j])
                    for j, name in enumerate(feature_names)
                    if X[i][j] != 0
                }
            })

        with open(output_path, "w") as f:
            json.dump(data, f, indent=2)
        print(f"[+] Features exported: {output_path} ({len(y)} samples, {len(feature_names)} features)")


def main():
    parser = argparse.ArgumentParser(
        description="Feature Extraction for Android Behavioral Analysis"
    )
    parser.add_argument("input", nargs="+",
                        help="SQLite DB files or JSON trace files")
    parser.add_argument("-o", "--output", default="./output/features.json",
                        help="Output JSON file")
    parser.add_argument("--labels", default="",
                        help="Comma-separated sample_id:label pairs")
    args = parser.parse_args()

    labels = {}
    if args.labels:
        for pair in args.labels.split(","):
            if ":" in pair:
                sid, label = pair.split(":", 1)
                labels[sid.strip()] = label.strip()

    extractor = FeatureExtractor()

    db_files = [f for f in args.input if f.endswith(".db")]
    trace_files = [f for f in args.input if f.endswith(".json")]

    vectors = []
    for db_path in db_files:
        sample_id = os.path.basename(db_path).replace(".db", "")
        fv = extractor.extract_from_db(db_path, sample_id)
        fv.label = labels.get(sample_id, "unknown")
        vectors.append(fv)
        print(f"  Extracted: {sample_id} ({len(fv.features)} features)")

    for trace_path in trace_files:
        fv = extractor.extract_from_trace(trace_path)
        fv.label = labels.get(fv.sample_id, "unknown")
        vectors.append(fv)
        print(f"  Extracted: {fv.sample_id} ({len(fv.features)} features)")

    if not vectors:
        print("[!] No input files found")
        return

    all_features = set()
    for fv in vectors:
        all_features.update(fv.features.keys())
    feature_names = sorted(all_features)

    X = np.array([fv.to_numpy(feature_names) for fv in vectors])
    y = [fv.label for fv in vectors]

    extractor.export_features(feature_names, X, y, args.output)

    print(f"\n  Dataset: {len(y)} samples, {len(feature_names)} features")
    label_counts = Counter(y)
    for label, count in label_counts.items():
        print(f"    {label}: {count}")


if __name__ == "__main__":
    main()
