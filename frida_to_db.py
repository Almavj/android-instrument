#!/usr/bin/env python3
"""Convert Frida JSONL / text logs into instrumentation.db for feature extraction."""
from __future__ import annotations

import argparse
import json
import os
import re
import sqlite3
import time
from pathlib import Path
from typing import Any


SCHEMA = """
CREATE TABLE IF NOT EXISTS api_calls (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp INTEGER,
    thread_id INTEGER,
    api_name TEXT,
    args TEXT,
    result TEXT
);
CREATE TABLE IF NOT EXISTS network_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp INTEGER,
    thread_id INTEGER,
    url TEXT,
    method TEXT,
    headers TEXT,
    response_code INTEGER
);
CREATE TABLE IF NOT EXISTS file_access (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp INTEGER,
    thread_id INTEGER,
    path TEXT,
    operation TEXT,
    size INTEGER
);
CREATE TABLE IF NOT EXISTS sensor_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp INTEGER,
    sensor_type TEXT,
    data TEXT
);
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp INTEGER,
    event_type TEXT,
    payload TEXT
);
"""


def _ts(value: Any) -> int:
    if value is None:
        return int(time.time() * 1000)
    if isinstance(value, (int, float)):
        return int(value)
    try:
        return int(float(value))
    except Exception:
        return int(time.time() * 1000)


def _parse_line(line: str) -> dict | None:
    line = line.strip()
    if not line:
        return None
    # Prefer pure JSON lines
    if line.startswith("{"):
        try:
            return json.loads(line)
        except json.JSONDecodeError:
            pass
    # Bracketed frida log: [ts] [TID:x] [TAG] msg
    m = re.match(r"^\[.*?\]\s*\[TID:(\d+)\]\s*\[([A-Z_]+)\]\s*(.*)$", line)
    if m:
        return {
            "event": m.group(2).lower(),
            "thread_id": int(m.group(1)),
            "message": m.group(3),
            "raw": line,
        }
    # JSON embedded after prefix
    idx = line.find("{")
    if idx >= 0:
        try:
            return json.loads(line[idx:])
        except json.JSONDecodeError:
            return {"event": "log", "message": line}
    return {"event": "log", "message": line}


def convert(log_path: str, db_path: str) -> dict[str, int]:
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.executescript(SCHEMA)
    counts = {"api_calls": 0, "network_log": 0, "file_access": 0, "sensor_log": 0, "events": 0}

    with open(log_path, "r", encoding="utf-8", errors="replace") as fh:
        for raw in fh:
            evt = _parse_line(raw)
            if not evt:
                continue

            event = str(evt.get("event") or evt.get("type") or "unknown").lower()
            ts = _ts(evt.get("timestamp") or evt.get("ts"))
            tid = int(evt.get("thread_id") or evt.get("tid") or 0)
            payload = json.dumps(evt, default=str)

            conn.execute(
                "INSERT INTO events (timestamp, event_type, payload) VALUES (?, ?, ?)",
                (ts, event, payload),
            )
            counts["events"] += 1

            if event in {
                "api", "api_call", "api_return", "reflection", "binder", "crypto",
                "sms", "contacts", "location", "camera", "microphone", "telephony",
                "clipboard", "package", "exec", "runtime",
            }:
                api_name = (
                    evt.get("name")
                    or evt.get("api")
                    or evt.get("method")
                    or evt.get("class_name")
                    or event
                )
                args = evt.get("args") or evt.get("message") or evt.get("data") or ""
                result = evt.get("retval") or evt.get("result") or ""
                if not isinstance(args, str):
                    args = json.dumps(args, default=str)
                if not isinstance(result, str):
                    result = json.dumps(result, default=str)
                conn.execute(
                    "INSERT INTO api_calls (timestamp, thread_id, api_name, args, result) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (ts, tid, str(api_name), args[:4000], result[:2000]),
                )
                counts["api_calls"] += 1

            if event in {"network", "http", "socket", "url", "okhttp"}:
                url = evt.get("url") or evt.get("host") or evt.get("message") or ""
                method = evt.get("method") or "GET"
                code = evt.get("response_code") or evt.get("code") or 0
                try:
                    code = int(code)
                except Exception:
                    code = 0
                headers = evt.get("headers") or ""
                if not isinstance(headers, str):
                    headers = json.dumps(headers, default=str)
                conn.execute(
                    "INSERT INTO network_log (timestamp, thread_id, url, method, headers, response_code) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (ts, tid, str(url)[:2000], str(method), headers[:2000], code),
                )
                counts["network_log"] += 1

            if event in {"file", "file_io", "open", "read", "write"}:
                path = evt.get("path") or evt.get("file") or evt.get("message") or ""
                op = evt.get("op") or evt.get("operation") or event
                size = evt.get("size") or 0
                try:
                    size = int(size)
                except Exception:
                    size = 0
                conn.execute(
                    "INSERT INTO file_access (timestamp, thread_id, path, operation, size) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (ts, tid, str(path)[:2000], str(op), size),
                )
                counts["file_access"] += 1

            if event in {"sensor", "gps", "location"} and "location" not in event:
                conn.execute(
                    "INSERT INTO sensor_log (timestamp, sensor_type, data) VALUES (?, ?, ?)",
                    (ts, event, payload[:4000]),
                )
                counts["sensor_log"] += 1
            elif event == "location":
                conn.execute(
                    "INSERT INTO sensor_log (timestamp, sensor_type, data) VALUES (?, ?, ?)",
                    (ts, "gps", payload[:4000]),
                )
                counts["sensor_log"] += 1

    conn.commit()
    conn.close()
    return counts


def main():
    parser = argparse.ArgumentParser(description="Convert Frida logs to instrumentation.db")
    parser.add_argument("log", help="Frida log path (JSONL or text)")
    parser.add_argument("-o", "--output", default="./output/traces/instrumentation.db")
    args = parser.parse_args()
    if not os.path.isfile(args.log):
        raise SystemExit(f"Log not found: {args.log}")
    counts = convert(args.log, args.output)
    print(f"[+] Wrote {args.output}")
    for k, v in counts.items():
        print(f"    {k}: {v}")


if __name__ == "__main__":
    main()
