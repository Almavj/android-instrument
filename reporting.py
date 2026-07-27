#!/usr/bin/env python3
"""Automated Reporting Module with MITRE ATT&CK Mapping.

Generates HTML/PDF reports from instrumentation results, mapping observed
behaviors to MITRE ATT&CK for Mobile techniques.

Usage:
    python reporting.py --trace ./output/traces/latest_trace.json --output report.html
"""

import argparse
import json
import os
import sys
from datetime import datetime
from typing import Optional


MITRE_ATTACK_MAP = {
    "getDeviceId": {"id": "T1426", "tactic": "Discovery", "technique": "System Information Discovery"},
    "getImei": {"id": "T1426", "tactic": "Discovery", "technique": "System Information Discovery"},
    "getLine1Number": {"id": "T1426", "tactic": "Discovery", "technique": "System Information Discovery"},
    "getSubscriberId": {"id": "T1422", "tactic": "Discovery", "technique": "SIM Information Discovery"},
    "getSimSerialNumber": {"id": "T1422", "tactic": "Discovery", "technique": "SIM Information Discovery"},
    "getAccounts": {"id": "T1421", "tactic": "Discovery", "technique": "System Network Configuration Discovery"},
    "getAccountTypes": {"id": "T1421", "tactic": "Discovery", "technique": "System Network Configuration Discovery"},
    "ContentResolver.query": {"id": "T1533", "tactic": "Discovery", "technique": "Data from Local System"},
    "LocationManager.getLastKnownLocation": {"id": "T1430", "tactic": "Collection", "technique": "Device Location"},
    "LocationManager.requestLocationUpdates": {"id": "T1430", "tactic": "Collection", "technique": "Device Location"},
    "Camera.open": {"id": "T1512", "tactic": "Collection", "technique": "Video Capture"},
    "MediaRecorder.start": {"id": "T1513", "tactic": "Collection", "technique": "Screen Capture"},
    "AudioRecord.startRecording": {"id": "T1512", "tactic": "Collection", "technique": "Video Capture"},
    "SmsManager.sendTextMessage": {"id": "T1432", "tactic": "Collection", "technique": "SMS Messages"},
    "ClipboardManager.getPrimaryClip": {"id": "T1414", "tactic": "Collection", "technique": "Clipboard Data"},
    "Runtime.exec": {"id": "T1424", "tactic": "Execution", "technique": "Process Injection"},
    "DexClassLoader": {"id": "T1407", "tactic": "Defense Evasion", "technique": "Download New Code at Runtime"},
    "PackageManager.getInstalledPackages": {"id": "T1418", "tactic": "Discovery", "technique": "Application Discovery"},
    "URL": {"id": "T1071", "tactic": "Command and Control", "technique": "Application Layer Protocol"},
    "HttpURLConnection": {"id": "T1071", "tactic": "Command and Control", "technique": "Application Layer Protocol"},
    "Activity.onCreate": {"id": "T1402", "tactic": "Execution", "technique": "App Execution"},
}

REPORT_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Red Team Report - {apk_name}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', system-ui, sans-serif; background: #0a0a0a; color: #e0e0e0; line-height: 1.6; }}
        .container {{ max-width: 1200px; margin: 0 auto; padding: 20px; }}
        .header {{ background: linear-gradient(135deg, #1a1a2e, #16213e); padding: 40px; border-radius: 12px; margin-bottom: 30px; border: 1px solid #0f3460; }}
        .header h1 {{ color: #e94560; font-size: 28px; margin-bottom: 10px; }}
        .header .meta {{ color: #888; font-size: 14px; }}
        .section {{ background: #111; border-radius: 8px; padding: 24px; margin-bottom: 20px; border: 1px solid #222; }}
        .section h2 {{ color: #e94560; margin-bottom: 16px; font-size: 20px; border-bottom: 1px solid #333; padding-bottom: 8px; }}
        .section h3 {{ color: #0f3460; margin: 12px 0 8px; font-size: 16px; }}
        table {{ width: 100%; border-collapse: collapse; margin: 12px 0; }}
        th {{ background: #1a1a2e; color: #e94560; padding: 10px; text-align: left; font-weight: 600; }}
        td {{ padding: 10px; border-bottom: 1px solid #222; }}
        tr:hover {{ background: #1a1a1a; }}
        .tag {{ display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 12px; font-weight: 600; margin: 2px; }}
        .tag-discovery {{ background: #1a3a1a; color: #4ade80; }}
        .tag-collection {{ background: #3a1a1a; color: #f87171; }}
        .tag-execution {{ background: #3a3a1a; color: #fbbf24; }}
        .tag-c2 {{ background: #1a1a3a; color: #60a5fa; }}
        .tag-evasion {{ background: #2a1a3a; color: #c084fc; }}
        .severity-critical {{ color: #ef4444; font-weight: bold; }}
        .severity-high {{ color: #f97316; font-weight: bold; }}
        .severity-medium {{ color: #eab308; }}
        .severity-low {{ color: #22c55e; }}
        .summary-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin: 16px 0; }}
        .summary-card {{ background: #1a1a2e; padding: 16px; border-radius: 8px; text-align: center; }}
        .summary-card .number {{ font-size: 32px; font-weight: bold; color: #e94560; }}
        .summary-card .label {{ color: #888; font-size: 13px; margin-top: 4px; }}
        .mitre-grid {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr)); gap: 12px; }}
        .mitre-card {{ background: #1a1a2e; padding: 12px; border-radius: 6px; border-left: 3px solid #e94560; }}
        .mitre-id {{ color: #e94560; font-weight: bold; font-family: monospace; }}
        .mitre-tech {{ color: #ccc; font-size: 14px; }}
        .mitre-tactic {{ color: #888; font-size: 12px; }}
        .timeline {{ position: relative; padding-left: 30px; }}
        .timeline::before {{ content: ''; position: absolute; left: 10px; top: 0; bottom: 0; width: 2px; background: #333; }}
        .timeline-item {{ position: relative; margin-bottom: 16px; padding: 12px; background: #1a1a2e; border-radius: 6px; }}
        .timeline-item::before {{ content: ''; position: absolute; left: -24px; top: 16px; width: 10px; height: 10px; border-radius: 50%; background: #e94560; }}
        .timeline-time {{ color: #888; font-size: 12px; }}
    </style>
</head>
<body>
<div class="container">
    <div class="header">
        <h1>Red Team Assessment Report</h1>
        <div class="meta">
            APK: {apk_name} | Generated: {timestamp} | SHA256: {sha256}<br>
            Classification: {classification}
        </div>
    </div>

    <div class="section">
        <h2>Executive Summary</h2>
        <div class="summary-grid">
            <div class="summary-card">
                <div class="number">{total_events}</div>
                <div class="label">Behavioral Events</div>
            </div>
            <div class="summary-card">
                <div class="number">{unique_apis}</div>
                <div class="label">Unique APIs Called</div>
            </div>
            <div class="summary-card">
                <div class="number">{mitre_count}</div>
                <div class="label">MITRE Techniques</div>
            </div>
            <div class="summary-card">
                <div class="number">{severity}</div>
                <div class="label">Overall Severity</div>
            </div>
        </div>
        <p>{summary_text}</p>
    </div>

    <div class="section">
        <h2>MITRE ATT&CK for Mobile Mapping</h2>
        <div class="mitre-grid">
            {mitre_cards}
        </div>
    </div>

    <div class="section">
        <h2>Behavioral Analysis</h2>
        <h3>API Call Summary</h3>
        {api_table}
    </div>

    <div class="section">
        <h2>Timeline</h2>
        <div class="timeline">
            {timeline}
        </div>
    </div>

    <div class="section">
        <h2>Network Activity</h2>
        {network_table}
    </div>

    <div class="section">
        <h2>Data Collection Events</h2>
        {data_collection_table}
    </div>

    <div class="section">
        <h2>Recommendations</h2>
        {recommendations}
    </div>

    <div class="section">
        <h2>Raw Event Data</h2>
        <details>
            <summary style="cursor:pointer;color:#e94560;">Show raw events ({total_events} total)</summary>
            <pre style="max-height:400px;overflow:auto;padding:12px;background:#0a0a0a;border-radius:6px;font-size:12px;margin-top:8px;">{raw_events}</pre>
        </details>
    </div>
</div>
</body>
</html>
"""


class ReportGenerator:
    """Generate comprehensive red team reports."""

    def __init__(self, trace_path: str, db_path: Optional[str] = None):
        self.trace_path = trace_path
        self.db_path = db_path
        self.trace = self._load_trace()
        self.events = []
        self.api_calls = {}
        self.network_events = []

    def _load_trace(self) -> dict:
        try:
            with open(self.trace_path, "r") as f:
                return json.load(f)
        except (json.JSONDecodeError, FileNotFoundError):
            return {"apk": "unknown", "events": []}

    def _load_events_from_db(self):
        import sqlite3
        if not self.db_path or not os.path.exists(self.db_path):
            return

        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row

        try:
            rows = conn.execute(
                "SELECT * FROM events ORDER BY timestamp ASC LIMIT 10000"
            ).fetchall()
            for row in rows:
                event = dict(row)
                self.events.append(event)

                event_type = event.get("event_type", "")
                api_name = event.get("name", "")
                if api_name:
                    self.api_calls[api_name] = self.api_calls.get(api_name, 0) + 1
                if event_type == "network" or "url" in str(event).lower():
                    self.network_events.append(event)
        except Exception:
            pass
        finally:
            conn.close()

    def _map_to_mitre(self) -> list:
        techniques = []
        seen = set()
        for api_name, count in self.api_calls.items():
            for key, mapping in MITRE_ATTACK_MAP.items():
                if key.lower() in api_name.lower():
                    if mapping["id"] not in seen:
                        seen.add(mapping["id"])
                        techniques.append({**mapping, "count": count})
                    break
        return techniques

    def _calculate_severity(self, techniques: list) -> str:
        score = len(techniques)
        if any(t["tactic"] == "Collection" for t in techniques):
            score += 3
        if any(t["tactic"] == "Command and Control" for t in techniques):
            score += 2
        if any(t["tactic"] == "Execution" for t in techniques):
            score += 2

        if score >= 10:
            return "CRITICAL"
        elif score >= 7:
            return "HIGH"
        elif score >= 4:
            return "MEDIUM"
        return "LOW"

    def _generate_recommendations(self, techniques: list) -> str:
        recs = []
        tactic_recs = {
            "Discovery": "Implement runtime application self-protection (RASP) and obfuscate sensitive API calls.",
            "Collection": "Use Android Keystore for sensitive data, implement proper data-at-rest encryption.",
            "Command and Control": "Implement network security configuration with certificate pinning.",
            "Execution": "Enable SELinux, use app signing verification, and implement code integrity checks.",
            "Defense Evasion": "Implement anti-tampering checks and code obfuscation.",
        }
        seen_tactics = set()
        for t in techniques:
            tactic = t["tactic"]
            if tactic not in seen_tactics and tactic in tactic_recs:
                seen_tactics.add(tactic)
                recs.append(f"<li><strong>{tactic}:</strong> {tactic_recs[tactic]}</li>")

        if not recs:
            recs.append("<li>No specific recommendations. Continue monitoring.</li>")

        return "<ul>" + "\n".join(recs) + "</ul>"

    def generate(self, output_path: str):
        self._load_events_from_db()
        techniques = self._map_to_mitre()
        severity = self._calculate_severity(techniques)

        apk_name = os.path.basename(self.trace.get("apk", "unknown"))
        sha256 = self.trace.get("apk_sha256", "N/A")[:16]
        total_events = len(self.events) or self.trace.get("total_events", 0)

        mitre_cards = ""
        for t in techniques:
            tag_class = f"tag-{t['tactic'].lower().replace(' ', '-')}"
            mitre_cards += f"""
            <div class="mitre-card">
                <span class="mitre-id">{t['id']}</span>
                <span class="tag {tag_class}">{t['tactic']}</span>
                <div class="mitre-tech">{t['technique']} (observed {t['count']}x)</div>
            </div>"""

        api_rows = ""
        for api, count in sorted(self.api_calls.items(), key=lambda x: -x[1]):
            api_rows += f"<tr><td>{api}</td><td>{count}</td></tr>\n"
        api_table = f"<table><tr><th>API Call</th><th>Count</th></tr>{api_rows}</table>" if api_rows else "<p>No API calls recorded.</p>"

        network_rows = ""
        for evt in self.network_events[:50]:
            url = evt.get("url", evt.get("args", "N/A"))
            ts = evt.get("timestamp", "N/A")
            network_rows += f"<tr><td>{ts}</td><td>{url}</td></tr>\n"
        network_table = f"<table><tr><th>Timestamp</th><th>URL/Target</th></tr>{network_rows}</table>" if network_rows else "<p>No network activity recorded.</p>"

        timeline = ""
        for evt in self.events[:30]:
            name = evt.get("name", evt.get("event_type", "unknown"))
            ts = evt.get("timestamp", "")
            timeline += f'<div class="timeline-item"><div class="timeline-time">{ts}</div><div>{name}</div></div>\n'
        if not timeline:
            timeline = "<p>No timeline events.</p>"

        data_rows = ""
        for evt in self.events:
            if any(k in str(evt).lower() for k in ["sms", "contact", "location", "camera", "clipboard"]):
                data_rows += f"<tr><td>{evt.get('event_type', 'N/A')}</td><td>{evt.get('name', 'N/A')}</td></tr>\n"
        data_collection_table = f"<table><tr><th>Type</th><th>Details</th></tr>{data_rows}</table>" if data_rows else "<p>No data collection events.</p>"

        summary_text = f"The analyzed APK ({apk_name}) exhibits {total_events} behavioral events spanning {len(techniques)} MITRE ATT&CK techniques. "
        if severity in ("CRITICAL", "HIGH"):
            summary_text += f"The application demonstrates significant concerning behaviors classified as {severity} risk."
        else:
            summary_text += f"The application risk level is assessed as {severity}."

        raw_events = json.dumps(self.events[:500], indent=2, default=str)[:50000]

        html = REPORT_TEMPLATE.format(
            apk_name=apk_name,
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            sha256=sha256,
            classification="RED TEAM - CONFIDENTIAL",
            total_events=total_events,
            unique_apis=len(self.api_calls),
            mitre_count=len(techniques),
            severity=severity,
            summary_text=summary_text,
            mitre_cards=mitre_cards or "<p>No MITRE mappings found.</p>",
            api_table=api_table,
            timeline=timeline,
            network_table=network_table,
            data_collection_table=data_collection_table,
            recommendations=self._generate_recommendations(techniques),
            raw_events=raw_events,
        )

        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
        with open(output_path, "w") as f:
            f.write(html)
        print(f"[+] Report generated: {output_path}")
        return output_path


def main():
    parser = argparse.ArgumentParser(description="Red Team Report Generator")
    parser.add_argument("--trace", required=True, help="Path to trace JSON")
    parser.add_argument("--db", help="Path to instrumentation.db")
    parser.add_argument("--output", default="report.html", help="Output HTML path")
    args = parser.parse_args()

    generator = ReportGenerator(args.trace, args.db)
    generator.generate(args.output)


if __name__ == "__main__":
    main()
