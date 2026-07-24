import json
import os
import sqlite3
import tempfile
import unittest

from frida_to_db import convert, _parse_line, SCHEMA


class TestParseLine(unittest.TestCase):
    def test_json_line(self):
        line = '{"event":"api","name":"getDeviceId","timestamp":12345}'
        result = _parse_line(line)
        self.assertEqual(result["event"], "api")
        self.assertEqual(result["name"], "getDeviceId")

    def test_empty_line(self):
        self.assertIsNone(_parse_line(""))

    def test_bracketed_log(self):
        line = "[2024-01-01] [TID:1234] [API_CALL] something happened"
        result = _parse_line(line)
        self.assertIsNotNone(result)
        self.assertEqual(result["thread_id"], 1234)

    def test_json_embedded_after_prefix(self):
        line = "some prefix {\"event\":\"network\",\"url\":\"https://example.com\"}"
        result = _parse_line(line)
        self.assertIsNotNone(result)
        self.assertEqual(result["event"], "network")

    def test_plain_text_returns_log_event(self):
        result = _parse_line("just some text")
        self.assertIsNotNone(result)
        self.assertEqual(result["event"], "log")

    def test_whitespace_only_returns_none(self):
        self.assertIsNone(_parse_line("   "))


class TestConvert(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="frida-db-test-")
        self.jsonl_path = os.path.join(self.tmp, "events.jsonl")
        self.db_path = os.path.join(self.tmp, "test.db")

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _write_jsonl(self, events):
        with open(self.jsonl_path, "w") as f:
            for evt in events:
                f.write(json.dumps(evt) + "\n")

    def test_empty_log_produces_empty_db(self):
        Path = __import__("pathlib").Path
        Path(self.jsonl_path).write_text("")
        counts = convert(self.jsonl_path, self.db_path)
        self.assertEqual(sum(counts.values()), 0)
        self.assertTrue(os.path.isfile(self.db_path))
        conn = sqlite3.connect(self.db_path)
        tables = [r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()]
        conn.close()
        self.assertIn("events", tables)
        self.assertIn("api_calls", tables)

    def test_api_event_goes_to_api_calls_and_events(self):
        self._write_jsonl([
            {"event": "api", "name": "getDeviceId", "timestamp": 1000, "thread_id": 1},
            {"event": "telephony", "name": "getImei", "timestamp": 1001, "thread_id": 2},
        ])
        counts = convert(self.jsonl_path, self.db_path)
        self.assertEqual(counts["events"], 2)
        self.assertEqual(counts["api_calls"], 2)
        conn = sqlite3.connect(self.db_path)
        rows = conn.execute("SELECT api_name FROM api_calls ORDER BY id").fetchall()
        conn.close()
        names = [r[0] for r in rows]
        self.assertIn("getDeviceId", names)
        self.assertIn("getImei", names)

    def test_network_event_goes_to_network_log(self):
        self._write_jsonl([
            {"event": "network", "url": "https://evil.com/data", "method": "POST", "timestamp": 2000},
        ])
        counts = convert(self.jsonl_path, self.db_path)
        self.assertEqual(counts["network_log"], 1)
        conn = sqlite3.connect(self.db_path)
        row = conn.execute("SELECT url, method FROM network_log").fetchone()
        conn.close()
        self.assertEqual(row[0], "https://evil.com/data")
        self.assertEqual(row[1], "POST")

    def test_file_event_goes_to_file_access(self):
        self._write_jsonl([
            {"event": "file", "path": "/sdcard/secrets.txt", "op": "read", "size": 1024, "timestamp": 3000},
        ])
        counts = convert(self.jsonl_path, self.db_path)
        self.assertEqual(counts["file_access"], 1)
        conn = sqlite3.connect(self.db_path)
        row = conn.execute("SELECT path, operation, size FROM file_access").fetchone()
        conn.close()
        self.assertEqual(row[0], "/sdcard/secrets.txt")
        self.assertEqual(row[2], 1024)

    def test_location_event_goes_to_sensor_log(self):
        self._write_jsonl([
            {"event": "location", "name": "getLastKnownLocation", "timestamp": 4000},
        ])
        counts = convert(self.jsonl_path, self.db_path)
        self.assertEqual(counts["sensor_log"], 1)

    def test_mixed_events_all_categorized(self):
        self._write_jsonl([
            {"event": "api", "name": "test1", "timestamp": 1000},
            {"event": "network", "url": "http://x.com", "method": "GET", "timestamp": 2000},
            {"event": "file", "path": "/tmp/f", "op": "open", "timestamp": 3000},
            {"event": "exec", "name": "Runtime.exec", "args": "id", "timestamp": 4000},
            {"event": "unknown_type", "timestamp": 5000},
        ])
        counts = convert(self.jsonl_path, self.db_path)
        self.assertEqual(counts["events"], 5)
        self.assertEqual(counts["api_calls"], 2)  # api + exec
        self.assertEqual(counts["network_log"], 1)
        self.assertEqual(counts["file_access"], 1)

    def test_text_log_parsing(self):
        with open(self.jsonl_path, "w") as f:
            f.write("2024-01-01 some plain log line\n")
            f.write('{"event":"api","name":"hook","timestamp":999}\n')
        counts = convert(self.jsonl_path, self.db_path)
        self.assertGreaterEqual(counts["events"], 1)


if __name__ == "__main__":
    unittest.main()
