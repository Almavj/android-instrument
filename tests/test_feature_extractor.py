import os
import sqlite3
import tempfile
import unittest
from pathlib import Path

from feature_extractor import FeatureExtractor, FeatureVector


class TestFeatureExtractor(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="feature-test-", dir="/tmp")
        self.extractor = FeatureExtractor()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_sqlite_parsing(self):
        db_path = os.path.join(self.temp_dir, "sample.db")
        conn = sqlite3.connect(db_path)
        conn.execute("CREATE TABLE api_calls (api_name TEXT, args TEXT, result TEXT, timestamp INTEGER)")
        conn.execute("CREATE TABLE network_log (url TEXT, method TEXT, response_code INTEGER)")
        conn.execute("CREATE TABLE file_access (path TEXT, operation TEXT, size INTEGER)")
        conn.execute("CREATE TABLE sensor_log (sensor_type TEXT, data TEXT)")
        conn.execute("INSERT INTO api_calls VALUES (?, ?, ?, ?)", ("getDeviceId", "foo", "bar", 1))
        conn.execute("INSERT INTO network_log VALUES (?, ?, ?)", ("https://example.com", "GET", 200))
        conn.execute("INSERT INTO file_access VALUES (?, ?, ?)", ("/sdcard/test", "read", 16))
        conn.execute("INSERT INTO sensor_log VALUES (?, ?)", ("gps", "1"))
        conn.commit()
        conn.close()

        fv = self.extractor.extract_from_db(db_path, "sample")
        self.assertGreater(fv.features.get("total_api_calls", 0), 0)
        self.assertGreater(fv.features.get("total_network_requests", 0), 0)
        self.assertGreater(fv.features.get("total_file_operations", 0), 0)
        self.assertGreater(fv.features.get("total_sensor_readings", 0), 0)

    def test_feature_vector_generation(self):
        fv = FeatureVector(sample_id="x")
        fv.features["total_api_calls"] = 2
        fv.features["unique_api_calls"] = 1
        self.assertEqual(fv.features["total_api_calls"], 2)
        self.assertEqual(fv.to_dict()["sample_id"], "x")

    def test_empty_db_returns_empty_vector(self):
        db_path = os.path.join(self.temp_dir, "empty.db")
        conn = sqlite3.connect(db_path)
        conn.close()
        fv = self.extractor.extract_from_db(db_path, "empty")
        self.assertEqual(fv.features.get("total_api_calls", 0), 0)
        self.assertEqual(fv.features.get("total_network_requests", 0), 0)


if __name__ == "__main__":
    unittest.main()
