import os
import tempfile
import unittest
from pathlib import Path

from common_config import load_config, _deep_merge, ensure_dirs, file_sha256, ROOT


class TestDeepMerge(unittest.TestCase):
    def test_simple_override(self):
        base = {"a": 1, "b": 2}
        over = {"b": 3, "c": 4}
        result = _deep_merge(base, over)
        self.assertEqual(result, {"a": 1, "b": 3, "c": 4})

    def test_nested_merge(self):
        base = {"a": {"x": 1, "y": 2}}
        over = {"a": {"y": 99, "z": 100}}
        result = _deep_merge(base, over)
        self.assertEqual(result["a"], {"x": 1, "y": 99, "z": 100})

    def test_none_override(self):
        result = _deep_merge({"a": 1}, None)
        self.assertEqual(result, {"a": 1})

    def test_empty_base(self):
        result = _deep_merge({}, {"a": 1})
        self.assertEqual(result, {"a": 1})


class TestLoadConfig(unittest.TestCase):
    def test_defaults_present(self):
        cfg = load_config(Path("/nonexistent/config.yaml"))
        self.assertIn("emulator", cfg)
        self.assertEqual(cfg["emulator"]["backend"], "genymotion")
        self.assertIn("analysis", cfg)
        self.assertTrue(cfg["analysis"]["frida_enabled"])

    def test_yaml_override(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write("emulator:\n  backend: avd\n  vm_name: TestVM\n")
            f.flush()
            cfg = load_config(f.name)
        os.unlink(f.name)
        self.assertEqual(cfg["emulator"]["backend"], "avd")
        self.assertEqual(cfg["emulator"]["vm_name"], "TestVM")
        # defaults preserved
        self.assertEqual(cfg["emulator"]["port"], 5554)

    def test_env_override_gmtool(self):
        os.environ["GMTOOL"] = "/custom/gmtool"
        try:
            cfg = load_config(Path("/nonexistent.yaml"))
            self.assertEqual(cfg["paths"]["gmtool"], "/custom/gmtool")
        finally:
            del os.environ["GMTOOL"]

    def test_env_override_adb_serial(self):
        os.environ["ADB_SERIAL"] = "192.168.1.100:5555"
        try:
            cfg = load_config(Path("/nonexistent.yaml"))
            self.assertEqual(cfg["emulator"]["serial"], "192.168.1.100:5555")
        finally:
            del os.environ["ADB_SERIAL"]


class TestEnsureDirs(unittest.TestCase):
    def test_creates_standard_dirs(self):
        with tempfile.TemporaryDirectory() as tmp:
            # Patch ROOT temporarily
            import common_config
            old_root = common_config.ROOT
            common_config.ROOT = Path(tmp)
            try:
                ensure_dirs()
                for d in ("logs", "output", "output/traces", "results", "models"):
                    self.assertTrue((Path(tmp) / d).is_dir(), f"{d} not created")
            finally:
                common_config.ROOT = old_root


class TestFileSha256(unittest.TestCase):
    def test_deterministic(self):
        with tempfile.NamedTemporaryFile(delete=False, mode="wb") as f:
            f.write(b"hello world")
            path = f.name
        try:
            h1 = file_sha256(path)
            h2 = file_sha256(path)
            self.assertEqual(h1, h2)
            self.assertEqual(len(h1), 64)  # SHA256 hex digest
        finally:
            os.unlink(path)

    def test_different_files_different_hash(self):
        with tempfile.NamedTemporaryFile(delete=False, mode="wb") as f:
            f.write(b"content A")
            path_a = f.name
        with tempfile.NamedTemporaryFile(delete=False, mode="wb") as f:
            f.write(b"content B")
            path_b = f.name
        try:
            self.assertNotEqual(file_sha256(path_a), file_sha256(path_b))
        finally:
            os.unlink(path_a)
            os.unlink(path_b)


if __name__ == "__main__":
    unittest.main()
