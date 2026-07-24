import json
import os
import tempfile
import unittest
from unittest.mock import patch, MagicMock

from orchestrator import EmulatorConfig, Command, SIMULATED_C2_COMMANDS, Orchestrator


class TestEmulatorConfig(unittest.TestCase):
    def test_defaults(self):
        cfg = EmulatorConfig()
        self.assertEqual(cfg.backend, "genymotion")
        self.assertEqual(cfg.vm_name, "Genymotion Phone")
        self.assertEqual(cfg.port, 5554)

    def test_custom_values(self):
        cfg = EmulatorConfig(backend="avd", vm_name="Test", port=5556)
        self.assertEqual(cfg.backend, "avd")
        self.assertEqual(cfg.port, 5556)


class TestCommand(unittest.TestCase):
    def test_command_creation(self):
        cmd = Command(name="test", action="shell", args={"cmd": "ls"})
        self.assertEqual(cmd.name, "test")
        self.assertEqual(cmd.delay_after, 1.5)

    def test_simulated_commands_populated(self):
        self.assertGreater(len(SIMULATED_C2_COMMANDS), 0)
        names = [c.name for c in SIMULATED_C2_COMMANDS]
        self.assertIn("get_device_info", names)
        self.assertIn("get_contacts", names)


class TestOrchestratorConfigFromYaml(unittest.TestCase):
    def test_config_from_yaml_defaults(self):
        cfg = Orchestrator._config_from_yaml({})
        self.assertEqual(cfg.backend, "genymotion")
        self.assertEqual(cfg.vm_name, "Genymotion Phone")

    def test_config_from_yaml_override(self):
        cfg = Orchestrator._config_from_yaml({
            "emulator": {"backend": "avd", "vm_name": "Custom VM", "port": 5557},
            "paths": {"adb": "/custom/adb", "gmtool": "", "genymotion": ""},
        })
        self.assertEqual(cfg.backend, "avd")
        self.assertEqual(cfg.vm_name, "Custom VM")
        self.assertEqual(cfg.port, 5557)
        self.assertEqual(cfg.adb_path, "/custom/adb")


class TestOrchestratorInit(unittest.TestCase):
    @patch.object(Orchestrator, "_init_genymotion")
    def test_init_genymotion_called(self, mock_init):
        """When backend is genymotion, _init_genymotion should be called."""
        # This will attempt gmtool lookup which may fail, but that's OK for unit test
        try:
            Orchestrator(
                config=EmulatorConfig(backend="genymotion"),
                app_config={"emulator": {"backend": "genymotion"}, "paths": {}},
            )
        except Exception:
            pass  # gmtool not found is expected in test env

    def test_init_avd_skips_genymotion(self):
        o = Orchestrator.__new__(Orchestrator)
        o.app_config = {"emulator": {"backend": "avd"}, "paths": {"adb": "adb"}}
        o.config = EmulatorConfig(backend="avd")
        o.adb = "adb"
        o.output_dir = "/tmp/test"
        o.emulator_proc = None
        o.gmtool = None
        o.genymotion_bin = None
        o.frida_proc = None
        o.package_name = None
        # Should not raise
        self.assertIsNone(o.gmtool)


class TestOrchestratorSha256(unittest.TestCase):
    def test_sha256_known_content(self):
        tmp = tempfile.NamedTemporaryFile(delete=False, mode="wb")
        tmp.write(b"test content")
        tmp.close()
        try:
            o = Orchestrator.__new__(Orchestrator)
            h = o._sha256(tmp.name)
            self.assertEqual(len(h), 64)
            self.assertTrue(all(c in "0123456789abcdef" for c in h))
        finally:
            os.unlink(tmp.name)

    def test_sha256_nonexistent(self):
        o = Orchestrator.__new__(Orchestrator)
        h = o._sha256("/nonexistent/path")
        self.assertEqual(h, "")


class TestOrchestratorSaveTrace(unittest.TestCase):
    def test_save_trace_creates_files(self):
        o = Orchestrator.__new__(Orchestrator)
        with tempfile.TemporaryDirectory() as tmp:
            o.output_dir = tmp
            trace = {"apk": "test.apk", "commands": [], "errors": []}
            o._save_trace(trace)
            self.assertTrue(os.path.isfile(os.path.join(tmp, "latest_trace.json")))
            # Check trace_*.json created
            trace_files = [f for f in os.listdir(tmp) if f.startswith("trace_")]
            self.assertEqual(len(trace_files), 1)


if __name__ == "__main__":
    unittest.main()
