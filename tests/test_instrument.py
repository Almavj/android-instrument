import os
import shutil
import tempfile
import types
import unittest
from pathlib import Path

from instrument import Instrumentor


class TestInstrumentor(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="instrument-test-", dir="/tmp")
        self.apk_path = os.path.join(self.temp_dir, "sample.apk")
        Path(self.apk_path).write_bytes(b"fake apk")

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_instrument_flow_creates_output_dir(self):
        instrumentor = Instrumentor(self.apk_path, output_dir=os.path.join(self.temp_dir, "out"))
        instrumentor._check_prereqs = lambda: None
        instrumentor._decompile = lambda: None
        instrumentor._inject_logging_code = lambda: None
        instrumentor._patch_manifest = lambda: None
        instrumentor._add_permissions = lambda: None
        instrumentor._recompile = lambda: "/tmp/out.apk"

        def fake_sign(apk):
            out_path = os.path.join(self.temp_dir, "out", "signed.apk")
            os.makedirs(os.path.dirname(out_path), exist_ok=True)
            Path(out_path).write_bytes(b"signed")
            return out_path

        instrumentor._sign = fake_sign
        output = instrumentor.instrument()
        self.assertTrue(os.path.exists(output))

    def test_manifest_patching_inserts_service_and_receiver(self):
        instrumentor = Instrumentor(self.apk_path, output_dir=os.path.join(self.temp_dir, "out"))
        manifest_dir = os.path.join(self.temp_dir, "decompiled")
        os.makedirs(manifest_dir, exist_ok=True)
        manifest_path = os.path.join(manifest_dir, "AndroidManifest.xml")
        Path(manifest_path).write_text("<manifest><application></application></manifest>")
        instrumentor.decompiled_dir = manifest_dir
        instrumentor._patch_manifest()
        content = Path(manifest_path).read_text()
        self.assertIn("InstrumentationService", content)
        self.assertIn("BootReceiver", content)

    def test_permission_injection_adds_requested_permissions(self):
        instrumentor = Instrumentor(self.apk_path, output_dir=os.path.join(self.temp_dir, "out"))
        manifest_dir = os.path.join(self.temp_dir, "decompiled")
        os.makedirs(manifest_dir, exist_ok=True)
        manifest_path = os.path.join(manifest_dir, "AndroidManifest.xml")
        Path(manifest_path).write_text("<manifest><application></application></manifest>")
        instrumentor.decompiled_dir = manifest_dir
        instrumentor._add_permissions()
        content = Path(manifest_path).read_text()
        self.assertIn("android.permission.INTERNET", content)
        self.assertIn("android.permission.RECEIVE_BOOT_COMPLETED", content)


if __name__ == "__main__":
    unittest.main()
