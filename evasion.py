#!/usr/bin/env python3
"""Anti-Detection & Evasion Module.

Provides smali patches and Frida scripts that bypass common Android
security checks: root detection, emulator detection, Frida detection,
debugger detection, and SafetyNet/Play Integrity attestation.

Usage:
    python evasion.py --apk-dir ./decompiled --mode full
    python evasion.py --apk-dir ./decompiled --mode root-only
"""

import argparse
import os
import random
import re
import string
import sys
from pathlib import Path
from typing import Optional


class EvasionPatcher:
    """Applies anti-detection smali patches to a decompiled APK."""

    ROOT_INDICATORS = [
        "/system/app/Superuser.apk",
        "/system/bin/su",
        "/system/xbin/su",
        "/sbin/su",
        "/data/local/xbin/su",
        "/data/local/bin/su",
        "/system/sd/xbin/su",
        "/system/bin/failsafe/su",
        "/data/local/su",
        "/su/bin/su",
    ]

    FRIDA_INDICATORS = [
        "frida",
        "fridaserver",
        "linjector",
        "REJECT",
        "gmain",
    ]

    EMULATOR_PROPS = {
        "ro.hardware": ["goldfish", "ranchu", "vbox86"],
        "ro.product.board": ["goldfish", "ranchu", "vbox86"],
        "ro.product.device": ["generic", "vbox86", "emulator"],
        "ro.product.model": ["sdk", "google_sdk", "Android SDK"],
        "ro.build.fingerprint": ["generic", "unknown", "sdk", "vbox"],
        "ro.hardware.audio.primary": ["goldfish"],
        "ro.kernel.qemu": ["1"],
    }

    def __init__(self, decompiled_dir: str, verbose: bool = False):
        self.decompiled_dir = os.path.abspath(decompiled_dir)
        self.verbose = verbose
        self.smali_dirs = self._find_smali_dirs()
        self.patches_applied = 0

    def _find_smali_dirs(self) -> list:
        dirs = []
        for entry in os.listdir(self.decompiled_dir):
            full = os.path.join(self.decompiled_dir, entry)
            if os.path.isdir(full) and entry.startswith("smali"):
                dirs.append(full)
        return dirs

    def _log(self, msg: str):
        if self.verbose:
            print(f"  [evasion] {msg}")

    def apply_all(self):
        print("[*] Applying anti-detection patches...")
        self.bypass_root_detection()
        self.bypass_frida_detection()
        self.bypass_emulator_detection()
        self.bypass_debugger_detection()
        self.bypass_safetynet()
        print(f"[+] Applied {self.patches_applied} evasion patches")

    def bypass_root_detection(self):
        self._log("Patching root detection checks...")
        patterns = [
            (r'Ljava/io/File;->exists\(\)Z', 'root_check_file'),
            (r'Lcom/scottyab/rootbeer/RootBeer;->isRooted\(\)Z', 'rootbeer'),
            (r'Lcom/scottyab/rootbeer/RootBeerGeneric;->isRooted\(\)Z', 'rootbeer_generic'),
        ]

        hook_smali = self._generate_root_bypass_smali()
        for smali_dir in self.smali_dirs:
            self._inject_bypass_class(smali_dir, "EvasionRootBypass", hook_smali)
            for check_dir in ["com", "eu", "io", "net"]:
                self._patch_known_root_libs(smali_dir, check_dir)
        self.patches_applied += 1

    def _patch_known_root_libs(self, smali_dir: str, org: str):
        lib_paths = [
            os.path.join(smali_dir, org, "scottyab", "rootbeer"),
            os.path.join(smali_dir, org, "nicklashansen", "rootbeer"),
            os.path.join(smali_dir, "com", "topjohnwu", "magisk"),
            os.path.join(smali_dir, "eu", "chainfire", "supersu"),
        ]
        for lib_path in lib_paths:
            if not os.path.isdir(lib_path):
                continue
            for root, dirs, files in os.walk(lib_path):
                for f in files:
                    if not f.endswith(".smali"):
                        continue
                    fpath = os.path.join(root, f)
                    with open(fpath, "r") as fh:
                        content = fh.read()
                    modified = content
                    modified = re.sub(
                        r'(\.method.*isRooted.*\n(?:.*\n)*?.*return v\d+\n.*\.end method)',
                        self._return_false_smali(),
                        modified
                    )
                    if modified != content:
                        with open(fpath, "w") as fh:
                            fh.write(modified)
                        self._log(f"Patched root check in {fpath}")

    def _return_false_smali(self) -> str:
        return """.method private static _evasion_return_false()Z
    .registers 2
    const/4 v0, 0x0
    return v0
.end method"""

    def _generate_root_bypass_smali(self) -> str:
        return f""".class public Lcom/evasion/RootBypass;
.super Ljava/lang/Object;

.method public static isRooted()Z
    .registers 2
    const/4 v0, 0x0
    return v0
.end method

.method public static checkSu()Z
    .registers 2
    const/4 v0, 0x0
    return v0
.end method

.method public static isDeviceRooted()Z
    .registers 2
    const/4 v0, 0x0
    return v0
.end method
"""

    def bypass_frida_detection(self):
        self._log("Patching Frida detection...")
        frida_bypass = self._generate_frida_bypass_smali()

        for smali_dir in self.smali_dirs:
            self._inject_bypass_class(smali_dir, "EvasionFridaBypass", frida_bypass)

            for root, dirs, files in os.walk(smali_dir):
                for f in files:
                    if not f.endswith(".smali"):
                        continue
                    fpath = os.path.join(root, f)
                    with open(fpath, "r") as fh:
                        content = fh.read()

                    modified = content

                    modified = re.sub(
                        r'const-string (v\d+), "frida"',
                        r'const-string \1, "unused_lib"',
                        modified
                    )
                    modified = re.sub(
                        r'const-string (v\d+), "fridaserver"',
                        r'const-string \1, "unused_binary"',
                        modified
                    )
                    modified = re.sub(
                        r'const-string (v\d+), "/proc/self/maps"',
                        r'const-string \1, "/dev/null"',
                        modified
                    )

                    if modified != content:
                        with open(fpath, "w") as fh:
                            fh.write(modified)
                        self._log(f"Patched Frida indicators in {fpath}")

        self.patches_applied += 1

    def _generate_frida_bypass_smali(self) -> str:
        return """.class public Lcom/evasion/FridaBypass;
.super Ljava/lang/Object;

.method public static isFridaActive()Z
    .registers 2
    const/4 v0, 0x0
    return v0
.end method

.method public static detectFridaServer()Z
    .registers 2
    const/4 v0, 0x0
    return v0
.end method

.method public static checkForFrida()Z
    .registers 2
    const/4 v0, 0x0
    return v0
.end method
"""

    def bypass_emulator_detection(self):
        self._log("Patching emulator detection...")
        emu_bypass = self._generate_emulator_bypass_smali()

        for smali_dir in self.smali_dirs:
            self._inject_bypass_class(smali_dir, "EvasionEmulatorBypass", emu_bypass)

            self._patch_build_props(smali_dir)

        self.patches_applied += 1

    def _patch_build_props(self, smali_dir: str):
        for root, dirs, files in os.walk(smali_dir):
            for f in files:
                if not f.endswith(".smali"):
                    continue
                fpath = os.path.join(root, f)
                with open(fpath, "r") as fh:
                    content = fh.read()

                modified = content
                modified = re.sub(
                    r'const-string (v\d+), "goldfish"',
                    r'const-string \1, "snapdragon"',
                    modified
                )
                modified = re.sub(
                    r'const-string (v\d+), "ranchu"',
                    r'const-string \1, "exynos"',
                    modified
                )
                modified = re.sub(
                    r'const-string (v\d+), "vbox86"',
                    r'const-string \1, "kirin"',
                    modified
                )
                modified = re.sub(
                    r'const-string (v\d+), "generic"',
                    r'const-string \1, "samsung"',
                    modified
                )

                if modified != content:
                    with open(fpath, "w") as fh:
                        fh.write(modified)

    def _generate_emulator_bypass_smali(self) -> str:
        return """.class public Lcom/evasion/EmulatorBypass;
.super Ljava/lang/Object;

.method public static isEmulator()Z
    .registers 2
    const/4 v0, 0x0
    return v0
.end method

.method public static getRealDeviceModel()Ljava/lang/String;
    .registers 2
    const-string v0, "SM-G991B"
    return-object v0
.end method

.method public static getRealManufacturer()Ljava/lang/String;
    .registers 2
    const-string v0, "samsung"
    return-object v0
.end method
"""

    def bypass_debugger_detection(self):
        self._log("Patching debugger detection...")
        debug_bypass = self._generate_debug_bypass_smali()

        for smali_dir in self.smali_dirs:
            self._inject_bypass_class(smali_dir, "EvasionDebugBypass", debug_bypass)

        self.patches_applied += 1

    def _generate_debug_bypass_smali(self) -> str:
        return """.class public Lcom/evasion/DebugBypass;
.super Ljava/lang/Object;

.method public static isDebuggerConnected()Z
    .registers 2
    const/4 v0, 0x0
    return v0
.end method

.method public static detectTracerPid()I
    .registers 2
    const/4 v0, 0x0
    return v0
.end method

.method public static timingCheck()J
    .registers 3
    invoke-static {}, Ljava/lang/System;->nanoTime()J
    move-result-wide v0
    return-wide v0
.end method
"""

    def bypass_safetynet(self):
        self._log("Patching SafetyNet/Play Integrity...")
        sn_bypass = self._generate_safetynet_smali()

        for smali_dir in self.smali_dirs:
            self._inject_bypass_class(smali_dir, "EvasionSafetyNet", sn_bypass)

            for root, dirs, files in os.walk(smali_dir):
                for f in files:
                    if not f.endswith(".smali"):
                        continue
                    fpath = os.path.join(root, f)
                    with open(fpath, "r") as fh:
                        content = fh.read()

                    modified = content
                    modified = re.sub(
                        r'(?i)Lcom/google/android/gms/safetynet/SafetyNetApi;->attest',
                        'Lcom/evasion/SafetyNet;->bypassAttest',
                        modified
                    )
                    modified = re.sub(
                        r'(?i)attestation.*certificateChain',
                        'return (byte[]) invoke-static {}, Lcom/evasion/SafetyNet;->getFakeResponse()Ljava/lang/Object;',
                        modified
                    )

                    if modified != content:
                        with open(fpath, "w") as fh:
                            fh.write(modified)

        self.patches_applied += 1

    def _generate_safetynet_smali(self) -> str:
        return """.class public Lcom/evasion/SafetyNet;
.super Ljava/lang/Object;

.method public static getFakeResponse()[B
    .registers 2
    const/16 v0, 0x10
    new-array v0, v0, [B
    fill-array-data v0, :array_data
    return-object v0

    :array_data
    .array-data 1
        0x0a 0x00 0x00 0x00
        0x00 0x00 0x00 0x00
        0x00 0x00 0x00 0x00
        0x00 0x00 0x00 0x00
    .end array-data
.end method

.method public static bypassAttest([B)[B
    .registers 2
    invoke-static {}, Lcom/evasion/SafetyNet;->getFakeResponse()[B
    move-result-object v0
    return-object v0
.end method
"""

    def patch_native_checks(self):
        self._log("Patching native library checks...")
        for smali_dir in self.smali_dirs:
            for root, dirs, files in os.walk(smali_dir):
                for f in files:
                    if not f.endswith(".smali"):
                        continue
                    fpath = os.path.join(root, f)
                    with open(fpath, "r") as fh:
                        content = fh.read()

                    modified = content
                    modified = re.sub(
                        r'Landroid/os/Build;->FINGERPRINT:Ljava/lang/String;',
                        'Lcom/evasion/EmulatorBypass;->getRealFingerprint()Ljava/lang/String;',
                        modified
                    )
                    modified = re.sub(
                        r'Landroid/os/Build;->MODEL:Ljava/lang/String;',
                        'Lcom/evasion/EmulatorBypass;->getRealDeviceModel()Ljava/lang/String;',
                        modified
                    )
                    modified = re.sub(
                        r'Landroid/os/Build;->MANUFACTURER:Ljava/lang/String;',
                        'Lcom/evasion/EmulatorBypass;->getRealManufacturer()Ljava/lang/String;',
                        modified
                    )

                    if modified != content:
                        with open(fpath, "w") as fh:
                            fh.write(modified)

        self.patches_applied += 1

    def _inject_bypass_class(self, smali_dir: str, class_name: str, smali_code: str):
        pkg_dir = os.path.join(smali_dir, "com", "evasion")
        os.makedirs(pkg_dir, exist_ok=True)
        smali_file = os.path.join(pkg_dir, f"{class_name}.smali")
        if os.path.exists(smali_file):
            return
        with open(smali_file, "w") as f:
            f.write(smali_code)
        self._log(f"Injected {class_name}.smali")


class FridaEvasionScript:
    """Generates a Frida script that hides Frida from detection."""

    @staticmethod
    def generate() -> str:
        return r"""
'use strict';

/**
 * Anti-detection Frida script.
 * Hides frida-server from /proc/maps, bypasses ptrace checks,
 * spoofs Build properties, and defeats common anti-Frida heuristics.
 */

// ── Hide Frida from /proc/self/maps ──────────────────────────────
function hideFromMaps() {
    var mapsPath = '/proc/self/maps';
    var origOpen = Module.findExportByName(null, 'open');
    var origRead = Module.findExportByName(null, 'read');
    var origClose = Module.findExportByName(null, 'close');

    if (origOpen && origRead && origClose) {
        Interceptor.attach(origOpen, {
            onEnter: function(args) {
                this.path = args[0].readCString();
                this.isMaps = this.path && this.path.indexOf('maps') !== -1;
            },
            onLeave: function(retval) {
            }
        });

        Interceptor.attach(origRead, {
            onEnter: function(args) {
                this.fd = args[0].toInt32();
            },
            onLeave: function(retval) {
                if (!retval.toInt32() || retval.toInt32() <= 0) return;
                try {
                    var buf = args[1];
                    var size = retval.toInt32();
                    var content = buf.readCString(size);
                    if (content && (content.indexOf('frida') !== -1 || content.indexOf('gadget') !== -1 || content.indexOf('gmain') !== -1)) {
                        var lines = content.split('\n');
                        var filtered = lines.filter(function(line) {
                            return line.indexOf('frida') === -1 &&
                                   line.indexOf('gadget') === -1 &&
                                   line.indexOf('gmain') === -1 &&
                                   line.indexOf('linjector') === -1;
                        });
                        var newContent = filtered.join('\n');
                        var newBytes = Memory.allocUtf8String(newContent);
                        Memory.copy(buf, newBytes, newContent.length);
                        retval.replace(newContent.length);
                    }
                } catch (e) {}
            }
        });
    }
}

// ── Bypass ptrace anti-debug ──────────────────────────────────────
function bypassPtrace() {
    var ptrace = Module.findExportByName(null, 'ptrace');
    if (ptrace) {
        Interceptor.attach(ptrace, {
            onEnter: function(args) {
                this.request = args[0].toInt32();
            },
            onLeave: function(retval) {
                if (this.request === 0) {
                    retval.replace(ptr(-1));
                }
            }
        });
    }
}

// ── Bypass strstr-based Frida detection ───────────────────────────
function bypassStrstr() {
    var strstr = Module.findExportByName(null, 'strstr');
    if (strstr) {
        Interceptor.attach(strstr, {
            onEnter: function(args) {
                this.haystack = args[0];
                this.needle = args[1];
                try {
                    var needleStr = this.needle.readCString();
                    if (needleStr && (
                        needleStr.indexOf('frida') !== -1 ||
                        needleStr.indexOf('FRIDA') !== -1 ||
                        needleStr.indexOf('gadget') !== -1 ||
                        needleStr.indexOf('LIBFRIDA') !== -1
                    )) {
                        this.shouldBlock = true;
                    } else {
                        this.shouldBlock = false;
                    }
                } catch (e) {
                    this.shouldBlock = false;
                }
            },
            onLeave: function(retval) {
                if (this.shouldBlock) {
                    retval.replace(ptr(0));
                }
            }
        });
    }
}

// ── Bypass pthread_create Frida thread check ──────────────────────
function bypassPthreadCreate() {
    var pthreadCreate = Module.findExportByName('libc.so', 'pthread_create');
    if (pthreadCreate) {
        Interceptor.attach(pthreadCreate, {
            onEnter: function(args) {
                try {
                    var funcPtr = args[2];
                    var module = Process.findModuleByAddress(funcPtr);
                    if (module && module.name.indexOf('frida') !== -1) {
                        args[2] = new NativeCallback(function() {
                            return 0;
                        }, 'int', []);
                    }
                } catch (e) {}
            }
        });
    }
}

// ── Spoof Android Build properties via Frida Java hooks ───────────
function spoofBuildProperties() {
    Java.perform(function() {
        try {
            var Build = Java.use('android.os.Build');
            Build.FINGERPRINT.value = 'samsung/r0qxxx/r0q:13/TP1A.220624.014/G991BXXUDFUE1:user/release-keys';
            Build.MODEL.value = 'SM-G991B';
            Build.MANUFACTURER.value = 'samsung';
            Build.BRAND.value = 'samsung';
            Build.DEVICE.value = 'r0q';
            Build.PRODUCT.value = 'r0qxxx';
            Build.HARDWARE.value = 'exynos2100';
            Build.BOARD.value = 'exynos2100';
            Build.HOST.value = '219KFXHRC99';
            Build.TAGS.value = 'release-keys';
            Build.TYPE.value = 'user';
        } catch (e) {}

        try {
            var SystemProperties = Java.use('android.os.SystemProperties');
            SystemProperties.get.overload('java.lang.String').implementation = function(key) {
                if (key === 'ro.product.model') return 'SM-G991B';
                if (key === 'ro.product.manufacturer') return 'samsung';
                if (key === 'ro.product.brand') return 'samsung';
                if (key === 'ro.product.device') return 'r0q';
                if (key === 'ro.hardware') return 'exynos2100';
                if (key === 'ro.build.display.id') return 'TP1A.220624.014';
                if (key === 'ro.board.platform') return 'exynos2100';
                if (key === 'qemu.hw.mainkeys') return '0';
                if (key === 'ro.kernel.qemu') return '0';
                if (key === 'init.svc.qemud') return 'stopped';
                if (key === 'init.svc.qemu-props') return 'stopped';
                return this.get(key);
            };
        } catch (e) {}
    });
}

// ── Bypass /proc/self/status TracerPid check ──────────────────────
function bypassTracerPid() {
    Interceptor.attach(Module.findExportByName(null, 'fopen'), {
        onEnter: function(args) {
            this.path = args[0].readCString();
        },
        onLeave: function(retval) {
            if (this.path && this.path.indexOf('status') !== -1) {
                try {
                    var stream = retval;
                    var origRead = Module.findExportByName(null, 'fgets');
                    if (origRead) {
                        Interceptor.attach(origRead, {
                            onEnter: function(args) {
                                this.buf = args[0];
                                this.size = args[1].toInt32();
                                this.stream = args[2];
                            },
                            onLeave: function(retval) {
                                if (this.stream.equals(stream)) {
                                    try {
                                        var line = this.buf.readCString();
                                        if (line && line.indexOf('TracerPid:') !== -1) {
                                            var fake = 'TracerPid:\t0\n';
                                            Memory.writeUtf8String(this.buf, fake);
                                        }
                                    } catch (e) {}
                                }
                            }
                        });
                    }
                } catch (e) {}
            }
        }
    });
}

// ── Init ──────────────────────────────────────────────────────────
setTimeout(function() {
    try { hideFromMaps(); } catch(e) {}
    try { bypassPtrace(); } catch(e) {}
    try { bypassStrstr(); } catch(e) {}
    try { bypassPthreadCreate(); } catch(e) {}
    try { spoofBuildProperties(); } catch(e) {}
    try { bypassTracerPid(); } catch(e) {}
    send({type: 'evasion', data: 'Anti-detection hooks loaded'});
}, 0);
"""

    @staticmethod
    def save(path: str):
        with open(path, "w") as f:
            f.write(FridaEvasionScript.generate())
        print(f"[+] Evasion Frida script written to {path}")


def main():
    parser = argparse.ArgumentParser(description="Anti-Detection Evasion Patcher")
    parser.add_argument("--apk-dir", required=True, help="Path to decompiled APK directory")
    parser.add_argument("--mode", choices=["full", "root-only", "frida-only", "emulator-only"],
                        default="full", help="Evasion mode")
    parser.add_argument("--frida-script", help="Also generate Frida evasion script to this path")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    patcher = EvasionPatcher(args.apk_dir, verbose=args.verbose)

    if args.mode == "full":
        patcher.apply_all()
    elif args.mode == "root-only":
        patcher.bypass_root_detection()
    elif args.mode == "frida-only":
        patcher.bypass_frida_detection()
    elif args.mode == "emulator-only":
        patcher.bypass_emulator_detection()

    if args.frida_script:
        FridaEvasionScript.save(args.frida_script)


if __name__ == "__main__":
    main()
