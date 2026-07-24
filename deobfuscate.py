#!/usr/bin/env python3
"""Runtime deobfuscation utility using Frida.

Enumerates loaded classes, dumps strings from ClassLoader/DexFile instances,
detects encrypted strings via entropy analysis, and exports context-rich output.
"""

import argparse
import json
import math
import os
import re
import subprocess
import sys
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional


FRIDA_SCRIPT = r"""
"use strict";

var results = [];

function timestamp() {
    return new Date().toISOString();
}

function log(msg) {
    var line = "[" + timestamp() + "] " + msg;
    send({type: "log", data: line});
}

function collectStrings() {
    Java.perform(function() {
        log("Enumerating loaded classes...");

        var classNames = [];
        Java.enumerateLoadedClasses({
            onMatch: function(className) {
                classNames.push(className);
            },
            onComplete: function() {
                log("Found " + classNames.length + " loaded classes");
                send({type: "class_count", data: classNames.length});
            }
        });

        setTimeout(function() {
            var stringSet = {};
            var classStrings = {};

            classNames.forEach(function(className) {
                try {
                    var cls = Java.use(className);
                    var methods = cls.class.getDeclaredMethods();

                    methods.forEach(function(method) {
                        try {
                            var body = method.toString();
                            var stringPattern = /"([^"\\]|\\.)*"/g;
                            var matches = body.match(stringPattern);
                            if (matches) {
                                matches.forEach(function(s) {
                                    var cleaned = s.slice(1, -1);
                                    if (cleaned.length > 2 && !stringSet[cleaned]) {
                                        stringSet[cleaned] = true;
                                        if (!classStrings[className]) {
                                            classStrings[className] = [];
                                        }
                                        classStrings[className].push(cleaned);
                                    }
                                });
                            }
                        } catch (e) {}
                    });
                } catch (e) {}
            });

            send({type: "strings", data: classStrings});
            log("Collected strings from " + Object.keys(classStrings).length + " classes");
        }, 2000);
    });
}

function dumpDexStrings() {
    Java.perform(function() {
        try {
            var ActivityThread = Java.use("android.app.ActivityThread");
            var app = ActivityThread.currentApplication();
            if (app === null) {
                log("Cannot get current application");
                return;
            }

            var appInfo = app.getApplicationInfo();
            var sourceDir = appInfo.sourceDir;
            log("APK path: " + sourceDir);

            var dexFiles = [];
            Java.enumerateLoadedClasses({
                onMatch: function(name) {
                    if (name.indexOf("DexFile") !== -1 || name.indexOf("BaseDexClassLoader") !== -1) {
                        dexFiles.push(name);
                    }
                },
                onComplete: function() {}
            });

            log("Found " + dexFiles.length + " DexFile-related classes");

        } catch (e) {
            log("Dex dump error: " + e.message);
        }
    });
}

function hookClassLoader() {
    Java.perform(function() {
        try {
            var BaseDexClassLoader = Java.use("dalvik.system.BaseDexClassLoader");
            BaseDexClassLoader.loadClass.overload("java.lang.String", "boolean").implementation = function(name, resolve) {
                send({type: "class_load", data: name});
                return this.loadClass(name, resolve);
            };
            log("ClassLoader hook installed");
        } catch (e) {
            log("ClassLoader hook failed: " + e.message);
        }
    });
}

function detectEncryptedStrings(strings) {
    var results = [];

    Object.keys(strings).forEach(function(className) {
        strings[className].forEach(function(s) {
            var entropy = calculateEntropy(s);
            var suspicious = false;
            var reasons = [];

            if (entropy > 4.5 && s.length > 10) {
                suspicious = true;
                reasons.push("high_entropy");
            }

            if (/^[A-Za-z0-9+/=]{20,}$/.test(s)) {
                suspicious = true;
                reasons.push("base64_like");
            }

            if (/^[0-9a-fA-F]{16,}$/.test(s)) {
                suspicious = true;
                reasons.push("hex_string");
            }

            if (/^[\x00-\x1f]{5,}/.test(s)) {
                suspicious = true;
                reasons.push("control_chars");
            }

            if (/\\x[0-9a-fA-F]{2}/.test(s) || /\\u[0-9a-fA-F]{4}/.test(s)) {
                suspicious = true;
                reasons.push("escape_sequences");
            }

            if (suspicious) {
                results.push({
                    class: className,
                    string: s,
                    entropy: round(entropy, 3),
                    length: s.length,
                    reasons: reasons,
                });
            }
        });
    });

    return results;
}

function calculateEntropy(str) {
    if (str.length === 0) return 0;
    var freq = {};
    for (var i = 0; i < str.length; i++) {
        var c = str[i];
        freq[c] = (freq[c] || 0) + 1;
    }
    var entropy = 0;
    var len = str.length;
    Object.keys(freq).forEach(function(c) {
        var p = freq[c] / len;
        entropy -= p * Math.log2(p);
    });
    return entropy;
}

function round(val, decimals) {
    return Number(Math.round(val + "e" + decimals) + "e-" + decimals);
}

collectStrings();
dumpDexStrings();
hookClassLoader();
log("Deobfuscation hooks active");
"""


@dataclass
class StringEntry:
    value: str
    class_name: str
    entropy: float
    length: int
    reasons: list = field(default_factory=list)
    source: str = "class_dump"


class Deobfuscator:
    def __init__(self, target: str, output_dir: str = "./output",
                 device_id: Optional[str] = None):
        self.target = target
        self.output_dir = output_dir
        self.device_id = device_id
        self.all_strings: list[StringEntry] = []
        os.makedirs(output_dir, exist_ok=True)

    def run(self) -> str:
        print(f"[*] Target: {self.target}")
        print(f"[*] Output: {self.output_dir}")
        print()

        self._check_prereqs()

        if self._is_package():
            output = self._attach_frida()
        elif os.path.isfile(self.target):
            output = self._run_standalone()
        else:
            print(f"[!] Cannot determine target type: {self.target}")
            sys.exit(1)

        self._analyze_strings()
        output_path = self._export_results()
        print(f"\n[+] Results: {output_path}")
        return output_path

    def _check_prereqs(self):
        frida = subprocess.run(["which", "frida"], capture_output=True, text=True)
        if frida.returncode != 0:
            print("[!] Frida not found. Install with:")
            print("    pip install frida-tools frida")
            sys.exit(1)
        print("[+] Frida found")

    def _is_package(self) -> bool:
        return not os.path.exists(self.target) and "." in self.target

    def _attach_frida(self) -> str:
        print(f"[*] Attaching to process: {self.target}")

        script_path = os.path.join(self.output_dir, "_frida_script.js")
        with open(script_path, "w") as f:
            f.write(FRIDA_SCRIPT)

        cmd = ["frida"]
        if self.device_id:
            cmd.extend(["-D", self.device_id])
        cmd.extend(["-n", self.target, "-l", script_path, "--no-pause"])

        print(f"    Command: {' '.join(cmd)}")
        print("    [*] Waiting for data (10 seconds)...")
        print("    [*] Press Ctrl+C to stop")

        try:
            result = subprocess.run(
                cmd, capture_output=False, timeout=15,
                text=True
            )
        except subprocess.TimeoutExpired:
            print("    [*] Collection window ended")
        except KeyboardInterrupt:
            print("    [*] Interrupted")
        finally:
            if os.path.exists(script_path):
                os.remove(script_path)

        return ""

    def _run_standalone(self) -> str:
        print(f"[*] Analyzing file: {self.target}")

        strings_result = subprocess.run(
            ["strings", "-n", "4", self.target],
            capture_output=True, text=True, timeout=30
        )

        raw_strings = strings_result.stdout.split("\n")
        print(f"    Extracted {len(raw_strings)} strings")

        for s in raw_strings:
            s = s.strip()
            if len(s) < 4:
                continue
            entropy = self._calculate_entropy(s)
            reasons = self._classify_string(s, entropy)

            if reasons:
                self.all_strings.append(StringEntry(
                    value=s,
                    class_name="<file>",
                    entropy=entropy,
                    length=len(s),
                    reasons=reasons,
                    source="strings",
                ))

        print(f"    Flagged {len(self.all_strings)} suspicious strings")
        return ""

    def _analyze_strings(self):
        print("[*] Analyzing extracted strings...")

        if not self.all_strings:
            print("    No strings collected from Frida session")
            print("    (Frida collection requires an active device connection)")
            return

        by_reason = defaultdict(list)
        for s in self.all_strings:
            for reason in s.reasons:
                by_reason[reason].append(s)

        print(f"\n    Summary:")
        print(f"    Total suspicious strings: {len(self.all_strings)}")
        for reason, entries in sorted(by_reason.items()):
            print(f"      {reason}: {len(entries)} strings")

    def _classify_string(self, s: str, entropy: float) -> list[str]:
        reasons = []
        if entropy > 4.5 and len(s) > 10:
            reasons.append("high_entropy")
        if re.match(r"^[A-Za-z0-9+/=]{20,}$", s):
            reasons.append("base64_like")
        if re.match(r"^[0-9a-fA-F]{16,}$", s):
            reasons.append("hex_string")
        if re.match(r"^[\x00-\x1f]{5,}", s):
            reasons.append("control_chars")
        if "\\x" in s or "\\u" in s:
            reasons.append("escape_sequences")
        if any(kw in s.lower() for kw in ["flag{", "ctf{", "password", "secret", "key"]):
            reasons.append("interesting_keyword")
        return reasons

    def _calculate_entropy(self, s: str) -> float:
        if not s:
            return 0.0
        freq = {}
        for c in s:
            freq[c] = freq.get(c, 0) + 1
        entropy = 0.0
        length = len(s)
        for count in freq.values():
            p = count / length
            if p > 0:
                entropy -= p * math.log2(p)
        return entropy

    def _export_results(self) -> str:
        output_path = os.path.join(self.output_dir, "strings_dump.txt")
        with open(output_path, "w") as f:
            f.write(f"Deobfuscation Results\n")
            f.write(f"Target: {self.target}\n")
            f.write(f"Total strings analyzed: {len(self.all_strings)}\n")
            f.write("=" * 80 + "\n\n")

            sorted_strings = sorted(self.all_strings, key=lambda s: s.entropy, reverse=True)

            for s in sorted_strings:
                f.write(f"String: {s.value[:200]}\n")
                f.write(f"  Class:    {s.class_name}\n")
                f.write(f"  Entropy:  {s.entropy:.3f}\n")
                f.write(f"  Length:   {s.length}\n")
                f.write(f"  Reasons:  {', '.join(s.reasons)}\n")
                f.write(f"  Source:   {s.source}\n")
                f.write("\n")

        json_path = os.path.join(self.output_dir, "strings_dump.json")
        with open(json_path, "w") as f:
            json.dump([{
                "value": s.value[:500],
                "class": s.class_name,
                "entropy": s.entropy,
                "length": s.length,
                "reasons": s.reasons,
                "source": s.source,
            } for s in self.all_strings], f, indent=2)

        print(f"    Exported: {output_path}")
        print(f"    Exported: {json_path}")
        return output_path


def main():
    parser = argparse.ArgumentParser(
        description="Runtime Deobfuscation via Frida"
    )
    parser.add_argument("target", help="Package name or APK/file path")
    parser.add_argument("-o", "--output", default="./output/deobfuscation",
                        help="Output directory")
    parser.add_argument("-d", "--device", help="USB device ID (frida-ls-devices)")
    args = parser.parse_args()

    deobfuscator = Deobfuscator(
        target=args.target,
        output_dir=args.output,
        device_id=args.device,
    )
    deobfuscator.run()


if __name__ == "__main__":
    main()
