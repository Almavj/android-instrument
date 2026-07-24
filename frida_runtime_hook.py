#!/usr/bin/env python3
"""Runtime Frida-based instrumentation fallback for obfuscated/protected APKs."""
import argparse
import json
import os
import subprocess
import sys
import tempfile
import textwrap
from pathlib import Path

DEFAULT_JS = r'''
setTimeout(function () {
  const fs = require('fs');
  const logPath = '/data/local/tmp/frida.log';
  const append = (msg) => {
    try { fs.appendFileSync(logPath, msg + '\n'); } catch (e) {}
  };

  function hookApi(name, target, impl) {
    try {
      Interceptor.attach(target, {
        onEnter(args) {
          append(JSON.stringify({event:'api', name:name, args: Array.from(args).slice(0, 3)}));
        },
        onLeave(retval) {
          append(JSON.stringify({event:'api_return', name:name, retval: retval.toString()}));
        }
      });
    } catch (e) {}
  }

  try {
    Java.perform(function () {
      const Activity = Java.use('android.app.Activity');
      Activity.onCreate.overload('android.os.Bundle').implementation = function (bundle) {
        append(JSON.stringify({event:'activity_onCreate', class: 'android.app.Activity'}));
        return this.onCreate(bundle);
      };

      const URLClass = Java.use('java.net.URL');
      URLClass.$init.overload('java.lang.String').implementation = function (url) {
        append(JSON.stringify({event:'network', url: url}));
        return this.$init(url);
      };

      const File = Java.use('java.io.File');
      File.$init.overload('java.lang.String').implementation = function (path) {
        append(JSON.stringify({event:'file', path: path, op: 'open'}));
        return this.$init(path);
      };

      const Class = Java.use('java.lang.Class');
      Class.forName.overload('java.lang.String').implementation = function (name) {
        append(JSON.stringify({event:'reflection', class_name: name}));
        return this.forName(name);
      };
    });
  } catch (e) {
    append(JSON.stringify({event:'error', message: e.message}));
  }
}, 0);
'''


def ensure_frida_installed():
    try:
        subprocess.run(['frida', '--version'], capture_output=True, text=True, check=True)
    except Exception as exc:
        raise RuntimeError('Frida is required. Install with: pip install frida frida-tools') from exc


def build_script(output_path: str):
    Path(output_path).write_text(DEFAULT_JS)
    return output_path


def run(target_pid: str=None, serial: str=None, script_path: str=None):
    ensure_frida_installed()
    script = script_path or build_script(tempfile.gettempdir() + '/frida_runtime_hook.js')
    cmd = ['frida', '-U']
    if serial:
        cmd.extend(['-D', serial])
    if target_pid:
        cmd.extend(['-p', target_pid])
    cmd.extend(['-l', script, '--no-pause'])
    print('[*] Starting Frida runtime hook')
    print(f'[*] Script: {script}')
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    try:
        for line in proc.stdout:
            if line:
                print(line.rstrip())
    except KeyboardInterrupt:
        proc.terminate()
    return proc.returncode


def main():
    parser = argparse.ArgumentParser(description='Frida runtime instrumentation fallback')
    parser.add_argument('--serial', default=None, help='ADB serial for device attachment')
    parser.add_argument('--script', default=None, help='Frida script path')
    parser.add_argument('--pid', default=None, help='Target PID to attach to')
    args = parser.parse_args()
    run(target_pid=args.pid, serial=args.serial, script_path=args.script)


if __name__ == '__main__':
    main()
