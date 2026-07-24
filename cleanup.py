#!/usr/bin/env python3
import os
import shutil
import sys
from datetime import datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parent

def remove_old_files(pattern, age_days, path):
    target = ROOT / path
    if not target.exists():
        return
    for p in target.glob(pattern):
        try:
            if p.is_file() and (datetime.now() - datetime.fromtimestamp(p.stat().st_mtime)).days >= age_days:
                p.unlink()
            elif p.is_dir() and (datetime.now() - datetime.fromtimestamp(p.stat().st_mtime)).days >= age_days:
                shutil.rmtree(p)
        except Exception:
            continue


def main():
    remove_old_files("*.json", 7, "output/traces")
    shutil.rmtree(ROOT / "__pycache__", ignore_errors=True)
    for p in ROOT.glob("*.pyc"):
        p.unlink(missing_ok=True)
    remove_old_files("*.log", 30, "logs")
    shutil.rmtree(ROOT / "test_app/app/build", ignore_errors=True)
    shutil.rmtree(ROOT / "test_app/app/.gradle", ignore_errors=True)
    print("Cleanup complete")


if __name__ == "__main__":
    sys.exit(main())
