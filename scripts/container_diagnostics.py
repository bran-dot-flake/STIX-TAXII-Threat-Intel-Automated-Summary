#!/usr/bin/env python3
"""Inspect owned containers and redact configured secrets before displaying logs."""
import argparse
import json
import os
import subprocess
from pathlib import Path
from ti_brief.cli import load_env


def redact(text):
    for key, value in os.environ.items():
        if len(value) >= 8 and any(word in key for word in ("PASSWORD", "TOKEN", "KEY", "PASSPHRASE", "SALT")):
            text = text.replace(value, "[REDACTED]")
    return text


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("containers", nargs="+")
    args = p.parse_args()
    load_env(Path(".env"))
    for name in args.containers:
        raw = subprocess.run(["docker", "inspect", name], capture_output=True, text=True, check=True, timeout=15)
        container = json.loads(raw.stdout)[0]
        if container["Config"].get("Labels", {}).get("org.ti-brief.managed") != "true":
            raise SystemExit("Refusing diagnostics for a container outside this project")
        result = {"name": container["Name"], "restarts": container["RestartCount"], "state": container["State"]}
        print(redact(json.dumps(result, indent=2)))
        logs = subprocess.run(["docker", "logs", "--tail", "80", name], capture_output=True, text=True, timeout=20)
        print(redact(logs.stdout + logs.stderr))
