#!/usr/bin/env python3
"""Read-only 15-second resource samples; exits nonzero on low headroom."""
import argparse
import json
import shutil
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path


def sample():
    mem = {k: int(v.strip().split()[0]) for k, v in (line.split(":", 1) for line in Path("/proc/meminfo").read_text().splitlines())}
    result = {"at": datetime.now(timezone.utc).isoformat(), "mem_available_mib": mem["MemAvailable"] // 1024,
        "swap_used_mib": (mem["SwapTotal"] - mem["SwapFree"]) // 1024, "load": Path("/proc/loadavg").read_text().strip(),
        "disk_free_gib": round(shutil.disk_usage(Path.cwd()).free / 2**30, 2)}
    try:
        p = subprocess.run(["docker", "stats", "--no-stream", "--format", "{{json .}}"], capture_output=True, text=True, timeout=10)
        result["containers"] = [json.loads(line) for line in p.stdout.splitlines()] if not p.returncode else []
    except (OSError, subprocess.TimeoutExpired):
        result["containers"] = []
    return result


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--samples", type=int, default=20)
    args = p.parse_args()
    if not 1 <= args.samples <= 240:
        p.error("samples must be 1..240")
    low = False
    for i in range(args.samples):
        result = sample()
        low |= result["mem_available_mib"] < 1024 or result["disk_free_gib"] < 10
        print(json.dumps(result), flush=True)
        if i + 1 < args.samples:
            time.sleep(15)
    raise SystemExit(low)
