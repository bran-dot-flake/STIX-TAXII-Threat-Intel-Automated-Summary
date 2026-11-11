#!/usr/bin/env python3
"""Refuse unsafe starts; no services are changed by this command."""
import argparse
import json
import shutil
import subprocess
from pathlib import Path


def check(profiles, mem_available_mib, disk_free_gib, max_map_count, listening=()):
    config = json.loads(Path("deploy/compose.json").read_text())
    names = {n for n, s in config["services"].items() if set(s["profiles"]) & set(profiles)}
    errors = []
    for n in names:
        for dep in config["services"][n].get("depends_on", {}):
            if dep not in names:
                errors.append(f"{n} requires {dep}; enable its profile")
    budget = sum(int(config["services"][n]["mem_limit"][:-1]) for n in names)
    if mem_available_mib < budget + 1024:
        errors.append(f"Available RAM {mem_available_mib} MiB < container caps {budget} MiB + 1024 MiB headroom. Stage services and measure before tuning.")
    if disk_free_gib < 25:
        errors.append("Require at least 25 GiB free for initial images, indexes and safety margin")
    if "opencti" in profiles and max_map_count < 262144:
        errors.append("vm.max_map_count below 262144; request approval before changing sysctl")
    desired = {8081 if "misp" in profiles else 0, 8080 if "opencti" in profiles else 0} - {0}
    if desired & set(listening):
        errors.append("A required loopback port is already in use; inspect before deployment")
    return {"profiles": profiles, "services": sorted(names), "container_caps_mib": budget, "errors": errors}


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("profiles", nargs="+", choices=["misp", "opencti", "integration"])
    args = p.parse_args()
    meminfo = dict(line.split(":", 1) for line in Path("/proc/meminfo").read_text().splitlines())
    available = int(meminfo["MemAvailable"].strip().split()[0]) // 1024
    listening = subprocess.run(["ss", "-lntH"], text=True, capture_output=True, check=True).stdout
    ports = [int(line.split()[3].rsplit(":", 1)[1]) for line in listening.splitlines()]
    result = check(args.profiles, available, shutil.disk_usage(Path.cwd()).free / 2**30,
                   int(Path("/proc/sys/vm/max_map_count").read_text()), ports)
    print(json.dumps(result, indent=2))
    raise SystemExit(bool(result["errors"]))
