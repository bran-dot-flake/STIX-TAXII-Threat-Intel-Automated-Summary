#!/usr/bin/env python3
"""Read-only assessment. No sudo, installs, model downloads, or service changes."""
import ctypes
import json
import os
import platform
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.request import urlopen


def command(args):
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=20)
        return {"returncode": p.returncode, "stdout": p.stdout[:16000], "stderr": p.stderr[:1000]}
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"unavailable": type(exc).__name__}


def read(path):
    try:
        return Path(path).read_text()[:16000]
    except OSError:
        return None


def assess():
    disk = shutil.disk_usage(Path.cwd())
    result = {"assessed_at": datetime.now(timezone.utc).isoformat(), "platform": platform.platform(),
        "python": platform.python_version(), "cpu_threads": os.cpu_count(),
        "disk_bytes": {"total": disk.total, "free": disk.free},
        "commands": {}, "ollama": {}}
    if sys.platform == "win32":
        class Memory(ctypes.Structure):
            _fields_ = [("length", ctypes.c_ulong), ("load", ctypes.c_ulong)] + [(x, ctypes.c_ulonglong) for x in
                ("total_physical", "available_physical", "total_page", "available_page", "total_virtual", "available_virtual", "extended")]
        memory = Memory()
        memory.length = ctypes.sizeof(memory)
        if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(memory)):
            result["memory_bytes"] = {"total_physical": memory.total_physical, "available_physical": memory.available_physical}
    else:
        result.update(meminfo=read("/proc/meminfo"), os_release=read("/etc/os-release"),
                      max_map_count=read("/proc/sys/vm/max_map_count"), loadavg=read("/proc/loadavg"))
        for name, args in {"disk": ["df", "-h"], "listening_ports": ["ss", "-lnt"],
            "running_services": ["systemctl", "list-units", "--type=service", "--state=running", "--no-pager"],
            "project_directories": ["find", str(Path.home()), "-maxdepth", "2", "-type", "d", "-name", ".git"]}.items():
            result["commands"][name] = command(args)
    for name, args in {"docker_version": ["docker", "version", "--format", "{{json .}}"],
        "compose_version": ["docker", "compose", "version"],
        "containers": ["docker", "ps", "-a", "--format", "{{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}"],
        "container_resources": ["docker", "stats", "--no-stream", "--format", "{{json .}}"],
        "ollama_models": ["ollama", "list"], "ollama_running": ["ollama", "ps"]}.items():
        result["commands"][name] = command(args)
    for endpoint in ("tags", "ps", "version"):
        try:
            with urlopen("http://127.0.0.1:11434/api/" + endpoint, timeout=5) as r:
                result["ollama"][endpoint] = json.loads(r.read(1_000_000))
        except Exception as exc:
            result["ollama"][endpoint] = {"unavailable": type(exc).__name__}
    return result


if __name__ == "__main__":
    print(json.dumps(assess(), indent=2))
