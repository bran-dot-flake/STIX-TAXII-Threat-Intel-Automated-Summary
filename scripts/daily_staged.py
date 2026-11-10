#!/usr/bin/env python3
"""Opt-in orchestration of this project's containers only. Never invokes sudo.

Enable only after manual platform acceptance and measured memory validation.
"""
import argparse
import json
import os
import subprocess
import sys
from pathlib import Path
from ti_brief.cli import load_env, required, run_lock

COMPOSE = ["docker", "compose", "--project-name", "ti-lab", "--env-file", ".env", "-f", "deploy/compose.json",
           "--profile", "misp", "--profile", "opencti", "--profile", "integration"]


def invoke(args, **kwargs):
    return subprocess.run(args, check=True, timeout=1200, **kwargs)


def verify_ownership():
    result = invoke(["docker", "ps", "-a", "--filter", "label=com.docker.compose.project=ti-lab", "--format", "{{json .Labels}}"], capture_output=True, text=True)
    for line in result.stdout.splitlines():
        labels = dict(pair.split("=", 1) for pair in json.loads(line).split(",") if "=" in pair)
        if labels.get("org.ti-brief.managed") != "true":
            raise RuntimeError("Project-name conflict: found a container not owned by ti-brief")


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--manage-project", action="store_true", help="Explicit consent to start/stop only ti-lab containers")
    args = p.parse_args()
    if not args.manage_project:
        p.error("Requires explicit --manage-project after lab deployment approval")
    load_env(Path(".env"))
    for key in ("MISP_API_KEY", "OPENCTI_TOKEN", "OLLAMA_MODEL"):
        required(key)
    with run_lock(Path("data/live/orchestrator.lock")):
        verify_ownership()
        # A prior interrupted project run may have left only some containers up.
        invoke(COMPOSE + ["stop", "--timeout", "60"])
        invoke([sys.executable, "scripts/preflight.py", "misp", "opencti", "integration"])
        try:
            invoke(COMPOSE + ["up", "-d", "--no-build", "--wait", "--wait-timeout", "900"])
            invoke([sys.executable, "-m", "ti_brief.cli", "--prepare-only", "--sync-timeout", "900"])
        finally:
            # Never delete volumes; release platform memory before CPU inference.
            invoke(COMPOSE + ["stop", "--timeout", "60"])
        invoke([sys.executable, "-m", "ti_brief.cli", "--render-prepared"])
        # Leave MISP accessible after a successful run; OpenCTI can be started on demand.
        invoke([sys.executable, "scripts/preflight.py", "misp"])
        invoke(COMPOSE + ["up", "-d", "--no-build", "--wait", "--wait-timeout", "900", "misp-nginx"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
