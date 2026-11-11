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


def parse_args(argv=None):
    p = argparse.ArgumentParser()
    p.add_argument("--manage-project", action="store_true", help="Explicit consent to start/stop only ti-lab containers")
    args = p.parse_args(argv)
    if not args.manage_project:
        p.error("Requires explicit --manage-project after lab deployment approval")
    return args


def orchestrate(args=None):
    args = args or parse_args()
    load_env(Path(".env"))
    for key in ("MISP_API_KEY", "OPENCTI_TOKEN", "OLLAMA_MODEL"):
        required(key)
    resident = os.environ.get("TI_RESIDENT_PROFILE", "misp")
    if resident not in {"misp", "all"}:
        raise ValueError("TI_RESIDENT_PROFILE must be misp or all")
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
        # Restore both UIs only when the operator selected the measured all profile.
        profiles = ["misp", "opencti", "integration"] if resident == "all" else ["misp"]
        invoke([sys.executable, "scripts/preflight.py", *profiles])
        targets = [] if resident == "all" else ["misp-nginx"]
        invoke(COMPOSE + ["up", "-d", "--no-build", "--wait", "--wait-timeout", "900", *targets])
    return 0


def main(argv=None):
    args = parse_args(argv)
    load_env(Path('.env'))
    if os.environ.get('TI_TAXII_ENABLED')=='true':
        try:
            invoke([os.environ.get('TI_STIX_PYTHON',sys.executable),'scripts/sync_taxii.py','--sync'])
        except Exception as exc:
            print(json.dumps({'stage':'taxii','status':'failed-retaining-cache','error_type':type(exc).__name__}))
    # Public collection is independent: preserve the website even if a local
    # integration fails. The existing report exit status remains visible.
    try:
        return orchestrate(args)
    finally:
        if os.environ.get('TI_STIX_OPENCTI_ENABLED')=='true':
            try:
                invoke([sys.executable,'scripts/sync_stix_opencti.py','--max-objects','20'])
            except Exception as exc:
                print(json.dumps({'stage':'stix-opencti','status':'failed','error_type':type(exc).__name__}))
        if os.environ.get("TI_PUBLICATION_ENABLED") == "true":
            invoke([sys.executable, "scripts/export_publication.py", "--publish"])


if __name__ == "__main__":
    raise SystemExit(main())
