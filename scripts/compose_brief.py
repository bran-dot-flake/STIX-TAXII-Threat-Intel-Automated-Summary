#!/usr/bin/env python3
"""Compose a bounded narrative for one already sanitized public edition."""

import argparse
import json
import os
from pathlib import Path
from ti_brief.cli import load_env, required, run_lock
from ti_brief.http import Http
from ti_brief.publication import validate_snapshot
from ti_brief.briefing_public import enrich_snapshot
from ti_brief.narrative import compose
from ti_brief.report import atomic_write


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snapshot", type=Path, default=Path("data/publication/snapshot.json"))
    parser.add_argument("--cache-dir", type=Path, default=Path("data/narrative"))
    args = parser.parse_args()
    load_env(Path(".env"))
    if os.name != "nt":
        os.umask(0o077)
    try:
        with run_lock(args.cache_dir / "compose.lock"):
            snapshot = validate_snapshot(json.loads(args.snapshot.read_text(encoding="utf-8")))
            enrich_snapshot(snapshot)
            if not snapshot["reports"]:
                raise ValueError("No public edition available")
            report = snapshot["reports"][0]
            narrative = compose(
                Http(timeout=600, retries=0),
                os.environ.get("OLLAMA_URL", "http://127.0.0.1:11434"),
                required("OLLAMA_MODEL"),
                report,
            )
            atomic_write(
                args.cache_dir / (report["id"] + ".json"),
                json.dumps(narrative, ensure_ascii=False, indent=2) + "\n",
            )
            print(
                json.dumps(
                    {"status": "composed", "report": report["id"], "mode": narrative["mode"]}
                )
            )
            return 0
    except Exception as exc:
        print(json.dumps({"status": "narrative-withheld", "error_type": type(exc).__name__}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
