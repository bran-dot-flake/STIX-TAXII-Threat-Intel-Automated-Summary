#!/usr/bin/env python3
"""One-shot, optional MITRE catalog bridge; no container/service management."""

import argparse
import json
import os
from pathlib import Path
from ti_brief.cli import load_env, required, run_lock
from ti_brief.http import Http
from ti_brief.stix_store import StixStore
from ti_brief.stix_platform import StixPlatform


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--max-objects", type=int, default=20)
    args = p.parse_args()
    if not 1 <= args.max_objects <= 50:
        p.error("Object bound must be 1..50")
    load_env(Path(".env"))
    if os.name != "nt":
        os.umask(0o077)
    store = None
    try:
        with run_lock(Path("data/stix/intelligence.lock")):
            store = StixStore(Path("data/stix/intelligence.sqlite3"))
            result = StixPlatform(
                Http(), required("OPENCTI_URL"), required("OPENCTI_TOKEN"), store
            ).synchronize(limit=args.max_objects)
            print(json.dumps({"status": "opencti-stix-synchronized", **result}))
            return 0
    except Exception as exc:
        print(json.dumps({"status": "opencti-stix-failed", "error_type": type(exc).__name__}))
        return 1
    finally:
        if store:
            store.close()


if __name__ == "__main__":
    raise SystemExit(main())
