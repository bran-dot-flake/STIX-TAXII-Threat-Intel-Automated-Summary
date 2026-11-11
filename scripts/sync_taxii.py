#!/usr/bin/env python3
"""One-shot STIX 2.1 import / bounded TAXII 2.1 synchronization."""

import argparse
import hashlib
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from ti_brief.cli import load_env, run_lock
from ti_brief.stix_store import StixStore, parse_objects
from ti_brief.taxii import DISCOVERY, ENTERPRISE, SOURCE, STREAMS, TaxiiClient, origin


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    modes = p.add_mutually_exclusive_group(required=True)
    modes.add_argument("--discover", action="store_true")
    modes.add_argument("--sync", action="store_true")
    modes.add_argument("--bundle", type=Path)
    p.add_argument("--discovery", default=DISCOVERY)
    p.add_argument("--root")
    p.add_argument("--collection", default=ENTERPRISE)
    p.add_argument("--source", default=SOURCE)
    p.add_argument("--database", type=Path, default=Path("data/stix/intelligence.sqlite3"))
    p.add_argument(
        "--max-pages", type=int, default=2, help="Per main stream; definitions use one page"
    )
    p.add_argument("--page-size", type=int, default=100)
    p.add_argument("--resolve", type=int, default=12, help="Maximum dependency fetches")
    p.add_argument("--types", help="Optional comma-separated STIX types for the entity stream")
    args = p.parse_args(argv)
    if (
        not 1 <= args.max_pages <= 6
        or not 1 <= args.page_size <= 200
        or not 0 <= args.resolve <= 20
    ):
        p.error("Bounds: pages 1..6, page size 1..200, resolve 0..20")
    if not re.fullmatch(r"[a-z0-9_-]{1,64}", args.source):
        p.error("Invalid source label")
    if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,160}", args.collection):
        p.error("Invalid collection identifier")
    streams = {**STREAMS}
    if args.types:
        chosen = args.types.split(",")
        if len(chosen) > 30 or not all(re.fullmatch(r"[a-z][a-z0-9-]{0,79}", t) for t in chosen):
            p.error("Invalid STIX type list")
        streams["entities"] = chosen
    if (
        args.source == SOURCE
        and not args.bundle
        and (args.discovery != DISCOVERY or args.collection != ENTERPRISE)
    ):
        p.error("Use a different --source label for non-MITRE/private collections")
    load_env(Path(".env"))
    if os.name != "nt":
        os.umask(0o077)
    store = None
    try:
        with run_lock(args.database.with_suffix(".lock")):
            store = StixStore(args.database)
            if args.bundle:
                if args.bundle.stat().st_size > 20_000_000:
                    raise ValueError("Bundle too large")
                objects = parse_objects(args.bundle.read_text(encoding="utf-8-sig"))
                label = "bundle-" + args.source
                added = store.ingest(label, objects)
                store.metadata(
                    label, {"public": False, "last_success": datetime.now(timezone.utc).isoformat()}
                )
                print(
                    json.dumps(
                        {
                            "status": "imported",
                            "source": label,
                            "objects": len(objects),
                            "new_versions": added,
                        }
                    )
                )
                return 0
            # Private-feed credentials must never accompany the default public
            # MITRE job, even when both are configured in the same environment.
            auth = (
                {}
                if origin(args.discovery) == origin(DISCOVERY)
                else {
                    "user": os.environ.get("TAXII_USER"),
                    "password": os.environ.get("TAXII_PASSWORD"),
                    "token": os.environ.get("TAXII_TOKEN"),
                }
            )
            client = TaxiiClient(args.discovery, store, args.source, **auth)
            try:
                if args.sync:
                    previous = store.metadata(args.source)
                    store.metadata(
                        args.source,
                        {
                            **previous,
                            "status": "syncing",
                            "last_attempt": datetime.now(timezone.utc).isoformat(
                                timespec="seconds"
                            ),
                        },
                    )
                discovery = client.discover(args.root)
                if args.discover:
                    # Do not echo private URLs or descriptions; IDs/titles only.
                    print(
                        json.dumps(
                            {"status": "discovered", "collections": discovery["collections"]}
                        )
                    )
                    return 0
                client.select(args.collection)
                generation = hashlib.sha256(
                    json.dumps(sorted(discovery["roots"])).encode()
                ).hexdigest()
                results = {}
                for name, types in streams.items():
                    results[name] = client.sync_stream(
                        name,
                        types,
                        1 if name == "definitions" else args.max_pages,
                        args.page_size,
                        generation,
                    )
                resolved = client.resolve(args.resolve) if args.resolve else 0
                public = (
                    args.discovery == DISCOVERY
                    and args.collection == ENTERPRISE
                    and args.source == SOURCE
                    and discovery["root"].rstrip("/") == "https://attack-taxii.mitre.org/api/v21"
                )
                store.metadata(
                    args.source,
                    {
                        "public": public,
                        "status": "ok",
                        "discovery": args.discovery,
                        "root": discovery["root"],
                        "collection": args.collection,
                        "last_success": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                        "generation": generation,
                        "streams": results,
                    },
                )
                print(
                    json.dumps(
                        {
                            "status": "synchronized",
                            "source": args.source,
                            "streams": results,
                            "dependency_requests": resolved,
                            "latest_objects": store.count(args.source),
                        }
                    )
                )
                return 0
            finally:
                client.conn.close()
    except Exception as exc:
        if store and not args.bundle:
            previous = store.metadata(args.source)
            store.metadata(
                args.source,
                {
                    **previous,
                    "status": "failed",
                    "last_attempt": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                },
            )
        print(json.dumps({"status": "stix-sync-failed", "error_type": type(exc).__name__}))
        return 1
    finally:
        if store:
            store.close()


if __name__ == "__main__":
    raise SystemExit(main())
