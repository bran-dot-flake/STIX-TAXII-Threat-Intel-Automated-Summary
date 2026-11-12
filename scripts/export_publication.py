#!/usr/bin/env python3
"""Independent public-source export; optional outbound-only GitHub publication."""

import argparse
import json
import os
from pathlib import Path
from datetime import datetime, timezone
from ti_brief.cli import load_env, run_lock
from ti_brief.http import Http
from ti_brief.publication import (
    collect_public,
    empty_snapshot,
    save_snapshot,
    validate_snapshot,
)
from ti_brief.publish import DEFAULT_REPOSITORY, publish, read_remote
from ti_brief.stix_publication import project_context
from ti_brief.briefing_public import enrich_snapshot
from ti_brief.executive import prepare, refresh
from ti_brief.artwork import enrich as enrich_artwork


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    publication = parser.add_mutually_exclusive_group()
    publication.add_argument(
        "--publish",
        action="store_true",
        help="Collect, then update only intel-data/snapshot.json and dispatch Pages",
    )
    publication.add_argument(
        "--publish-prepared",
        action="store_true",
        help="Publish the validated collected snapshot with a matching editorial composition; no recollection",
    )
    parser.add_argument(
        "--output", type=Path, default=Path("data/publication/snapshot.json")
    )
    parser.add_argument("--reports-dir", type=Path, default=Path("reports/live"))
    parser.add_argument(
        "--revise-latest",
        action="store_true",
        help="Explicitly replace the latest weekly article using its frozen evidence and a checked review; preserve publication date",
    )
    args = parser.parse_args()
    if args.revise_latest and not args.publish_prepared:
        parser.error("--revise-latest requires --publish-prepared")
    load_env(Path(".env"))
    if os.name != "nt":
        os.umask(0o077)
    try:
        with run_lock(args.output.with_suffix(".lock")):
            repo = os.environ.get("TI_PUBLICATION_REPOSITORY", DEFAULT_REPOSITORY)
            previous = (
                validate_snapshot(json.loads(args.output.read_text(encoding="utf-8")))
                if args.output.exists()
                else None
            )
            if args.publish_prepared:
                if previous is None:
                    raise ValueError("No prepared public snapshot")
                if (
                    not 0
                    <= (
                        datetime.now(timezone.utc)
                        - datetime.fromisoformat(previous["exported_at"])
                    ).total_seconds()
                    <= 86400
                ):
                    raise ValueError("Prepared public snapshot expired")
                enrich_snapshot(previous)
                refresh(
                    previous,
                    Path("data/editorial"),
                    published_at=datetime.now(timezone.utc).isoformat(
                        timespec="seconds"
                    ),
                    revision=args.revise_latest,
                )
                # Accepted editorial state advances only after the public data
                # commit succeeds. A failed upload leaves the collected file intact.
                enrich_artwork(previous)
                commit = publish(previous, repo)
                save_snapshot(args.output, previous)
                print(
                    json.dumps(
                        {
                            "status": "published-prepared",
                            "commit": commit,
                            "collection": previous.get("collection"),
                        }
                    )
                )
                return 0
            if previous is None and args.publish:
                previous = read_remote(repo)
            snapshot, originals = collect_public(Http(), previous or empty_snapshot())
            # Keep accepted legacy public evidence; private daily batch reports
            # remain private and never become additional editorial editions.
            enrich_snapshot(snapshot, Path("data/narrative"))
            try:
                snapshot["stix"] = project_context(
                    Path("data/stix/intelligence.sqlite3"), snapshot.get("stix")
                )
            except Exception as exc:
                print(
                    json.dumps(
                        {
                            "source": "mitre-enterprise",
                            "status": "cached",
                            "error_type": type(exc).__name__,
                        }
                    )
                )
                if snapshot["stix"]["collected_at"]:
                    snapshot["stix"]["status"] = "cached"
            prepare(snapshot)
            enrich_artwork(snapshot)
            save_snapshot(args.output, snapshot)
            result = {
                "status": "exported",
                "records": len(snapshot["records"]),
                "news": len(snapshot["news"]),
                "briefs": len(snapshot["reports"]),
                "sources": snapshot["sources"],
            }
            if args.publish:
                refresh(
                    snapshot,
                    Path("data/editorial"),
                    published_at=datetime.now(timezone.utc).isoformat(
                        timespec="seconds"
                    ),
                )
                enrich_artwork(snapshot)
                result.update(
                    status="published-to-data-branch", commit=publish(snapshot, repo)
                )
                save_snapshot(args.output, snapshot)
            print(json.dumps(result))
        return 0
    except Exception as exc:
        print(
            json.dumps(
                {"status": "publication-failed", "error_type": type(exc).__name__}
            )
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
