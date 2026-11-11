#!/usr/bin/env python3
"""Independent public-source export; optional outbound-only GitHub publication."""
import argparse
import json
import os
from pathlib import Path
from ti_brief.cli import load_env, run_lock
from ti_brief.http import Http
from ti_brief.publication import attach_briefs, collect_public, empty_snapshot, save_snapshot, validate_snapshot
from ti_brief.publish import DEFAULT_REPOSITORY, publish, read_remote
from ti_brief.stix_publication import empty_context, project_context
from ti_brief.briefing_public import enrich_snapshot


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--publish", action="store_true", help="Update only intel-data/snapshot.json and dispatch Pages")
    parser.add_argument("--output", type=Path, default=Path("data/publication/snapshot.json"))
    parser.add_argument("--reports-dir", type=Path, default=Path("reports/live"))
    args = parser.parse_args()
    load_env(Path(".env"))
    if os.name != "nt":
        os.umask(0o077)
    try:
        with run_lock(args.output.with_suffix(".lock")):
            repo = os.environ.get("TI_PUBLICATION_REPOSITORY", DEFAULT_REPOSITORY)
            previous = validate_snapshot(json.loads(args.output.read_text(encoding="utf-8"))) if args.output.exists() else None
            if previous is None and args.publish:
                previous = read_remote(repo)
            snapshot, originals = collect_public(Http(), previous or empty_snapshot())
            attach_briefs(snapshot, originals, args.reports_dir)
            enrich_snapshot(snapshot,Path('data/narrative'))
            try:
                snapshot['stix']=project_context(Path('data/stix/intelligence.sqlite3'),snapshot.get('stix'))
            except Exception as exc:
                print(json.dumps({'source':'mitre-enterprise','status':'cached','error_type':type(exc).__name__}))
                if snapshot['stix']['collected_at']:snapshot['stix']['status']='cached'
            save_snapshot(args.output, snapshot)
            result = {"status": "exported", "records": len(snapshot["records"]), "news": len(snapshot["news"]),
                "briefs": len(snapshot["reports"]), "sources": snapshot["sources"]}
            if args.publish:
                result.update(status="published-to-data-branch", commit=publish(snapshot, repo))
            print(json.dumps(result))
        return 0
    except Exception as exc:
        print(json.dumps({"status": "publication-failed", "error_type": type(exc).__name__}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
