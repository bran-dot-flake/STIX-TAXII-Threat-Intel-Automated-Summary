#!/usr/bin/env python3
"""Dependency-free static build. Only frontend allowlist + validated public JSON."""

import argparse
import json
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from ti_brief.publication import empty_snapshot, validate_snapshot

ROOT = Path(__file__).resolve().parents[1]
ASSETS = (
    "index.html",
    "styles.css",
    "app.js",
    "analytics.js",
    "assets/exploitation.svg",
    "assets/advisory.svg",
    "assets/favicon.svg",
    "assets/licenses/MITRE-ATTACK.txt",
    "assets/fonts/newsreader-latin-700.woff2",
    "assets/fonts/OFL-Newsreader.txt",
)


def build(source, output, demo=False):
    if demo and source:
        raise ValueError("Choose either demo or a real snapshot")
    if demo:
        source = ROOT / "examples/dashboard.synthetic.json"
    snapshot = (
        validate_snapshot(
            json.loads(source.read_text(encoding="utf-8")), allow_synthetic=demo
        )
        if source
        else empty_snapshot()
    )
    if demo:
        from ti_brief.briefing_public import enrich_snapshot
        from ti_brief.hybrid import refresh
        from ti_brief.stix_publication import empty_context

        snapshot["stix"] = snapshot.get("stix", empty_context())
        enrich_snapshot(snapshot)
        refresh(snapshot, config={"weekday": 2, "hour": 0, "update_hours": 48})
        from ti_brief.artwork import enrich as enrich_artwork

        enrich_artwork(snapshot)
        validate_snapshot(snapshot, allow_synthetic=True)
    if source and not snapshot["records"] and not snapshot["news"]:
        raise ValueError("Live build requires a nonempty validated publication")
    # Refuse stale, unrelated output files: artifact upload copies this directory.
    from ti_brief.artwork import asset_path

    artworks = {asset_path(a): a["svg"] for a in snapshot.get("illustrations", [])}
    allowed = {*ASSETS, *artworks, "snapshot.json", "build.json", ".nojekyll"}
    if output.exists():
        for path in output.rglob("*"):
            if path.is_symlink() or (
                path.is_file() and path.relative_to(output).as_posix() not in allowed
            ):
                raise ValueError("Unexpected file in build output")
    # No recursive copy, templated shell or raw report-directory inclusion.
    output.mkdir(parents=True, exist_ok=True)
    for name in ASSETS:
        target = output / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / "website" / name, target)
    for name, svg in artworks.items():
        target = output / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(svg, encoding="utf-8")
    (output / "snapshot.json").write_text(
        json.dumps(snapshot, ensure_ascii=False), encoding="utf-8"
    )
    (output / "build.json").write_text(
        json.dumps(
            {"built_at": datetime.now(timezone.utc).isoformat(timespec="seconds")}
        ),
        encoding="utf-8",
    )
    (output / ".nojekyll").write_text("", encoding="utf-8")
    print(
        json.dumps(
            {
                "status": "built",
                "records": len(snapshot["records"]),
                "briefs": len(snapshot["reports"]),
                "news": len(snapshot["news"]),
            }
        )
    )


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument(
        "--snapshot",
        type=Path,
        help="Validated public snapshot; omitted means clearly labeled empty development state",
    )
    p.add_argument("--output", type=Path, default=ROOT / "dist")
    p.add_argument(
        "--demo",
        action="store_true",
        help="Labeled synthetic fixture; never accepted by the live publisher",
    )
    args = p.parse_args()
    build(args.snapshot, args.output, args.demo)
