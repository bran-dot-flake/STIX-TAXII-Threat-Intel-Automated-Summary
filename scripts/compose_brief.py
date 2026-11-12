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
    parser.add_argument(
        "--snapshot", type=Path, default=Path("data/publication/snapshot.json")
    )
    parser.add_argument("--cache-dir", type=Path)
    parser.add_argument(
        "--editorial",
        action="store_true",
        help="Compose the publication-wide edition, independent of the private batch",
    )
    args = parser.parse_args()
    args.cache_dir = args.cache_dir or Path(
        "data/editorial" if args.editorial else "data/narrative"
    )
    load_env(Path(".env"))
    if os.name != "nt":
        os.umask(0o077)
    try:
        with run_lock(args.cache_dir / "compose.lock"):
            snapshot = validate_snapshot(
                json.loads(args.snapshot.read_text(encoding="utf-8"))
            )
            if args.editorial:
                from ti_brief.editorial import (
                    compose as compose_editorial,
                    edition,
                    curate,
                    DraftRequiresReview,
                )

                if snapshot["schema_version"] == 5:
                    from ti_brief.hybrid import candidate

                    package = candidate(snapshot)
                    if package is None:
                        print(
                            json.dumps(
                                {
                                    "status": "editorial-not-due",
                                    "collection": snapshot["collection"]["status"],
                                }
                            )
                        )
                        return 0
                else:
                    package = curate(snapshot)
                result = edition(package)
                cache = args.cache_dir / (result["id"] + ".json")
                if cache.exists():
                    from ti_brief.editorial import validate_edition

                    try:
                        cached = validate_edition(
                            json.loads(cache.read_text(encoding="utf-8"))
                        )
                        if cached["input_digest"] == result["input_digest"]:
                            print(
                                json.dumps(
                                    {
                                        "status": "editorial-already-composed",
                                        "mode": cached["mode"],
                                    }
                                )
                            )
                            return 0
                    except (OSError, ValueError, KeyError, TypeError):
                        pass
                try:
                    if Path("/proc/meminfo").exists():
                        mem = dict(
                            line.split(":", 1)
                            for line in Path("/proc/meminfo").read_text().splitlines()
                        )
                        if int(mem["MemAvailable"].split()[0]) < 3500 * 1024:
                            raise RuntimeError(
                                "Insufficient available memory for editorial inference"
                            )
                    result = compose_editorial(
                        Http(timeout=900, retries=0),
                        os.environ.get("OLLAMA_URL", "http://127.0.0.1:11434"),
                        required("OLLAMA_MODEL"),
                        package,
                    )
                except DraftRequiresReview as exc:
                    atomic_write(
                        args.cache_dir
                        / "review"
                        / f"{result['id']}-{result['input_digest'][:16]}.json",
                        json.dumps(
                            {
                                "status": "requires-review",
                                "input_digest": result["input_digest"],
                                "draft": exc.draft,
                            },
                            ensure_ascii=False,
                            indent=2,
                        ),
                    )
                    if exc.accepted is not None:
                        result = exc.accepted
                except (RuntimeError, ValueError, KeyError, TypeError) as exc:
                    print(
                        json.dumps(
                            {
                                "stage": "editorial",
                                "status": "source-grounded-fallback",
                                "error_type": type(exc).__name__,
                            }
                        )
                    )
                atomic_write(
                    args.cache_dir / (result["id"] + ".json"),
                    json.dumps(result, ensure_ascii=False, indent=2) + "\n",
                )
                print(
                    json.dumps(
                        {
                            "status": "editorial-composed",
                            "mode": result["mode"],
                            "topics": len(result["topics"]),
                        }
                    )
                )
                return 0
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
                    {
                        "status": "composed",
                        "report": report["id"],
                        "mode": narrative["mode"],
                    }
                )
            )
            return 0
    except Exception as exc:
        print(
            json.dumps(
                {"status": "narrative-withheld", "error_type": type(exc).__name__}
            )
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
