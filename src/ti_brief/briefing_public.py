"""Projection and validation of the public narrative; no platform context crosses here."""

import json
from pathlib import Path
from .narrative import make_narrative, validate_narrative
from .topics import observation

CHRONOLOGY = {
    "modified_at",
    "first_seen",
    "last_seen",
    "content_changed_at",
    "known_content_change",
}


def promote_observations(raw, matched, generated):
    from .publication import exact_fields, ITEM_FIELDS, stamp, validate_item, clean_text

    supplied = raw.get("observations")
    if supplied is not None and (not isinstance(supplied, list) or len(supplied) != len(matched)):
        raise ValueError("Observation coverage changed")
    rows = []
    for index, record in enumerate(matched):
        chronology = {}
        if supplied is not None:
            item = supplied[index]
            exact_fields(item, ITEM_FIELDS | CHRONOLOGY)
            chronology = {k: item[k] for k in CHRONOLOGY - {"modified_at"}}
        row = observation(record, chronology)
        if supplied is not None and row != supplied[index]:
            raise ValueError("Observation differs from original source projection")
        validate_observation(row, generated)
        rows.append(row)
    return rows


def validate_observation(row, generated):
    from .publication import exact_fields, ITEM_FIELDS, stamp, validate_item, clean_text

    exact_fields(row, ITEM_FIELDS | CHRONOLOGY)
    validate_item(row)
    clean_text(row["excerpt"], 240)
    if row["source"] == "circl-osint" and (
        row["excerpt"] != row["title"] or len(row["excerpt"].split()) > 25
    ):
        raise ValueError("CIRCL narrative evidence must remain a short source title")
    if row["published_at"] and stamp(row["published_at"]) > stamp(generated):
        raise ValueError("Source publication postdates report")
    if type(row["known_content_change"]) is not bool:
        raise ValueError("Invalid content-change flag")
    for key in CHRONOLOGY - {"known_content_change"}:
        if row[key] is not None and stamp(row[key]) > stamp(generated):
            raise ValueError("Future observation chronology")
    if (row["first_seen"] is None) != (row["last_seen"] is None):
        raise ValueError("Incomplete collection interval")
    if row["first_seen"] and stamp(row["first_seen"]) > stamp(row["last_seen"]):
        raise ValueError("Invalid collection interval")
    if row["known_content_change"] != bool(row["content_changed_at"]):
        raise ValueError("Missing substantive-change evidence")
    return row


def enrich(report, candidate=None):
    """Upgrade legacy history conservatively, without inventing collection dates."""
    if "observations" not in report:
        report["observations"] = [
            {
                **item,
                "modified_at": None,
                "first_seen": None,
                "last_seen": None,
                "content_changed_at": None,
                "known_content_change": False,
            }
            for item in report["items"]
        ]
    previous = candidate or report.get("narrative")
    try:
        report["narrative"] = validate_narrative(previous, report)
    except (ValueError, TypeError, KeyError, AttributeError):
        report["narrative"] = make_narrative(report)
    return report


def enrich_snapshot(snapshot, cache_dir=None):
    for report in snapshot["reports"]:
        candidate = None
        if cache_dir:
            try:
                candidate = json.loads(
                    (Path(cache_dir) / (report["id"] + ".json")).read_text(encoding="utf-8")
                )
            except (OSError, ValueError):
                pass
        enrich(report, candidate)
    snapshot["schema_version"] = 4 if snapshot.get('schema_version')==4 else 3
    return snapshot
