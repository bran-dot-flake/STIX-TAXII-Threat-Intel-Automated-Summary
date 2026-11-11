"""Editorial topics and chronology. Shared source provenance is not attribution."""

import hashlib
import json
import re
from dataclasses import asdict
from datetime import datetime, timedelta, timezone

EVENT = re.compile(r"https://www\.circl\.lu/doc/misp/feed-osint/[0-9a-f-]{36}\.json\Z")
DEFAULT_ACTION = "Review indicator against local telemetry before taking action."
KEV = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
FRESHNESS = {
    "catalog-added": 0,
    "newly-published": 0,
    "source-updated": 1,
    "newly-collected-history": 2,
    "historical-context": 3,
    "undated": 4,
}


def instant(value):
    result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return (
        result.replace(tzinfo=timezone.utc)
        if result.tzinfo is None
        else result.astimezone(timezone.utc)
    )


def reporting_window(generated):
    end = instant(generated)
    start = (end - timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
    return start, end


def content_version(record):
    # Source republishing/manifest clocks alone do not create another story.
    value = asdict(record)
    for key in ("published_at", "modified_at", "occurred_at"):
        value.pop(key)
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


def topic_key(row):
    if row["kind"] == "vulnerability":
        return "cve:" + row["value"].upper()
    if EVENT.fullmatch(row["source_url"]):
        return "event:" + row["source_url"]
    # A whole CSV/catalog URL or matching actor name is not a shared report.
    return "observation:" + row["id"]


def row_from_record(record, chronology=None):
    value = asdict(record)
    value.update(
        id=record.key,
        source=(
            "cisa-kev"
            if record.source == "CISA KEV"
            else "circl-osint" if EVENT.fullmatch(record.source_url) else record.source
        ),
        first_seen=None,
        last_seen=None,
        content_changed_at=None,
        known_content_change=False,
    )
    value.update(chronology or {})
    return value


def observation(record, chronology=None):
    from .report import excerpt_options

    row = row_from_record(record, chronology)
    choices = excerpt_options(record)
    excerpt = (
        record.title
        if row["source"] == "circl-osint"
        else next((s for s in choices if s != record.title), choices[0])
    )
    fields = {
        "id",
        "source",
        "source_url",
        "kind",
        "value",
        "title",
        "action",
        "published_at",
        "modified_at",
        "first_seen",
        "last_seen",
        "content_changed_at",
        "known_content_change",
    }
    result = {k: row[k] for k in fields}
    result["value"] = (
        record.value.replace("https://", "hxxps://")
        .replace("http://", "hxxp://")
        .replace(".", "[.]")
    )
    result["excerpt"] = excerpt
    return result


def freshness(row, generated):
    start, end = reporting_window(generated)
    published = instant(row["published_at"]) if row.get("published_at") else None
    # Day-only source dates are labeled catalog dates, never attack times.
    if published and start <= published <= end:
        return "catalog-added" if row["source"] == "cisa-kev" else "newly-published"
    modified = instant(row["modified_at"]) if row.get("modified_at") else None
    changed = instant(row["content_changed_at"]) if row.get("content_changed_at") else None
    if (
        row.get("known_content_change")
        and modified
        and changed
        and start <= modified <= end
        and start <= changed <= end
    ):
        return "source-updated"
    first = instant(row["first_seen"]) if row.get("first_seen") else None
    if first and start <= first <= end:
        return "newly-collected-history" if published or modified else "undated"
    return "historical-context" if published or modified else "undated"


def group_topics(rows, generated):
    groups = {}
    seen = {}
    conflicts = set()
    for row in rows:
        if row["id"] in seen:
            if row != seen[row["id"]]:
                conflicts.add(topic_key(row))
                conflicts.add(topic_key(seen[row["id"]]))
            continue
        seen[row["id"]] = row
        groups.setdefault(topic_key(row), []).append(row)
    result = []
    for key, members in groups.items():
        members = sorted(members, key=lambda row: row["id"])
        conflict = key in conflicts or (
            key.startswith("event:") and len({row["title"] for row in members}) != 1
        )
        statuses = [freshness(row, generated) for row in members]
        category = min(statuses, key=lambda value: FRESHNESS[value])
        result.append(
            {
                "id": hashlib.sha256(key.encode()).hexdigest()[:24],
                "title": members[0]["title"],
                "evidence_ids": [row["id"] for row in members],
                "freshness": category,
                "conflicting": conflict,
                "records": members,
            }
        )
    return sorted(
        result,
        key=lambda topic: (
            FRESHNESS[topic["freshness"]],
            -max(
                (instant(r["published_at"]).timestamp() if r.get("published_at") else 0)
                for r in topic["records"]
            ),
            topic["id"],
        ),
    )


def select_records(records, store, generated, limit=8, max_topics=4):
    lookup = {r.key: r for r in records}
    rows = [row_from_record(r, store.chronology(r)) for r in records]
    topics = group_topics(rows, generated)[:max_topics]
    # Reserve a place for every selected topic before filling IOC evidence.
    selected = [t["evidence_ids"][0] for t in topics][:limit]
    for topic in topics:
        for key in topic["evidence_ids"][1:]:
            if len(selected) >= limit:
                break
            selected.append(key)
    return [lookup[key] for key in selected]


def topic_label(topic):
    row = topic["records"][0]
    if topic["conflicting"]:
        return "Source metadata requires review"
    if row["kind"] != "vulnerability":
        title = row["title"].split(":", 1)[0].strip()
        return title if len(title) <= 75 else "Public source report"
    prefix = re.split(
        r"\b(?:Improper|Unexpected|Unchecked|Missing|Insufficient|Unrestricted|Uncontrolled|Use.After.Free|Out.of.bounds|Buffer|SQL|Command|Path|Directory|Cross.Site)\b",
        row["title"],
        maxsplit=1,
        flags=re.I,
    )[0].strip()
    words = prefix.split()
    if len(words) > 7:
        prefix = " ".join(words[:4])
    return prefix or row["value"]
