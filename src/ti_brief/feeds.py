"""Small explicit allowlist; intelligence URLs are never dereferenced."""
import csv
import io
import json
import re
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from .model import Record

KEV = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
FEODO = "https://feodotracker.abuse.ch/downloads/ipblocklist.csv"
CIRCL = "https://www.circl.lu/doc/misp/feed-osint/"


def kev_records(data, lookback_days=14, now=None):
    cutoff = ((now or datetime.now(timezone.utc)) - timedelta(days=lookback_days)).date().isoformat()
    rows = data["vulnerabilities"]
    if not isinstance(rows, list):
        raise ValueError("Invalid KEV catalog")
    for row in rows:
        if row["dateAdded"] < cutoff:
            continue
        yield Record(
            source="CISA KEV", source_url=KEV, kind="vulnerability", value=row["cveID"],
            title=row["vulnerabilityName"], description=row["shortDescription"],
            # KEV dateAdded is catalog entry date, not CVE disclosure/exploitation date.
            published_at=row["dateAdded"], action=row["requiredAction"], priority=90,
            confidence="CISA KEV listing; local exposure has not been assessed",
        )


def feodo_records(text, now=None):
    updated = re.search(r"# Last updated:\s*(\d{4}-\d{2}-\d{2})", text)
    if not updated:
        raise ValueError("Feodo source freshness timestamp missing")
    age = (now or datetime.now(timezone.utc)).date() - datetime.fromisoformat(updated[1]).date()
    if not 0 <= age.days <= 7:
        raise ValueError("Feodo feed is stale or future-dated; disabled until source freshness is restored")
    lines = (line for line in text.splitlines() if line.strip() and not line.startswith("#"))
    reader = csv.DictReader(lines, skipinitialspace=True)
    if not reader.fieldnames or not {"dst_ip", "dst_port", "c2_status", "first_seen_utc", "malware"}.issubset(reader.fieldnames):
        raise ValueError("Unexpected Feodo CSV schema")
    for row in reader:
        yield Record(
            source="abuse.ch Feodo Tracker", source_url=FEODO, kind="ip-dst", value=row["dst_ip"],
            title=f"Source-reported {row['malware']} infrastructure",
            description=f"Feodo reports {row['dst_ip']}:{row['dst_port']} with status {row['c2_status']} and malware label {row['malware']}.",
            occurred_at=row["first_seen_utc"].replace(" ", "T") + "+00:00", priority=60,
        )


def circl_records(http, lookback_days=14, max_events=3, max_attributes=20):
    manifest = http.json(CIRCL + "manifest.json")
    cutoff = (datetime.now(timezone.utc) - timedelta(days=lookback_days)).timestamp()
    entries = sorted(manifest.items(), key=lambda item: int(item[1]["timestamp"]), reverse=True)
    for raw_uid, metadata in entries[:max_events]:
        if int(metadata["timestamp"]) < cutoff:
            continue
        uid = str(uuid.UUID(raw_uid))  # Prevent paths/URLs in untrusted manifest keys.
        source_url = CIRCL + uid + ".json"
        event = http.json(source_url)["Event"]
        attributes = list(event.get("Attribute", []))
        for obj in event.get("Object", []):
            attributes.extend(obj.get("Attribute", []))
        emitted = 0
        for attr in attributes:
            kind = "ip-dst" if attr.get("type") == "ip-src" else attr.get("type")
            if kind not in {"ip-dst", "domain", "url", "md5", "sha1", "sha256", "vulnerability"}:
                continue
            published = event.get("publish_timestamp")
            try:
                record = Record(source="CIRCL OSINT / " + uid, source_url=source_url, kind=kind, value=attr["value"],
                    title=str(event["info"])[:200], description=str(attr.get("comment") or event["info"])[:1000],
                    published_at=datetime.fromtimestamp(int(published), timezone.utc).isoformat() if published and int(published) else None,
                    modified_at=datetime.fromtimestamp(int(metadata["timestamp"]), timezone.utc).isoformat(), priority=60)
            except ValueError:
                continue  # Composite values and invalid observables are not coerced into facts.
            yield record
            emitted += 1
            if emitted == max_attributes:
                break


def collect(http, names, lookback_days=14):
    result = []
    for name in names:
        if name == "cisa-kev":
            result.extend(kev_records(http.json(KEV), lookback_days))
        elif name == "feodo":
            result.extend(feodo_records(http.request(FEODO)))
        elif name == "circl-osint":
            result.extend(circl_records(http, lookback_days))
        else:
            raise ValueError(f"Unknown configured feed: {name}")
    return result


def demo_records():
    rows = json.loads((Path(__file__).parent / "demo.json").read_text(encoding="utf-8"))
    return [Record(**row) for row in rows]
