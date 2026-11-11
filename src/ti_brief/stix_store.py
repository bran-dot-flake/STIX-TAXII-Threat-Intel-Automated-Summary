"""Versioned STIX 2.1 storage, independent of the reporting database/platforms."""

import hashlib
import json
import re
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path

SDO = {
    "attack-pattern",
    "campaign",
    "course-of-action",
    "grouping",
    "identity",
    "indicator",
    "infrastructure",
    "intrusion-set",
    "location",
    "malware",
    "malware-analysis",
    "note",
    "observed-data",
    "opinion",
    "report",
    "threat-actor",
    "tool",
    "vulnerability",
    "relationship",
    "sighting",
}
SCO = {
    "artifact",
    "autonomous-system",
    "directory",
    "domain-name",
    "email-addr",
    "email-message",
    "file",
    "ipv4-addr",
    "ipv6-addr",
    "mac-addr",
    "mutex",
    "network-traffic",
    "process",
    "software",
    "url",
    "user-account",
    "windows-registry-key",
    "x509-certificate",
}


def stix_id(value, expected=None):
    if not isinstance(value, str) or "--" not in value:
        raise ValueError("Invalid STIX identifier")
    kind, uid = value.split("--", 1)
    if (
        not re.fullmatch(r"[a-z][a-z0-9-]+", kind)
        or str(uuid.UUID(uid)) != uid
        or (expected and kind != expected)
    ):
        raise ValueError("Invalid STIX identifier")
    return value


def timestamp(value):
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ValueError("STIX timestamp must be UTC")
    return datetime.fromisoformat(value.replace("Z", "+00:00")).isoformat(timespec="microseconds")


def parse_objects(value):
    """Use the OASIS parser, while rejecting silently defaulted required fields."""
    from stix2 import parse

    if isinstance(value, str):
        value = json.loads(value)
    if not isinstance(value, dict):
        raise ValueError("STIX object or bundle required")
    if value.get("type") == "bundle":
        stix_id(value.get("id"), "bundle")
        objects = value.get("objects")
    else:
        objects = [value]
    if not isinstance(objects, list) or len(objects) > 10000:
        raise ValueError("Invalid or oversized STIX batch")
    result = []
    for raw in objects:
        if not isinstance(raw, dict) or len(json.dumps(raw)) > 1_000_000:
            raise ValueError("Invalid or oversized STIX object")
        kind = raw.get("type")
        stix_id(raw.get("id"), kind)
        if raw.get("spec_version") != "2.1":
            raise ValueError("Only explicit STIX 2.1 objects are accepted")
        if kind in SDO or kind == "marking-definition":
            timestamp(raw.get("created"))
        if kind in SDO:
            if timestamp(raw.get("modified")) < timestamp(raw["created"]):
                raise ValueError("Modified precedes creation")
        if kind == "relationship":
            stix_id(raw.get("source_ref"))
            stix_id(raw.get("target_ref"))
        for ref in raw.get("object_refs", []) + raw.get("object_marking_refs", []):
            stix_id(ref)
        for key in ("revoked", "x_mitre_deprecated"):
            if key in raw and not isinstance(raw[key], bool):
                raise ValueError("Invalid lifecycle flag")
        # ATT&CK uses x_mitre_* extensions and custom SDOs. They are retained,
        # never implicitly converted into invented standard entities.
        parse(raw, version="2.1", allow_custom=True)
        result.append(raw)
    return result


class StixStore:
    def __init__(self, path):
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(path)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.executescript("""
          CREATE TABLE IF NOT EXISTS stix_objects (
            source TEXT, id TEXT, version TEXT, body TEXT NOT NULL, digest TEXT NOT NULL,
            first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, PRIMARY KEY(source,id,version));
          CREATE TABLE IF NOT EXISTS taxii_cursors (
            source TEXT, stream TEXT, state TEXT NOT NULL, PRIMARY KEY(source,stream));
          CREATE TABLE IF NOT EXISTS source_metadata (source TEXT PRIMARY KEY, body TEXT NOT NULL);
          CREATE TABLE IF NOT EXISTS platform_versions (
            source TEXT, id TEXT, version TEXT, platform TEXT, remote_id TEXT,
            PRIMARY KEY(source,id,platform));
          CREATE TABLE IF NOT EXISTS taxii_requests (origin TEXT, sent REAL);
          CREATE INDEX IF NOT EXISTS rate_window ON taxii_requests(origin,sent);
        """)

    def close(self):
        self.db.close()

    def state(self, source, stream):
        row = self.db.execute(
            "SELECT state FROM taxii_cursors WHERE source=? AND stream=?", (source, stream)
        ).fetchone()
        return json.loads(row[0]) if row else {}

    def ingest(self, source, objects, cursor=None, now=None):
        objects = parse_objects(
            {
                "type": "bundle",
                "id": "bundle--00000000-0000-4000-8000-000000000001",
                "objects": objects,
            }
        )
        now = now or datetime.now(timezone.utc).isoformat(timespec="seconds")
        added = 0
        # Object versions and the matching continuation cursor commit together.
        with self.db:
            for raw in objects:
                body = json.dumps(raw, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
                digest = hashlib.sha256(body.encode()).hexdigest()
                version = (
                    timestamp(raw["modified"])
                    if "modified" in raw
                    else timestamp(raw["created"]) if "created" in raw else digest
                )
                old = self.db.execute(
                    "SELECT digest FROM stix_objects WHERE source=? AND id=? AND version=?",
                    (source, raw["id"], version),
                ).fetchone()
                if old and old[0] != digest:
                    raise ValueError("Conflicting payload for the same STIX version")
                added += old is None
                self.db.execute(
                    """INSERT INTO stix_objects VALUES(?,?,?,?,?,?,?)
                    ON CONFLICT(source,id,version) DO UPDATE SET last_seen=excluded.last_seen""",
                    (source, raw["id"], version, body, digest, now, now),
                )
            if cursor:
                stream, state = cursor
                self.db.execute(
                    "INSERT OR REPLACE INTO taxii_cursors VALUES(?,?,?)",
                    (source, stream, json.dumps(state)),
                )
        return added

    def iter_latest(self, source, active_only=False):
        rows = self.db.execute(
            """SELECT * FROM (
          SELECT *,ROW_NUMBER() OVER(PARTITION BY id ORDER BY
            CASE WHEN json_extract(body,'$.modified') IS NULL AND json_extract(body,'$.created') IS NULL
            THEN rowid END DESC,version DESC) AS rank
          FROM stix_objects WHERE source=?) WHERE rank=1 ORDER BY id""",
            (source,),
        )
        for row in rows:
            raw = json.loads(row["body"])
            if not active_only or not (raw.get("revoked") or raw.get("x_mitre_deprecated")):
                yield raw

    def latest(self, source, active_only=False):
        return list(self.iter_latest(source, active_only))

    def count(self, source):
        return self.db.execute(
            "SELECT count(DISTINCT id) FROM stix_objects WHERE source=?", (source,)
        ).fetchone()[0]

    def metadata(self, source, value=None):
        if value is not None:
            with self.db:
                self.db.execute(
                    "INSERT OR REPLACE INTO source_metadata VALUES(?,?)",
                    (source, json.dumps(value)),
                )
        row = self.db.execute(
            "SELECT body FROM source_metadata WHERE source=?", (source,)
        ).fetchone()
        return json.loads(row[0]) if row else {}
