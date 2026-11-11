"""Bounded TAXII 2.1 client using OASIS taxii2-client endpoint/filter models."""

import json
import hashlib
import re
import time
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from email.message import Message
from urllib.parse import urlsplit

from .stix_store import stix_id

DISCOVERY = "https://attack-taxii.mitre.org/taxii2/"
ENTERPRISE = "x-mitre-collection--1f5f1533-f617-4ca8-9ab4-6a02367fa019"
SOURCE = "mitre-enterprise"
STREAMS = {
    "definitions": ["identity", "marking-definition"],
    "entities": [
        "attack-pattern",
        "intrusion-set",
        "malware",
        "tool",
        "report",
        "indicator",
        "vulnerability",
        "campaign",
        "threat-actor",
        "observed-data",
        "ipv4-addr",
        "ipv6-addr",
        "domain-name",
        "url",
        "file",
        "email-addr",
        "network-traffic",
    ],
    "relationships": ["relationship"],
}


class TaxiiError(RuntimeError):
    pass


class TaxiiDeferred(TaxiiError):
    pass


class TaxiiHTTPError(TaxiiError):
    def __init__(self, status):
        self.status = status
        super().__init__("TAXII HTTP request failed")


def origin(url):
    p = urlsplit(url)
    if p.scheme != "https" or not p.hostname or p.username or p.password or p.query or p.fragment:
        raise ValueError("TAXII endpoint requires HTTPS without URL credentials/query")
    return p.scheme, p.hostname.lower(), p.port or 443


class Connection:
    """Library connection interface with origin pinning, size/time/rate bounds.

    It deliberately exposes GET only. Discovery cannot redirect credentials to
    another origin. HTTP bodies/URLs/auth are never included in errors.
    """

    def __init__(
        self,
        url,
        store,
        user=None,
        password=None,
        token=None,
        timeout=25,
        sleeper=time.sleep,
        clock=time.time,
    ):
        import requests

        self.origin = origin(url)
        self.store = store
        self.session = requests.Session()
        self.session.trust_env = False
        if token and (user or password):
            raise ValueError("Choose bearer or basic authentication")
        if bool(user) != bool(password):
            raise ValueError("Basic authentication requires both fields")
        if user:
            self.session.auth = (user, password)
        if token:
            self.session.headers["Authorization"] = "Bearer " + token
        self.timeout, self.sleep, self.clock = timeout, sleeper, clock
        self.headers = {}

    def charge(self):
        key = json.dumps(self.origin)
        with self.store.db:
            now = self.clock()
            self.store.db.execute("DELETE FROM taxii_requests WHERE sent<?", (now - 600,))
            used = self.store.db.execute(
                "SELECT count(*) FROM taxii_requests WHERE origin=?", (key,)
            ).fetchone()[0]
            if used >= 35:
                raise TaxiiDeferred("TAXII request budget exhausted; resume later")
            self.store.db.execute("INSERT INTO taxii_requests VALUES(?,?)", (key, now))

    def get(self, url, headers=None, params=None):
        if origin(url) != self.origin:
            raise TaxiiError("Cross-origin TAXII endpoint rejected")
        for attempt in range(3):
            self.charge()
            try:
                response = self.session.get(
                    url,
                    params=params,
                    headers={
                        "Accept": "application/taxii+json;version=2.1",
                        "User-Agent": "EMBER/0.2",
                        **(headers or {}),
                    },
                    timeout=(self.timeout, self.timeout),
                    allow_redirects=False,
                    stream=True,
                )
                with response:
                    if response.status_code == 429 or response.status_code in {500, 502, 503, 504}:
                        retry = response.headers.get("Retry-After", str(2**attempt))
                        try:
                            wait = float(retry)
                        except ValueError:
                            wait = (
                                parsedate_to_datetime(retry) - datetime.now(timezone.utc)
                            ).total_seconds()
                        if wait > 45 or attempt == 2:
                            raise TaxiiDeferred("TAXII source requested a later retry")
                        self.sleep(max(0, wait))
                        continue
                    if not 200 <= response.status_code < 300:
                        raise TaxiiHTTPError(response.status_code)
                    media = Message()
                    media["Content-Type"] = response.headers.get("Content-Type", "")
                    if media.get_content_type() != "application/taxii+json" or media.get_param(
                        "version"
                    ) not in {None, "2.1"}:
                        raise TaxiiError("Unexpected TAXII media type")
                    chunks = []
                    total = 0
                    deadline = self.clock() + self.timeout
                    for chunk in response.iter_content(65536):
                        total += len(chunk)
                        if total > 8_000_000 or self.clock() > deadline:
                            raise TaxiiError("TAXII response exceeded bounds")
                        chunks.append(chunk)
                    self.headers = {k.lower(): v for k, v in response.headers.items()}
                    result = json.loads(b"".join(chunks))
                    if not isinstance(result, dict):
                        raise TaxiiError("Invalid TAXII envelope")
                    return result
            except (TaxiiError, ValueError):
                raise
            except Exception:
                if attempt == 2:
                    raise TaxiiError("TAXII connection failed") from None
                self.sleep(2**attempt)
        raise TaxiiError("TAXII retries exhausted")

    def close(self):
        self.session.close()


class TaxiiClient:
    def __init__(self, discovery, store, source, connection=None, **auth):
        from taxii2client.v21 import Server

        self.store, self.source, self.discovery = store, source, discovery
        self.conn = connection or Connection(discovery, store, **auth)
        self.server = Server(discovery, conn=self.conn)

    def discover(self, root_url=None):
        from taxii2client.v21 import ApiRoot

        roots = [r.url for r in self.server.api_roots]
        default = self.server.default.url if self.server.default else None
        selected = root_url or default
        if selected is None or selected.rstrip("/") not in {r.rstrip("/") for r in roots}:
            raise TaxiiError("Select a discovered TAXII API root")
        if origin(selected) != origin(self.discovery):
            raise TaxiiError("Cross-origin API root rejected")
        self.root = ApiRoot(selected, conn=self.conn)
        if "application/taxii+json;version=2.1" not in self.root.versions:
            raise TaxiiError("API root does not support TAXII 2.1")
        collections = self.root.collections
        # Discovery is read-only. No object pulls occur until explicit selection.
        return {
            "root": self.root.url,
            "roots": roots,
            "collections": [
                {"id": c.id, "title": c.title, "can_read": c.can_read} for c in collections
            ],
        }

    def select(self, collection_id):
        match = next(
            (c for c in self.root.collections if c.id == collection_id and c.can_read), None
        )
        if match is None:
            raise TaxiiError("Readable selected collection not found")
        self.collection = match

    def sync_stream(self, name, types, max_pages=2, page_size=100, generation=""):
        generation += ":" + hashlib.sha256(json.dumps([types, page_size]).encode()).hexdigest()
        state = self.store.state(self.source, name)
        # A changed discovered release set triggers bounded replay, not daily
        # full downloads. This also protects against old MITRE date_added values.
        if state.get("generation") != generation:
            state = {"generation": generation}
        pages = added = received = 0
        for _ in range(max_pages):
            filters = {"type": types, "limit": page_size, "version": "last"}
            if state.get("after"):
                filters["added_after"] = state["after"]
            if state.get("next"):
                filters["next"] = state["next"]
            try:
                envelope = self.collection.get_objects(**filters)
            except TaxiiHTTPError as exc:
                if state.get("next") and exc.status in {400, 404}:
                    state.pop("next", None)
                    state.pop("high", None)
                    self.store.ingest(self.source, [], (name, state))
                    raise TaxiiDeferred("Continuation expired; safe replay queued") from None
                raise
            objects = envelope.get("objects")
            if (
                not isinstance(objects, list)
                or len(objects) > page_size
                or not isinstance(envelope.get("more", False), bool)
            ):
                raise TaxiiError("Invalid bounded TAXII page")
            more = envelope.get("more", False)
            if more and not objects:
                raise TaxiiError("Empty continuation page")
            token = envelope.get("next")
            if more and (
                not isinstance(token, str)
                or not token
                or len(token) > 2048
                or token == state.get("next")
            ):
                raise TaxiiError("Missing or repeated TAXII continuation")
            latest = self.conn.headers.get("x-taxii-date-added-last")
            high = state.get("high")
            if latest:
                try:
                    parsed = datetime.fromisoformat(latest.replace("Z", "+00:00"))
                    if parsed.tzinfo is None:
                        raise ValueError()
                    if parsed > datetime.now(timezone.utc) + timedelta(minutes=5):
                        raise ValueError()
                    latest = parsed.astimezone(timezone.utc).isoformat(timespec="microseconds")
                except ValueError:
                    raise TaxiiError("Invalid TAXII date-added header") from None
                high = max(filter(None, [high, latest]))
            elif objects:
                raise TaxiiError("TAXII date-added header is required for safe checkpoints")
            next_state = {**state, "high": high, "next": token if more else None}
            if not more:
                if high:
                    # Inclusive boundary overlap is intentional; exact object
                    # versions deduplicate it, including equal timestamps.
                    next_state["after"] = (
                        (datetime.fromisoformat(high) - timedelta(seconds=1))
                        .isoformat()
                        .replace("+00:00", "Z")
                    )
                next_state.pop("high", None)
            added += self.store.ingest(self.source, objects, (name, next_state))
            pages += 1
            received += len(objects)
            state = next_state
            if not more:
                break
        return {
            "pages": pages,
            "received": received,
            "new_versions": added,
            "pending": bool(state.get("next")),
        }

    def resolve(self, limit=12):
        """Bounded endpoint/marking lookups. Dangling relations stay unasserted."""
        if limit <= 0:
            return 0
        known = {
            row[0]
            for row in self.store.db.execute(
                "SELECT DISTINCT id FROM stix_objects WHERE source=?", (self.source,)
            )
        }
        markings = []
        endpoints = []
        for obj in self.store.iter_latest(self.source):
            markings.extend(obj.get("object_marking_refs", []))
            if obj["type"] == "relationship":
                endpoints.extend([obj["source_ref"], obj["target_ref"]])
        fetched = 0
        for uid in dict.fromkeys(markings + endpoints):
            if uid in known:
                continue
            if fetched >= limit:
                break
            stix_id(uid)
            fetched += 1
            try:
                raw = self.collection.get_object(uid, version="last")
            except TaxiiHTTPError as exc:
                if exc.status == 404:
                    known.add(uid)
                    print(json.dumps({"stage": "taxii-dependency", "status": "not-found"}))
                    continue
                raise
            objects = raw.get("objects", [])
            if len(objects) > 10 or any(o.get("id") != uid for o in objects):
                raise TaxiiError("Unexpected dependency response")
            self.store.ingest(self.source, objects)
            known.add(uid)
        return fetched
