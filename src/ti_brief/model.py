import hashlib
import ipaddress
import json
import re
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from urllib.parse import urlsplit


def utcnow():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def canonical(kind, value):
    value = str(value).strip()
    if kind == "ip-dst":
        return str(ipaddress.ip_address(value))
    if kind == "domain":
        value = value.rstrip(".").lower().encode("idna").decode()
        if len(value) > 253 or not all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", x) for x in value.split(".")):
            raise ValueError("Invalid domain")
    elif kind == "url":
        p = urlsplit(value)
        if p.scheme not in {"http", "https"} or not p.hostname or p.username or p.password:
            raise ValueError("Invalid URL")
    elif kind in {"md5", "sha1", "sha256"}:
        value = value.lower()
        if not re.fullmatch(r"[0-9a-f]{%d}" % {"md5": 32, "sha1": 40, "sha256": 64}[kind], value):
            raise ValueError("Invalid hash")
    elif kind == "vulnerability":
        value = value.upper()
        if not re.fullmatch(r"CVE-\d{4}-\d{4,}", value):
            raise ValueError("Invalid CVE")
    elif kind not in {"domain", "url"}:
        raise ValueError("Unsupported indicator type")
    return value


@dataclass(frozen=True)
class Record:
    source: str
    source_url: str
    kind: str
    value: str
    title: str
    description: str
    published_at: str | None = None
    occurred_at: str | None = None
    modified_at: str | None = None
    action: str = "Review indicator against local telemetry before taking action."
    priority: int = 50
    confidence: str = "Source-reported; not independently verified"

    def __post_init__(self):
        object.__setattr__(self, "value", canonical(self.kind, self.value))
        p = urlsplit(self.source_url)
        if p.scheme != "https" or not p.hostname or p.username or p.password:
            raise ValueError("Evidence source must be an HTTPS URL without credentials")
        for field in (self.source, self.title, self.description, self.action):
            if not isinstance(field, str) or len(field) > 4000:
                raise ValueError("Invalid or oversized evidence field")
        for stamp in (self.published_at, self.occurred_at, self.modified_at):
            if stamp is not None:
                datetime.fromisoformat(stamp.replace("Z", "+00:00"))
        if not 0 <= self.priority <= 100:
            raise ValueError("Priority out of range")

    @property
    def key(self):
        # One observation per source; independent corroboration is preserved.
        return hashlib.sha256(f"{self.source}|{self.kind}|{self.value}".encode()).hexdigest()[:24]

    @property
    def version(self):
        return hashlib.sha256(json.dumps(asdict(self), sort_keys=True).encode()).hexdigest()
