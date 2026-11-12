"""Bounded official RSS metadata. Never fetch articles or content:encoded bodies."""

import hashlib
import json
import re
import xml.etree.ElementTree as ET
from datetime import timedelta, timezone
from email.utils import parsedate_to_datetime

FEEDS = {
    "sans-isc": {
        "url": "https://isc.sans.edu/rssfeed.xml",
        "host": "isc.sans.edu",
        "publisher": "SANS Technology Institute, Internet Storm Center",
        "license": "https://creativecommons.org/licenses/by-nc-sa/4.0/",
        "terms": "https://isc.sans.edu/linkback.html",
    },
    "cisco-talos": {
        "url": "https://blog.talosintelligence.com/rss/",
        "host": "blog.talosintelligence.com",
        "publisher": "Cisco Talos",
        "license": "https://www.cisco.com/c/en/us/about/legal/terms-conditions.html",
        "terms": "https://www.cisco.com/c/en/us/about/legal/terms-conditions.html",
    },
    "google-gti": {
        "url": "https://cloudblog.withgoogle.com/topics/threat-intelligence/rss/",
        "host": "cloud.google.com",
        "publisher": "Google Threat Intelligence Group",
        "license": "https://policies.google.com/terms",
        "terms": "https://policies.google.com/terms",
    },
}
EXTRA_FIELDS = {
    "publisher",
    "author",
    "license",
    "modified_at",
    "first_seen",
    "last_seen",
    "content_changed_at",
    "source_id",
    "references",
}
CATEGORIES = {
    "Malware research",
    "Campaign reporting",
    "Phishing",
    "Vulnerability research",
    "Security research",
}


def category(text):
    """Classify report subject, not incidents, victims, actor identity or volume."""
    text = text.lower()
    if re.search(r"phish|credential theft|vishing|smishing", text):
        return "Phishing"
    if re.search(
        r"ransomware|malware|infostealer|backdoor|\btrojan\b|\bloader\b", text
    ):
        return "Malware research"
    if re.search(r"campaign|threat actor|intrusion|espionage", text):
        return "Campaign reporting"
    if re.search(r"CVE-\d|vulnerabilit|exploitation|patch tuesday", text, re.I):
        return "Vulnerability research"
    return "Security research"


def relevant(title, excerpt):
    if re.search(
        r"stormcast|podcast|webinar|newsletter|\bconference\b|humans of talos|lessons from it-sa|from federal socs to talos",
        title,
        re.I,
    ):
        return False
    return bool(
        re.search(
            r"malware|ransomware|campaign|phish|exploit|CVE-\d|credential|vulnerabilit|backdoor|intrusion|threat actor|botnet|webshell|supply.chain|security research|patch|command.and.control|compromised",
            title + " " + excerpt,
            re.I,
        )
    )


def fingerprint(row):
    # Exclude fetch clocks, author edits and other metadata-only changes.
    return hashlib.sha256(
        json.dumps(
            {
                k: row.get(k)
                for k in (
                    "source_url",
                    "title",
                    "excerpt",
                    "description",
                    "action",
                    "value",
                )
            },
            sort_keys=True,
        ).encode()
    ).hexdigest()


def items(raw, source, now, previous=()):
    from .publication import TextOnly, clean_text, source_url, stamp
    from .narrative import INJECTION

    if re.search(r"<!\s*(?:DOCTYPE|ENTITY)", raw, re.I):
        raise ValueError("Unsafe research XML")
    root = ET.fromstring(raw)
    if root.tag != "rss" or root.find("channel") is None:
        raise ValueError("Expected official RSS channel")
    old = {r["id"]: r for r in previous}

    class Description(TextOnly):
        def handle_endtag(self, tag):
            super().handle_endtag(tag)
            if tag in {"p", "div", "h1", "h2", "h3", "h4", "hr"}:
                self.parts.append("\n")

    rows = {}
    collected = now.isoformat(timespec="seconds")
    for node in root.findall("./channel/item")[:40]:
        try:
            published = parsedate_to_datetime(node.findtext("pubDate", ""))
            if published.tzinfo is None:
                raise ValueError("RSS publication timezone is required")
            published = published.astimezone(timezone.utc)
            if not now - timedelta(days=30) <= published <= now:
                continue
            url = source_url(node.findtext("link", "").strip(), source)
            title = clean_text(node.findtext("title", "").strip(), 300)
            if not title or len(title.split()) > 30:
                continue
            parser = Description()
            # Explicitly ignore content:encoded, media and article bodies.
            parser.feed(node.findtext("description", "")[:20000])
            paragraphs = [
                " ".join(p.split()) for p in "".join(parser.parts).splitlines()
            ]
            paragraphs = [
                p
                for p in paragraphs
                if p
                and p.casefold() != "introduction"
                and not p.casefold().startswith("written by:")
            ]
            plain = " ".join(paragraphs)
            if INJECTION.search(title + " " + plain):
                continue
            sentences = re.split(r"(?<=[.!?])\s+", plain)
            excerpt = ""
            for sentence in sentences:
                candidate = (excerpt + " " + sentence).strip()
                if len(candidate.split()) > 80 or len(candidate) > 900:
                    break
                excerpt = candidate
            # Never clip a qualification from an overlong first sentence.
            excerpt = clean_text(excerpt, 900)
            if not relevant(title, excerpt):
                continue
            author = (
                node.findtext("{http://purl.org/dc/elements/1.1/}creator")
                or node.findtext("author/name")
                or node.findtext("author", "")
            )
            author = clean_text(author, 160)
            modified = node.findtext("{http://purl.org/dc/terms/}modified")
            modified = stamp(modified).isoformat() if modified else None
            if modified and not published <= stamp(modified) <= now:
                continue
            uid = hashlib.sha256(url.encode()).hexdigest()[:24]
            before = old.get(uid)
            row = {
                "id": uid,
                "source": source,
                "source_url": url,
                "title": title,
                "excerpt": excerpt,
                "published_at": published.isoformat(),
                "category": category(title + " " + excerpt),
                "artwork": "advisory.svg",
                "publisher": FEEDS[source]["publisher"],
                "author": author,
                "license": FEEDS[source]["license"],
                "modified_at": modified,
                "first_seen": (
                    before.get("first_seen", collected) if before else collected
                ),
                "last_seen": collected,
                "content_changed_at": None,
                "source_id": clean_text(node.findtext("guid", url), 500),
                "references": [url],
            }
            if before:
                row["content_changed_at"] = (
                    collected
                    if fingerprint(row) != fingerprint(before)
                    else before.get("content_changed_at")
                )
            rows[uid] = row
        except (ValueError, TypeError, OverflowError, AttributeError):
            continue
    return sorted(
        rows.values(), key=lambda r: (r["published_at"], r["id"]), reverse=True
    )[:20]


def validate(row):
    from .publication import (
        NEWS_FIELDS,
        exact_fields,
        source_url,
        clean_text,
        stamp,
        valid_id,
    )

    exact_fields(row, NEWS_FIELDS | EXTRA_FIELDS)
    spec = FEEDS[row["source"]]
    valid_id(row["id"])
    if hashlib.sha256(row["source_url"].encode()).hexdigest()[:24] != row["id"]:
        raise ValueError("Research identity mismatch")
    source_url(row["source_url"], row["source"])
    if (
        row["publisher"] != spec["publisher"]
        or row["license"] != spec["license"]
        or row["references"] != [row["source_url"]]
    ):
        raise ValueError("Research attribution changed")
    if (
        row["category"] != category(row["title"] + " " + row["excerpt"])
        or row["artwork"] != "advisory.svg"
    ):
        raise ValueError("Research classification changed")
    for key, limit in (
        ("title", 300),
        ("excerpt", 900),
        ("author", 160),
        ("source_id", 500),
    ):
        clean_text(row[key], limit)
    if (
        not row["title"]
        or len(row["title"].split()) > 30
        or len(row["excerpt"].split()) > 80
    ):
        raise ValueError("Oversized research metadata")
    if not relevant(row["title"], row["excerpt"]):
        raise ValueError("Non-editorial research metadata")
    if stamp(row["first_seen"]) > stamp(row["last_seen"]):
        raise ValueError("Invalid research collection interval")
    for key in ("published_at", "modified_at", "content_changed_at"):
        if row[key] and stamp(row[key]) > stamp(row["last_seen"]):
            raise ValueError("Future research chronology")
    if row["modified_at"] and stamp(row["modified_at"]) < stamp(row["published_at"]):
        raise ValueError("Research modification precedes publication")
    return row
