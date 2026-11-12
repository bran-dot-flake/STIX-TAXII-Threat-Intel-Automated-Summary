"""Public-source projection. Never exports the local database or platform context.

The publication boundary accepts only the two original, allowlisted public feeds
and explicitly CLEAR/WHITE public CIRCL events. Unknown markings fail closed.
"""
import hashlib
import ipaddress
import json
import re
import uuid
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlsplit

from .feeds import CIRCL, KEV, kev_records
from .model import Record, canonical, utcnow
from .report import atomic_write, evidence_digest, validate_selection
from .stix_publication import empty_context, validate_context
from .research import FEEDS as RESEARCH_FEEDS

NEWS = "https://www.cisa.gov/cybersecurity-advisories/all.xml"
SOURCE_NAMES = {"cisa-kev": "CISA KEV", "circl-osint": "CIRCL OSINT", "cisa-advisories": "CISA Advisories"}
SOURCE_NAMES.update({key: spec["publisher"] for key, spec in RESEARCH_FEEDS.items()})
SOURCE_URLS = {"cisa-kev": KEV, "circl-osint": CIRCL, "cisa-advisories": NEWS}
KINDS = {"vulnerability", "ip-dst", "domain", "url", "md5", "sha1", "sha256"}
RECORD_FIELDS = {"id", "source", "source_url", "kind", "value", "title", "description", "action", "published_at", "first_seen", "last_seen"}
NEWS_FIELDS = {"id", "source", "source_url", "title", "excerpt", "published_at", "category", "artwork"}
REPORT_FIELDS = {"id", "generated_at", "mode", "evidence_count", "items"}
ITEM_FIELDS = {"id", "excerpt", "title", "source", "source_url", "value", "kind", "action", "published_at"}
SNAPSHOT_FIELDS = {"schema_version", "synthetic", "collected_at", "exported_at", "sources", "records", "news", "reports"}


def stamp(value):
    result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if result.tzinfo is None:
        result = result.replace(tzinfo=timezone.utc)
    return result.astimezone(timezone.utc)


def public_host(host):
    if not host:
        return False
    host = host.lower().rstrip(".")
    try:
        address = ipaddress.ip_address(host)
        return address.is_global and not address.is_multicast and not address.is_reserved
    except ValueError:
        return "." in host and not host.endswith((".local", ".internal", ".localhost", ".lan", ".home", ".home.arpa", ".corp", ".private", ".intranet", ".test", ".invalid", ".example")) and host not in {"example.com", "example.net", "example.org"}


def clean_text(value, limit=4000):
    """Reject suspicious content rather than trying to redact unknown secrets."""
    if not isinstance(value, str) or len(value) > limit:
        raise ValueError("Invalid public text")
    value = " ".join(value.split())
    if re.search(r"(?i)(?:tlp\s*:\s*(?:red|amber|green)|-----BEGIN|(?:api[_ -]?key|password|secret|token)\s*[:=]|\b(?:localhost|[\w-]+\.(?:internal|local|lan))\b|[\w.+-]+@[\w.-]+)", value):
        raise ValueError("Restricted public text")
    # Inspect IPv4 and IPv6 literals in free text, including URLs.
    for candidate in re.findall(r"(?<![\w])(?:\d{1,3}\.){3}\d{1,3}(?![\w])|[0-9a-fA-F:]*:[0-9a-fA-F:]+", value.replace("[.]", ".")):
        try:
            address = ipaddress.ip_address(candidate.strip("[]"))
        except ValueError:
            continue
        if not address.is_global:
            raise ValueError("Nonpublic address in text")
    return value


def source_url(value, source):
    p = urlsplit(value)
    if p.scheme != "https" or p.username or p.password or p.query or p.fragment or p.port not in (None, 443):
        raise ValueError("Invalid public source URL")
    if source == "cisa-kev" and value != KEV:
        raise ValueError("Unapproved KEV URL")
    if source == "circl-osint" and not re.fullmatch(re.escape(CIRCL) + r"[0-9a-f-]{36}\.json", value):
        raise ValueError("Unapproved CIRCL URL")
    if source == "cisa-advisories" and not (p.hostname == "www.cisa.gov" and p.path.startswith("/news-events/")):
        raise ValueError("Unapproved news URL")
    if source in RESEARCH_FEEDS and not (p.hostname == RESEARCH_FEEDS[source]["host"] and p.path.startswith("/") and len(p.path) > 1 and not re.search(r"[\\\s]|%2[fF]|%5[cC]", p.path)):
        raise ValueError("Unapproved research URL")
    if source=='google-gti' and not p.path.startswith('/blog/topics/threat-intelligence/'):
        raise ValueError('Unapproved Google research path')
    if source not in SOURCE_NAMES:
        raise ValueError("Unknown public source")
    return value


def public_value(kind, value):
    value = canonical(kind, value)
    if kind == "ip-dst" and not public_host(value):
        raise ValueError("Nonpublic indicator")
    if kind in {"domain", "url"}:
        host = value if kind == "domain" else urlsplit(value).hostname
        if not public_host(host):
            raise ValueError("Nonpublic host")
    clean_text(value)
    return value.replace("http://", "hxxp://").replace("https://", "hxxps://").replace(".", "[.]")


def clear_marking(node, inherited=False):
    tags = [str(t.get("name", "")).lower().replace('"', '') for t in node.get("Tag", [])]
    tlp = [t for t in tags if t.startswith("tlp:")]
    # Other distribution codes and sharing groups override a permissive marking.
    distribution = node.get("distribution")
    if distribution is not None and str(distribution) not in ({"3", "5"} if inherited else {"3"}):
        return False
    if node.get("SharingGroup") or str(node.get("sharing_group_id", "0")) not in {"0", "", "None"}:
        return False
    if tlp and any(t not in {"tlp:clear", "tlp:white"} for t in tlp):
        return False
    # Explicit non-TLP redistribution constraints are not exported.
    if any(t.startswith(("pap:", "iep:", "distribution:")) for t in tags):
        return False
    return bool(tlp) or inherited


def circl_public_records(http, now):
    manifest = http.json(CIRCL + "manifest.json")
    entries = sorted(manifest.items(), key=lambda item: int(item[1]["timestamp"]), reverse=True)
    result = []
    for raw_uid, metadata in entries[:3]:
        modified = datetime.fromtimestamp(int(metadata["timestamp"]), timezone.utc)
        if not now - timedelta(days=90) <= modified <= now + timedelta(minutes=5):
            continue
        uid = str(uuid.UUID(raw_uid))
        url = CIRCL + uid + ".json"
        event = http.json(url)["Event"]
        if event.get("published") is not True or not clear_marking(event):
            continue
        attributes = [(a, True) for a in event.get("Attribute", [])]
        for obj in event.get("Object", []):
            attributes.extend((a, clear_marking(obj, True)) for a in obj.get("Attribute", []))
        emitted = 0
        for attr, parent_clear in attributes:
            kind = "ip-dst" if attr.get("type") == "ip-src" else attr.get("type")
            if kind not in KINDS:
                continue
            published = event.get("publish_timestamp")
            try:
                r = Record(source="CIRCL OSINT / " + uid, source_url=url, kind=kind, value=attr["value"],
                    title=str(event["info"])[:200], description=str(attr.get("comment") or event["info"])[:1000],
                    published_at=datetime.fromtimestamp(int(published), timezone.utc).isoformat() if published and int(published) else None,
                    modified_at=modified.isoformat(), priority=60)
            except ValueError:
                continue
            # Mirror the existing adapter's batch before applying publication gates.
            emitted += 1
            if parent_clear and clear_marking(attr, True):
                try:
                    project_record(r, "circl-osint", now.isoformat())
                    result.append(r)
                except ValueError:
                    pass
            if emitted == 20:
                break
    return result


def project_record(r, source, collected, first_seen=None):
    return {"id": r.key, "source": source, "source_url": source_url(r.source_url, source),
        "kind": r.kind, "value": public_value(r.kind, r.value), "title": clean_text(r.title, 200),
        "description": clean_text(r.description) if source == "cisa-kev" else "Public CIRCL OSINT observation. Source attribution is not independent verification.",
        "action": clean_text(r.action), "published_at": r.published_at,
        "first_seen": first_seen or collected, "last_seen": collected}


class TextOnly(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts, self.blocked = [], 0

    def handle_starttag(self, tag, attrs):
        if tag in {"script", "style"}:
            self.blocked += 1

    def handle_endtag(self, tag):
        if tag in {"script", "style"}:
            self.blocked = max(0, self.blocked - 1)
        self.parts.append(" ")

    def handle_data(self, data):
        if not self.blocked:
            self.parts.append(data)


def news_items(raw, now):
    if re.search(r"<!\s*(?:DOCTYPE|ENTITY)", raw, re.I):
        raise ValueError("Unsafe XML")
    root = ET.fromstring(raw)
    rows = []
    for node in root.findall("./channel/item"):
        try:
            date = parsedate_to_datetime(node.findtext("pubDate", "")).astimezone(timezone.utc)
            if not now - timedelta(days=30) <= date <= now + timedelta(minutes=5):
                continue
            url = source_url(node.findtext("link", ""), "cisa-advisories")
            parser = TextOnly()
            parser.feed(node.findtext("description", ""))
            plain = " ".join(" ".join(parser.parts).split())
            plain = re.sub(r'^View CSAF Summary\s*','',plain)
            sentence = re.split(r'(?<=[.!?])\s+',plain,maxsplit=1)[0]
            words = sentence.split()
            # Prefer a complete introductory sentence over a clipped CVE list.
            excerpt = " ".join(words[:45]) + ("…" if len(words) > 45 else "")
            title = clean_text(node.findtext("title", ""), 300)
            category = "Exploitation watch" if "known exploited" in title.lower() else "Security advisory"
            rows.append({"id": hashlib.sha256(url.encode()).hexdigest()[:24], "source": "cisa-advisories", "source_url": url,
                "title": title, "excerpt": clean_text(excerpt, 600), "published_at": date.isoformat(), "category": category,
                "artwork": "exploitation.svg" if category == "Exploitation watch" else "advisory.svg"})
        except (ValueError, TypeError, OverflowError):
            continue
    ranked = sorted({r["id"]: r for r in rows}.values(), key=lambda r: r["published_at"], reverse=True)
    # Keep a few catalog updates; do not let near-identical KEV bulletins crowd
    # source advisories out of the bounded editorial selection.
    selected = [r for r in ranked if r['category']=='Exploitation watch'][:3]
    selected += [r for r in ranked if r['category']!='Exploitation watch'][:18-len(selected)]
    return sorted(selected,key=lambda r:r['published_at'],reverse=True)


def collect_public(http, previous=None, now=None):
    now = now or datetime.now(timezone.utc)
    collected = now.isoformat(timespec="seconds")
    previous = previous or empty_snapshot()
    validate_snapshot(previous)
    records, news, statuses, originals = [], [], [], {}
    for source in SOURCE_NAMES:
        old_status = next((s for s in previous["sources"] if s["id"] == source), {})
        try:
            if source == "cisa-advisories":
                fresh_news = news_items(http.request(NEWS), now)
                if not fresh_news:
                    raise ValueError("No recent news")
                news.extend(fresh_news)
            elif source in RESEARCH_FEEDS:
                from .research import items
                fresh_news = items(http.request(RESEARCH_FEEDS[source]["url"]), source, now, previous["news"])
                if not fresh_news:
                    raise ValueError("No usable recent research metadata")
                retained = {r["id"]: r for r in previous["news"] if r["source"] == source and now - timedelta(days=30) <= stamp(r["published_at"]) <= now}
                retained.update({r["id"]: r for r in fresh_news})
                news.extend(retained.values())
            else:
                raw_records = list(kev_records(http.json(KEV), 90, now)) if source == "cisa-kev" else circl_public_records(http, now)
                seen = {r["id"]: r["first_seen"] for r in previous["records"] if r["source"] == source}
                fresh = []
                for r in raw_records:
                    if r.published_at and stamp(r.published_at) > now + timedelta(minutes=5):
                        continue
                    try:
                        row = project_record(r, source, collected, seen.get(r.key))
                    except ValueError:
                        continue
                    fresh.append(row)
                    originals[r.key] = r
                records.extend(fresh)
            statuses.append({"id": source, "status": "ok", "attempted_at": collected, "last_success_at": collected})
        except Exception as exc:
            # Error class only; exception text can contain source content or infrastructure.
            records.extend(r for r in previous["records"] if r["source"] == source)
            news.extend(r for r in previous["news"] if r["source"] == source)
            statuses.append({"id": source, "status": "cached" if old_status.get("last_success_at") else "unavailable",
                "attempted_at": collected, "last_success_at": old_status.get("last_success_at")})
            print(json.dumps({"source": source, "status": "failed", "error_type": type(exc).__name__}))
    successes = [s["last_success_at"] for s in statuses if s["last_success_at"]]
    result = {"schema_version": 1, "synthetic": False, "collected_at": max(successes) if successes else None,
        "exported_at": collected, "sources": statuses,
        "records": sorted({r["id"]: r for r in records}.values(), key=lambda r: (r["published_at"] or "", r["id"]), reverse=True),
        "news": news, "reports": previous["reports"], "stix":previous.get("stix",empty_context())}
    # Retain public research history independently of article publication.
    result['news']=sorted({r['id']:r for r in result['news']}.values(),key=lambda r:(r['published_at'],r['id']),reverse=True)[:240]
    result["schema_version"]=previous['schema_version'] if previous['schema_version'] in {3,4,5,6,7} else 2
    if previous['schema_version'] in {4,5,6,7}:result['editions']=previous['editions']
    if previous['schema_version']==7:result['illustrations']=previous['illustrations']
    if previous['schema_version'] in {5,6,7}:
        if previous['schema_version'] in {6,7}:
            from .executive import prepare
        else:
            from .hybrid import prepare
        prepare(result)
    validate_snapshot(result)
    return result, originals


def attach_briefs(snapshot, originals, reports_dir):
    """Revalidate exact source versions before promoting private sidecar selections.

    No Markdown, database, platform context, event UUID, model URL or run ID is
    copied. A report with any unpublished evidence is withheld as a whole.
    """
    from .briefing_public import promote_observations, enrich, enrich_snapshot
    history = {r["id"]: r for r in snapshot["reports"]}
    lookup = {r["id"]: r for r in snapshot["records"]}
    for path in sorted(Path(reports_dir).glob("*.json"))[-90:]:
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
            if raw["status"] != "complete":
                continue
            if not raw.get('records'):
                continue  # Collection success alone is not a public article.
            matched = [originals[r["id"]] for r in raw["records"]]
            if any(r.version != meta["version"] for r, meta in zip(matched, raw["records"])) or evidence_digest(matched) != raw["evidence_digest"]:
                continue
            selection = validate_selection({"items": raw["selection"]}, {r.key: r for r in matched})
            # Timestamp only, not a raw Markdown excerpt.
            md = path.with_suffix(".md").read_text(encoding="utf-8")
            generated = next(line.removeprefix("Generated: ") for line in md.splitlines() if line.startswith("Generated: "))
            stamp(generated)
            if stamp(generated) > stamp(snapshot["exported_at"]) + timedelta(minutes=5):
                continue
            items = []
            for item in selection:
                record = lookup[item["record_id"]]
                excerpt = clean_text(item["excerpt"], 240)
                # Avoid publishing third-party source prose beyond short titles.
                if record["source"] == "circl-osint" and (excerpt != record["title"] or len(excerpt.split()) > 25):
                    raise ValueError("CIRCL excerpt not approved for publication")
                items.append({**{k: record[k] for k in ITEM_FIELDS - {"excerpt"}}, "excerpt": excerpt})
            report_id = hashlib.sha256((generated + raw["evidence_digest"]).encode()).hexdigest()[:24]
            # The sidecar does not claim LLM mode, so read the trusted renderer's marker.
            mode = "quiet-day" if not matched else "ollama-extractive" if "Report mode: Ollama selected, validated source excerpts." in md else "deterministic"
            report = {"id": report_id, "generated_at": generated, "mode": mode, "evidence_count": len(matched), "items": items,
                      'observations':promote_observations(raw,matched,generated)}
            # Preserve a previously checked model composition when a legacy
            # sidecar is revalidated during a later publication run.
            candidate=raw.get('narrative') or history.get(report_id,{}).get('narrative')
            history[report_id] = enrich(report,candidate)
        except (KeyError, ValueError, TypeError, StopIteration, OSError):
            continue
    snapshot["reports"] = sorted(history.values(), key=lambda r: r["generated_at"], reverse=True)[:90]
    enrich_snapshot(snapshot)
    validate_snapshot(snapshot)
    return snapshot


def empty_snapshot():
    return {"schema_version": 2, "synthetic": False, "collected_at": None, "exported_at": None,
        "sources": [], "records": [], "news": [], "reports": [], "stix":empty_context()}


def exact_fields(row, fields):
    if not isinstance(row, dict) or set(row) != fields:
        raise ValueError("Unexpected publication fields")


def valid_id(value):
    if not isinstance(value, str) or not re.fullmatch(r"[a-f0-9]{24}", value):
        raise ValueError("Invalid publication identifier")


def validate_item(row):
    valid_id(row["id"])
    if row["source"] not in {"cisa-kev", "circl-osint"} or row["kind"] not in KINDS:
        raise ValueError("Invalid public record classification")
    if row["source"] == "cisa-kev" and row["kind"] != "vulnerability":
        raise ValueError("KEV evidence must be a CVE")
    source_url(row["source_url"], row["source"])
    raw = row["value"].replace("hxxps://", "https://").replace("hxxp://", "http://").replace("[.]", ".")
    if public_value(row["kind"], raw) != row["value"]:
        raise ValueError("Invalid or armed indicator")
    for key in ("title", "action"):
        clean_text(row[key])
    if row["published_at"] is not None:
        stamp(row["published_at"])


def validate_snapshot(value, allow_synthetic=False):
    version=value.get("schema_version")
    exact_fields(value, SNAPSHOT_FIELDS | ({"stix"} if version in {2,3,4,5,6,7} else set()) | ({'editions'} if version in {4,5,6,7} else set()) | ({'collection'} if version in {5,6,7} else set()) | ({'illustrations'} if version==7 else set()))
    if version not in {1,2,3,4,5,6,7} or (value["synthetic"] is not False and not (allow_synthetic and value["synthetic"] is True)):
        raise ValueError("Unsupported or synthetic public snapshot")
    if version in {2,3,4,5,6,7}:validate_context(value["stix"])
    for field in ("collected_at", "exported_at"):
        if value[field] is not None:
            stamp(value[field])
    if not all(isinstance(value[k], list) for k in ("sources", "records", "news", "reports")):
        raise ValueError("Invalid publication collections")
    if len(value["records"]) > 5000 or len(value["news"]) > 240 or len(value["reports"]) > 90 or len(value["sources"]) > len(SOURCE_NAMES):
        raise ValueError("Oversized publication")
    for collection in ("sources", "records", "news", "reports"):
        ids = [r["id"] for r in value[collection]]
        if len(ids) != len(set(ids)):
            raise ValueError("Duplicate publication IDs")
    for row in value["sources"]:
        exact_fields(row, {"id", "status", "attempted_at", "last_success_at"})
        if row["id"] not in SOURCE_NAMES or row["status"] not in {"ok", "cached", "unavailable"}:
            raise ValueError("Invalid source health")
        stamp(row["attempted_at"])
        if row["last_success_at"] is not None:
            stamp(row["last_success_at"])
    for row in value["records"]:
        exact_fields(row, RECORD_FIELDS)
        validate_item(row)
        clean_text(row["description"])
        if stamp(row["first_seen"]) > stamp(row["last_seen"]):
            raise ValueError("Invalid observation interval")
    for row in value["news"]:
        validate_news(row)
        if value['exported_at'] and any(row.get(k) and stamp(row[k])>stamp(value['exported_at']) for k in ('published_at','modified_at','last_seen','content_changed_at')):
            raise ValueError('Future public news')
    for row in value["reports"]:
        exact_fields(row, REPORT_FIELDS | ({'observations','narrative'} if version in {3,4,5,6,7} else set()))
        valid_id(row["id"])
        stamp(row["generated_at"])
        quiet = row["mode"] == "quiet-day" and row["evidence_count"] == 0 and row["items"] == []
        if not quiet and (row["mode"] not in {"ollama-extractive", "deterministic"} or not 1 <= row["evidence_count"] <= 8 or not 1 <= len(row["items"]) <= row["evidence_count"]):
            raise ValueError("Invalid brief metadata")
        for item in row["items"]:
            exact_fields(item, ITEM_FIELDS)
            validate_item(item)
            clean_text(item["excerpt"], 240)
        if version in {3,4,5,6,7}:
            from .briefing_public import validate_observation
            from .narrative import validate_narrative
            observations=row['observations']
            if not isinstance(observations,list) or not len(row['items'])<=len(observations)<=row['evidence_count']:
                raise ValueError('Invalid topic evidence coverage')
            ids=[r['id'] for r in observations]
            if len(ids)!=len(set(ids)) or any(item['id'] not in ids for item in row['items']):raise ValueError('Invalid topic evidence identifiers')
            for observation in observations:validate_observation(observation,row['generated_at'])
            validate_narrative(row['narrative'],row)
    if version in {4,5,6,7}:
        from .editorial import validate_edition
        editions=value['editions']
        if not isinstance(editions,list) or len(editions)>90:raise ValueError('Invalid editorial history')
        ids=[r['id'] for r in editions]
        if len(ids)!=len(set(ids)):raise ValueError('Duplicate editorial editions')
        for edition in editions:
            validate_edition(edition)
            if edition.get('version') in {2,3} and edition.get('published_at') is None:raise ValueError('Unpublished editorial candidate')
            if stamp(edition['generated_at'])>stamp(value['exported_at']):raise ValueError('Future editorial edition')
            if edition.get('version')==1 and edition['generated_at']==value['exported_at']:
                from .editorial import curate
                if edition['input']!=curate(value):raise ValueError('Editorial input differs from the collected publication')
            if edition.get('version') in {2,3} and edition['generated_at']==value['exported_at']:
                originals={r['id']:r for r in value['records']+value['news']}
                for row in edition['input']['records']+edition['input']['news']:
                    if originals.get(row['id'])!=row:raise ValueError('Hybrid evidence differs from collected publication')
    if version in {5,6,7}:
        if version in {6,7}:
            from .executive import validate_collection
        else:
            from .hybrid import validate_collection
        validate_collection(value)
    if version==7:
        from .artwork import validate
        validate(value)
    return value


def validate_news(row):
    if row.get('source') in RESEARCH_FEEDS:
        from .research import validate
        return validate(row)
    exact_fields(row, NEWS_FIELDS)
    valid_id(row['id'])
    if row['source']!='cisa-advisories' or row['artwork'] not in {'advisory.svg','exploitation.svg'} or row['category'] not in {'Exploitation watch','Security advisory'}:
        raise ValueError('Invalid editorial metadata')
    source_url(row['source_url'],row['source'])
    stamp(row['published_at'])
    clean_text(row['title'],300)
    clean_text(row['excerpt'],600)
    if len(row['excerpt'].split())>45:raise ValueError('Oversized news excerpt')
    return row


def save_snapshot(path, snapshot):
    validate_snapshot(snapshot)
    atomic_write(Path(path), json.dumps(snapshot, ensure_ascii=False, indent=2) + "\n")
