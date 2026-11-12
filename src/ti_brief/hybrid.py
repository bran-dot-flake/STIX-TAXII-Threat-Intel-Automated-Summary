"""Repeatable weekly editions, conservative interim updates and quiet collection.

Only sanitized public projections enter this module. Legacy editions remain
readable; collection clocks never establish a new threat development.
"""

import copy
import json
import os
import re
from datetime import timedelta
from pathlib import Path
from .topics import instant
from .research import fingerprint
from .editorial import digest, contaminated, validate_plan, fallback_plan

META = {"publication_kind", "window_start", "window_end", "covered_story_ids"}
COLLECTION_FIELDS = {"checked_at", "status", "last_substantive_at", "weekly_window_end"}


def settings():
    result = {
        "weekday": int(os.environ.get("TI_WEEKLY_DAY", "0")),
        "hour": int(os.environ.get("TI_WEEKLY_HOUR_UTC", "8")),
        "update_hours": int(os.environ.get("TI_UPDATE_LOOKBACK_HOURS", "48")),
    }
    if (
        not 0 <= result["weekday"] <= 6
        or not 0 <= result["hour"] <= 23
        or not 1 <= result["update_hours"] <= 72
    ):
        raise ValueError("Invalid hybrid publication schedule")
    return result


def weekly_window(now, config):
    end = now.replace(hour=config["hour"], minute=0, second=0, microsecond=0)
    end -= timedelta(days=(end.weekday() - config["weekday"]) % 7)
    if end > now:
        end -= timedelta(days=7)
    return end - timedelta(days=7), end


def within(row, start, end, include_end=False):
    value = row.get("published_at")
    return bool(
        value
        and start <= instant(value)
        and (instant(value) <= end if include_end else instant(value) < end)
    )


def changed_in_window(row, start, end, include_end=False):
    return all(
        row.get(key) and within({"published_at": row[key]}, start, end, include_end)
        for key in ("modified_at", "content_changed_at")
    )


def story_key(row):
    if row.get("kind") == "vulnerability":
        chain = sorted(
            set(
                [row["value"]]
                + re.findall(
                    r"can be chained with (CVE-\d{4}-\d{4,7})",
                    row.get("description", ""),
                    re.I,
                )
            )
        )
        return "cve:" + "|".join(c.upper() for c in chain)
    if row.get("kind"):
        return "report:" + row["source_url"]
    # Exact CVEs in a vulnerability headline are an explicit shared subject.
    # Actor/vendor names alone never merge different reports or campaigns.
    cves = sorted(set(re.findall(r"CVE-\d{4}-\d{4,7}", row["title"], re.I)))
    if cves and row["category"] in {"Security advisory", "Vulnerability research"}:
        all_cves = sorted(
            set(
                re.findall(
                    r"CVE-\d{4}-\d{4,7}", row["title"] + " " + row["excerpt"], re.I
                )
            )
        )
        return "cve:" + "|".join(c.upper() for c in all_cves)
    return "article:" + row["source_url"]


def significant(row):
    """A deterministic publication threshold, not a risk/severity score."""
    text = (
        row.get("title", "")
        + " "
        + row.get("excerpt", "")
        + " "
        + row.get("description", "")
    ).lower()
    if row.get("category") == "Exploitation watch":
        return False  # A routine catalog bulletin alone is not an interim article.
    if re.search(
        r"no evidence|not observed|have not|has not|not actively|not exploited|not targeting|no active|cannot confirm",
        text,
    ):
        return False
    if "can be chained with cve-" in text:
        return True
    if re.search(
        r"actively exploited|exploitation in the wild|exploited in the wild|zero.day|exploit attempts|attempts to exploit",
        text,
    ) and re.search(r"cve-\d{4}-\d{4,7}", text):
        return True
    return bool(
        re.search(r"campaign|ransomware|malware|infostealer|backdoor", text)
        and re.search(
            r"\bobserved\b|\bidentified\b|\bdiscovered\b|\btargeting\b|\btargets\b",
            text,
        )
    )


def version_map(rows):
    groups = {}
    for row in rows:
        groups.setdefault(story_key(row), {})[row["id"]] = fingerprint(row)
    return {digest(key)[:24]: digest(value) for key, value in groups.items()}


def publication_time(edition):
    return edition.get("published_at") or edition["generated_at"]


def substantive(snapshot):
    return sorted(
        (e for e in snapshot.get("editions", []) if e["topics"]),
        key=publication_time,
        reverse=True,
    )


def covered(snapshot):
    seen = {}
    for e in reversed(substantive(snapshot)):
        if e.get("version") == 2:
            seen.update(e["story_versions"])
        else:
            selected = {uid for t in e["topics"] for uid in t["evidence_ids"]}
            seen.update(
                version_map(
                    [
                        r
                        for r in e["input"]["records"] + e["input"]["news"]
                        if r["id"] in selected
                    ]
                )
            )
    return seen


def package_for(snapshot, kind, start, end):
    generated = snapshot["exported_at"]
    # Failed sources retain data and history but cannot trigger fresh articles.
    healthy = {s["id"] for s in snapshot["sources"] if s["status"] == "ok"}
    seen = covered(snapshot)
    old_rows = {
        r["id"]: r
        for e in reversed(substantive(snapshot))
        for r in e["input"]["records"] + e["input"]["news"]
    }
    covered_articles = {
        digest(story_key(r))[:24]
        for e in substantive(snapshot)
        for r in e["input"]["news"]
        if r.get("category") != "Exploitation watch"
        and any(r["id"] in t["evidence_ids"] for t in e["topics"])
    }
    rows = [
        r
        for r in snapshot["records"] + snapshot["news"]
        if r["source"] in healthy
        and not contaminated(r)
        and within(r, start, end, kind == "update")
        and not (
            kind == "weekly"
            and r.get("modified_at")
            and instant(r["modified_at"]) >= end
        )
    ]
    if kind == "update":
        rows = [
            r
            for r in rows
            if significant(r)
            and (
                digest(story_key(r))[:24] not in seen
                or (
                    not r.get("kind")
                    and digest(story_key(r))[:24] not in covered_articles
                )
            )
        ]
    # Explicit source modification plus a measured change can qualify an older
    # report in either window. Weekly retrospectives retain prior interim updates.
    for r in snapshot["news"]:
        if (
            r["source"] in healthy
            and not contaminated(r)
            and changed_in_window(r, start, end, kind == "update")
            and (
                kind == "weekly"
                or (
                    significant(r)
                    and r["id"] in old_rows
                    and fingerprint(r) != fingerprint(old_rows[r["id"]])
                )
            )
        ):
            rows.append(r)
    unique = {r["id"]: r for r in rows}
    ordered = sorted(
        unique.values(),
        key=lambda r: (
            -int(significant(r)),
            -int(r["source"] not in {"cisa-kev", "cisa-advisories"}),
            r["id"],
        ),
    )
    # One representative of each original source first; do not let one publisher
    # monopolize a bounded editorial input. Remaining originals stay searchable.
    news = [r for r in ordered if not r.get("kind") and (r["excerpt"] or r["title"])]
    diverse, publishers = [], set()
    for r in news:
        if r["source"] not in publishers:
            diverse.append(r)
            publishers.add(r["source"])
    news = (diverse + [r for r in news if r not in diverse])[:4]
    records = [r for r in ordered if r.get("kind")][:36]
    selected_text = " ".join(
        r.get("description", r.get("excerpt", "")) for r in records + news
    )
    explicit = set(
        re.findall(r"\b(?:T\d{4}(?:\.\d{3})?|G\d{4}|S\d{4})\b", selected_text)
    )
    return {
        "generated_at": generated,
        "sources": snapshot["sources"],
        "records": records,
        "news": news,
        "updates": [],
        "context": [
            r
            for r in snapshot.get("stix", {}).get("objects", [])
            if r["external_id"] in explicit
        ][:8],
        "publication_kind": kind,
        "window_start": start.isoformat(),
        "window_end": end.isoformat(),
        "covered_story_ids": sorted(seen)[:1000],
    }


def candidate(snapshot, config=None):
    config = config or settings()
    now = instant(snapshot["exported_at"])
    start, end = weekly_window(now, config)
    week_id = digest("editorial:weekly:" + end.isoformat())[:24]
    overlaps = any(
        e.get("publication_kind") == "weekly"
        and start < instant(e["window_end"])
        and instant(e["window_start"]) < end
        for e in snapshot.get("editions", [])
    )
    if not overlaps and not any(
        e["id"] == week_id for e in snapshot.get("editions", [])
    ):
        package = package_for(snapshot, "weekly", start, end)
        if ledger(package)["topics"]:
            return package
    package = package_for(
        snapshot, "update", now - timedelta(hours=config["update_hours"]), now
    )
    return package if ledger(package)["topics"] else None


def headline(value):
    # Preserve a source's wording and qualifications. Long originals remain in
    # evidence; the compact display title uses an explicit ellipsis.
    value = re.sub(r"^(?:SANS ISC|Cisco Talos)\s*[:–—-]\s*", "", value).strip()
    value = re.sub(r"^The Rise of\s+", "", value)
    value = re.sub(
        r",\s*\([A-Za-z]{3},\s*[A-Za-z]{3}\s+\d+(?:st|nd|rd|th)?\)$", "", value
    )
    return value if len(value) <= 95 else value[:92].rsplit(" ", 1)[0] + "…"


def attribution_prefix(row):
    dates = row["published_at"][:10]
    if row.get("modified_at") and row.get("content_changed_at"):
        dates += "; updated " + row["modified_at"][:10]
    return f"{row.get('publisher','CISA')} ({dates}) reports: "


def ledger(package):
    facts, topics, groups = {}, [], {}
    rows = package["news"] + package["records"]
    for row in rows:
        groups.setdefault(story_key(row), []).append(row)
    cves = [r for r in package["records"] if r["source"] == "cisa-kev"]

    def fact(key, text, ids):
        facts[key] = {"texts": [text], "evidence_ids": sorted(set(ids))}
        return key

    def topic(key, title, summary, members, kind, freshness, when):
        ids = sorted({r["id"] for r in members})
        fid = fact("story:" + digest(key)[:24], summary, ids)
        topics.append(
            {
                "id": digest(key)[:24],
                "headline": headline(title),
                "summary_facts": [fid],
                "evidence_ids": ids,
                "kind": kind,
                "freshness": freshness,
                "published_at": when,
                "context_ids": [
                    c["id"]
                    for c in package["context"]
                    if any(
                        c["external_id"] in r.get("description", r.get("excerpt", ""))
                        for r in members
                    )
                ],
                "previously_reported": any(
                    digest(story_key(r))[:24] in package["covered_story_ids"]
                    for r in members
                ),
            }
        )

    # Reserve room for original research before the catalog summary.
    for key, members in groups.items():
        articles = [
            r
            for r in members
            if not r.get("kind") and r.get("category") != "Exploitation watch"
        ]
        if not articles:
            continue
        row = articles[0]
        summary = (
            row["excerpt"]
            or f"{row.get('publisher', 'CISA')} published “{row['title']}”."
        )
        if row["excerpt"]:
            summary = attribution_prefix(row) + summary
        topic(
            key,
            row["title"],
            summary,
            members,
            "advisory",
            (
                "source-updated"
                if row.get("modified_at")
                and not within(
                    row,
                    instant(package["window_start"]),
                    instant(package["window_end"]),
                )
                else "newly-published"
            ),
            row.get("modified_at") or row["published_at"],
        )
        if len(topics) >= (
            (1 if cves else 2)
            if package["publication_kind"] == "update"
            else 3 if cves else 4
        ):
            break
    used_ids = {uid for t in topics for uid in t["evidence_ids"]}
    catalog_cves = [r for r in cves if r["id"] not in used_ids]
    if catalog_cves and len(topics) < 4:
        # Interim CVEs reach this point only for an explicit chain or exploitation.
        dates = sorted({r["published_at"][:10] for r in catalog_cves})
        titles = list(
            dict.fromkeys(
                r["title"].removesuffix(" Vulnerability") for r in catalog_cves
            )
        )
        selected_titles = []
        for title in titles[:3]:
            if len((" ".join(selected_titles) + " " + title).split()) > 50:
                break
            selected_titles.append(title)
        names = "; ".join(selected_titles) or catalog_cves[0]["value"]
        summary = f"The reviewed CISA KEV additions date from {dates[0]} through {dates[-1]}. They include {names}."
        guidance = next((r["action"] for r in catalog_cves if r["action"]), "")
        if guidance and len((summary + guidance).split()) <= 90:
            summary += " CISA's required action: " + guidance
        topic(
            "catalog:" + "|".join(sorted(r["value"] for r in catalog_cves)),
            "CISA adds exploited vulnerabilities",
            summary,
            catalog_cves,
            "catalog",
            "catalog-added",
            max(r["published_at"] for r in catalog_cves),
        )
    for key, members in groups.items():
        if len(topics) >= 4:
            break
        if (
            members[0]["source"] != "circl-osint"
            or len({r["title"] for r in members}) != 1
        ):
            continue
        row = members[0]
        topic(
            key,
            row["title"],
            f"CIRCL's source report is titled “{row['title']}”.",
            members,
            "report",
            "newly-published",
            row["published_at"],
        )
    selected = {uid for t in topics for uid in t["evidence_ids"]}
    selected_rows = [r for r in rows if r["id"] in selected]
    first, second = [], []
    if topics:
        # Use actual findings in the executive overview. Move their remaining
        # context into the development summary so the same description is not
        # printed twice. Attribution dates anchor relative source wording.
        for t in topics:
            article = next(
                (
                    r
                    for r in selected_rows
                    if r["id"] in t["evidence_ids"]
                    and not r.get("kind")
                    and r.get("excerpt")
                ),
                None,
            )
            if article is None:
                continue
            sentences = re.split(
                r'(?<=[.!?])\s+|(?<=[.!?]["”’])\s+', article["excerpt"]
            )
            if len(sentences) < 2:
                continue
            index = next(
                (
                    i
                    for i, s in enumerate(sentences)
                    if re.search(
                        r"incident|campaign|exploit|hijack|malware|botnet|credential|vulnerab|ransom",
                        s,
                        re.I,
                    )
                ),
                0,
            )
            lead_indices = {index}
            if index + 1 < len(sentences) and re.search(
                r"limited|uncertain|not confirmed|could not|confidence",
                sentences[index + 1],
                re.I,
            ):
                lead_indices.add(index + 1)
            prefix = attribution_prefix(article)
            first.append(
                fact(
                    "lead:" + t["id"],
                    prefix
                    + " ".join(s for i, s in enumerate(sentences) if i in lead_indices),
                    t["evidence_ids"],
                )
            )
            remaining = " ".join(
                s for i, s in enumerate(sentences) if i not in lead_indices
            )
            if not remaining:
                # Keep the overview finding and a compact source reference rather
                # than printing the same source description twice.
                remaining = f"The original report is titled “{article['title']}”."
            facts[t["summary_facts"][0]]["texts"] = [prefix + remaining]
            if len(first) == 2:
                break
        if not first:
            first.append(
                fact(
                    "edition:focus",
                    topics[0]["headline"] + ".",
                    topics[0]["evidence_ids"],
                )
            )
        # Recommendations are explicitly editorial review steps, never claims of
        # local exposure, new attacks, invented attribution or source endorsement.
        phishing = any(r.get("category") == "Phishing" for r in selected_rows)
        if not phishing and any(
            r.get("category") in {"Malware research", "Campaign reporting"}
            for r in selected_rows
        ):
            second.append(
                fact(
                    "review:behavior",
                    "Defensive review: compare the source reports' documented behavior with relevant endpoint telemetry before treating a reported technique as local activity.",
                    selected,
                )
            )
        if phishing:
            second.append(
                fact(
                    "review:phishing",
                    "Defensive review: investigate related authentication and email telemetry where the reported credential-theft behavior is relevant to your environment.",
                    selected,
                )
            )
        if cves:
            second.append(
                fact(
                    "review:kev",
                    "For the KEV additions, check affected products against asset inventory and follow the cited vendor mitigation guidance. Catalog dates identify additions, not the start of attacks.",
                    [r["id"] for r in cves],
                )
            )
    return {
        "facts": facts,
        "topics": topics,
        "first": first,
        "second": second,
        "required": first,
        "generated_at": package["generated_at"],
        "publication_kind": package["publication_kind"],
    }


def edition(package, plan=None, mode="deterministic-fallback", published_at=None):
    # An accepted edition must never alias mutable live collection rows.
    package = copy.deepcopy(package)
    validate_input(package)
    if published_at is not None and instant(published_at) < instant(
        package["generated_at"]
    ):
        raise ValueError("Publication precedes evidence cutoff")
    book = ledger(package)
    if not book["topics"]:
        raise ValueError("A quiet collection is not an edition")
    plan = validate_plan(plan or fallback_plan(book), book)
    total = sum(len(c["text"].split()) for p in plan["overview"] for c in p) + sum(
        len(t["summary"]["text"].split()) for t in plan["topics"]
    )
    if total > (450 if package["publication_kind"] == "weekly" else 240):
        raise ValueError("Oversized hybrid edition")
    selected = {uid for t in book["topics"] for uid in t["evidence_ids"]}
    versions = version_map(
        [r for r in package["records"] + package["news"] if r["id"] in selected]
    )
    key = (
        "editorial:"
        + package["publication_kind"]
        + ":"
        + (
            package["window_end"]
            if package["publication_kind"] == "weekly"
            else digest(versions)
        )
    )
    return {
        "version": 2,
        "id": digest(key)[:24],
        "publication_kind": package["publication_kind"],
        "generated_at": package["generated_at"],
        "published_at": published_at,
        "window_start": package["window_start"],
        "window_end": package["window_end"],
        "input_digest": digest(package),
        "input": package,
        "topics": book["topics"],
        "plan": plan,
        "mode": mode,
        "story_versions": versions,
    }


def validate_input(package):
    from .editorial import validate_input as validate_base, INPUT_FIELDS
    from .publication import exact_fields, valid_id

    exact_fields(package, INPUT_FIELDS | META)
    validate_base({k: v for k, v in package.items() if k in INPUT_FIELDS})
    start, end, generated = (
        instant(package[k]) for k in ("window_start", "window_end", "generated_at")
    )
    kind = package["publication_kind"]
    if kind not in {"weekly", "update"} or not start < end <= generated:
        raise ValueError("Invalid publication window")
    if (kind == "weekly" and end - start != timedelta(days=7)) or (
        kind == "update" and end - start > timedelta(hours=72)
    ):
        raise ValueError("Invalid publication interval")
    if (
        not isinstance(package["covered_story_ids"], list)
        or len(package["covered_story_ids"]) > 1000
        or len(set(package["covered_story_ids"])) != len(package["covered_story_ids"])
    ):
        raise ValueError("Invalid editorial continuity")
    for uid in package["covered_story_ids"]:
        valid_id(uid)
    for r in package["records"] + package["news"]:
        if (
            kind == "weekly"
            and r.get("modified_at")
            and instant(r["modified_at"]) >= end
        ):
            raise ValueError("Source content postdates weekly cutoff")
        if not within(r, start, end, kind == "update"):
            if not changed_in_window(r, start, end, kind == "update"):
                raise ValueError("Historical evidence mislabeled as current")
        if kind == "update" and not significant(r):
            raise ValueError("Routine evidence in interim edition")
    return package


def validate_edition(value):
    from .publication import exact_fields

    fields = {
        "version",
        "id",
        "generated_at",
        "window_start",
        "window_end",
        "input_digest",
        "input",
        "topics",
        "plan",
        "mode",
        "publication_kind",
        "story_versions",
        "published_at",
    }
    exact_fields(value, fields)
    if value["mode"] not in {"ollama-source-grounded", "deterministic-fallback"}:
        raise ValueError("Invalid hybrid composition mode")
    if value != edition(
        value["input"], value["plan"], value["mode"], value["published_at"]
    ):
        raise ValueError("Hybrid edition provenance changed")
    return value


def prepare(snapshot, config=None):
    config = config or settings()
    history = substantive(snapshot)
    package = candidate(snapshot, config)
    status = "ready" if package else "quiet"
    if not any(s["status"] == "ok" for s in snapshot["sources"]):
        status = "source-failure"
    snapshot["collection"] = {
        "checked_at": snapshot["exported_at"],
        "status": status,
        "last_substantive_at": publication_time(history[0]) if history else None,
        "weekly_window_end": weekly_window(instant(snapshot["exported_at"]), config)[
            1
        ].isoformat(),
    }
    snapshot.setdefault("editions", [])
    snapshot["schema_version"] = 5
    return package


def refresh(snapshot, cache_dir=None, config=None, published_at=None):
    package = prepare(snapshot, config)
    if package is None:
        return snapshot
    value = edition(package)
    if cache_dir:
        try:
            cached = json.loads(
                (Path(cache_dir) / (value["id"] + ".json")).read_text(encoding="utf-8")
            )
            validate_edition(cached)
            if cached["input_digest"] == value["input_digest"]:
                value = cached
        except (OSError, ValueError, KeyError, TypeError):
            pass
    history = {e["id"]: e for e in snapshot["editions"]}
    value["published_at"] = published_at or snapshot["exported_at"]
    validate_edition(value)
    history.setdefault(value["id"], value)
    snapshot["editions"] = sorted(
        history.values(),
        key=lambda e: (publication_time(e), e.get("publication_kind") == "update"),
        reverse=True,
    )[:90]
    snapshot["collection"].update(
        status="published",
        last_substantive_at=publication_time(substantive(snapshot)[0]),
    )
    return snapshot


def validate_collection(snapshot):
    from .publication import exact_fields, stamp

    value = snapshot["collection"]
    exact_fields(value, COLLECTION_FIELDS)
    if value["checked_at"] != snapshot["exported_at"] or value["status"] not in {
        "ready",
        "quiet",
        "source-failure",
        "published",
    }:
        raise ValueError("Invalid collection status")
    if stamp(value["weekly_window_end"]) > stamp(value["checked_at"]):
        raise ValueError("Future weekly boundary")
    latest = substantive(snapshot)
    if value["last_substantive_at"] != (
        publication_time(latest[0]) if latest else None
    ):
        raise ValueError("Collection changed publication chronology")
    return value
