"""Automatic, attributed weekly facts. No model prose or self-approval.

Every accepted byte is recomputed from the frozen validated source package.
Unknown story types use explicitly attributed titles, not invented analysis.
"""

import copy, re
from .editorial import digest
from .topics import instant
from . import executive as e

NAMES = {
    "sans-isc": "SANS ISC",
    "cisco-talos": "Cisco Talos",
    "google-gti": "Google GTI",
    "cisa-advisories": "CISA",
    "cisa-kev": "CISA KEV",
}


def short_title(row):
    text = re.sub(r",\s*\([A-Za-z]{3},.*?\)$", "", row["title"]).strip()
    words = text.split()
    return " ".join(words[:12]) + ("…" if len(words) > 12 else "")


def finding(row):
    source = NAMES.get(row["source"], row["source"])
    text = row.get("excerpt", "")

    def number(value):
        return f"{int(value.replace(',','')):,}"

    # Exact source-specific patterns preserve units, scope and the critical/RCE
    # subset relationship. Matching a number elsewhere is not sufficient.
    if row["source"] == "cisco-talos":
        m = re.fullmatch(
            r'Microsoft has released its monthly security update for [A-Za-z]+ \d{4}, which includes (?P<total>[\d,]+) vulnerabilities affecting a range of products, including (?P<critical>[\d,]+) that Microsoft marked as "critical\." Out of (?P<critical_again>[\d,]+) "critical" vulnerabilities, (?P<rce>[\d,]+) are remote code execution \(RCE\) vulnerabilities\.',
            text,
        )
        if (
            m
            and m["critical"] == m["critical_again"]
            and int(m["rce"].replace(",", ""))
            <= int(m["critical"].replace(",", ""))
            <= int(m["total"].replace(",", ""))
        ):
            return f"Cisco Talos’s Microsoft update coverage lists {number(m['total'])} vulnerabilities, including {number(m['critical'])} critical issues and {number(m['rce'])} critical remote code execution vulnerabilities."
    if row["source"] == "sans-isc":
        m = re.fullmatch(
            r"Microsoft continues its AI-induced patch surge, addressing (?P<total>[\d,]+) different vulnerabilities this month\. (?P<critical>[\d,]+) of these vulnerabilities are considered critical\. (?P<chromium>[\d,]+) of the vulnerabilities are Chromium issues affecting Microsoft Edge\.",
            text,
        )
        if (
            m
            and int(m["critical"].replace(",", "")) <= int(m["total"].replace(",", ""))
            and int(m["chromium"].replace(",", "")) <= int(m["total"].replace(",", ""))
        ):
            return f"SANS ISC’s Microsoft update coverage lists {number(m['total'])} vulnerabilities and {number(m['critical'])} critical issues; it identifies {number(m['chromium'])} Chromium issues affecting Microsoft Edge."
    if row.get("kind") == "vulnerability":
        return f"CISA KEV records {row['value']} as a catalog addition dated {row['published_at'][:10]}."
    return f"{source} published a report titled “{short_title(row)}”."


def plan(package):
    rows = {r["id"]: r for r in package["news"] + package["records"]}
    ts = e.topics(package)
    if not ts:
        raise ValueError("No factual weekly evidence")
    groups = []
    for topic in ts:
        members = [rows[uid] for uid in topic["evidence_ids"]]
        atoms = [{"text": finding(r), "evidence_ids": [r["id"]]} for r in members]
        groups.append((topic, members, atoms))
    topic, members, lead = groups[0]
    if e.story_key(members[0]).startswith("release:microsoft-patch-tuesday:"):
        from datetime import datetime

        release = e.story_key(members[0]).rsplit(":", 1)[1]
        headline = "Microsoft Patch Tuesday — " + datetime.strptime(
            release, "%Y-%m"
        ).strftime("%B %Y")
    else:
        headline = short_title(members[0])
    overview = [[atom] for atom in lead[:2]]
    if len(lead) == 1 and len(groups) > 1:
        overview.append([groups[1][2][0]])
    supporting = []
    for topic, members, atoms in groups:
        supporting.append(
            {
                "topic_id": topic["id"],
                "headline": short_title(members[0]),
                "summary": atoms[0],
            }
        )
    return {"headline": headline, "overview": overview, "topics": supporting}


def edition(package, published_at=None, revised_at=None):
    e.validate_input(package)
    healthy = {r["id"] for r in package["sources"] if r["status"] == "ok"}
    for row in package["news"] + package["records"]:
        if row["source"] not in healthy or not e.eligible(
            row, instant(package["window_start"]), instant(package["window_end"])
        ):
            raise ValueError("Ineligible factual weekly evidence")
    if published_at and instant(published_at) < instant(package["generated_at"]):
        raise ValueError("Publication precedes evidence")
    if revised_at and (not published_at or instant(revised_at) < instant(published_at)):
        raise ValueError("Invalid revision")
    output = plan(package)
    topics = [
        {
            **t,
            "headline": next(
                r["headline"] for r in output["topics"] if r["topic_id"] == t["id"]
            ),
        }
        for t in e.topics(package)
    ]
    return {
        "version": 4,
        "id": digest("editorial:weekly:" + package["window_end"])[:24],
        "publication_kind": "weekly",
        "generated_at": package["generated_at"],
        "published_at": published_at,
        "revised_at": revised_at,
        "window_start": package["window_start"],
        "window_end": package["window_end"],
        "input_digest": digest(package),
        "input": copy.deepcopy(package),
        "topics": topics,
        "headline": output["headline"],
        "plan": output,
        "mode": "deterministic-factual",
        "approval_id": None,
        "evidence_digest": e.evidence_digest(package),
    }


def validate_edition(value):
    expected = edition(
        value["input"], value.get("published_at"), value.get("revised_at")
    )
    if value != expected:
        raise ValueError("Factual weekly differs from verified source rendering")
    return value
