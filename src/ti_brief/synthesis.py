"""Version-5 executive synthesis from checked fact patterns.

Version 4 remains frozen. Interpretive formulations here are deliberately bounded:
no invented incidents, exploit success, urgency or specific mitigation claims.
"""

import re
from . import factual, executive


def plan(package):
    original = factual.plan(package)
    lead = executive.topics(package)[0]
    rows = {r["id"]: r for r in package["news"] + package["records"]}
    members = [rows[uid] for uid in lead["evidence_ids"]]
    if not all(
        executive.story_key(r).startswith("release:microsoft-patch-tuesday:")
        for r in members
    ):
        return None
    facts = {}
    for row in members:
        # Reuse the frozen, exact source-pattern validation, including subset checks.
        rendered = factual.finding(row)
        if "coverage lists" not in rendered:
            continue
        values = [v.replace(",", "") for v in re.findall(r"\b[\d,]+\b", rendered)]
        if len(values) == 3:
            facts[row["source"]] = (row, [f"{int(v):,}" for v in values])
    if set(facts) != {"cisco-talos", "sans-isc"}:
        return None
    talos, (total, critical, rce) = facts["cisco-talos"]
    sans, (sans_total, sans_critical, chromium) = facts["sans-isc"]
    if (
        int(rce.replace(",", "")) < 10
        or int(rce.replace(",", "")) * 2 < int(critical.replace(",", ""))
        or total == sans_total
        or int(chromium.replace(",", "")) == 0
    ):
        return None

    def claim(text, *ids):
        return {"text": text, "evidence_ids": list(ids)}

    # Derive the release month from the title identity, never the collection clock.
    month = factual.plan(package)["headline"].split("— ")[-1].split()[0]
    original["headline"] = (
        f"Remote Code Execution Dominates Microsoft’s {month} Critical Fixes"
    )
    original["overview"] = [
        [
            claim(
                "Critical code execution flaws account for much of the highest-severity work in Microsoft’s latest patch cycle, giving security teams a clearer focus than the headline vulnerability count alone.",
                talos["id"],
            ),
            claim(
                f"Cisco Talos identifies {rce} remote code execution vulnerabilities among {critical} critical issues—more than half of that critical subset.",
                talos["id"],
            ),
            claim(
                "That concentration makes the affected products an important starting point for assessing the release against an organization’s own systems.",
                talos["id"],
            ),
        ],
        [
            claim(
                f"The workload also extends to the browser estate: SANS ISC identifies {chromium} Chromium issues affecting Microsoft Edge.",
                sans["id"],
            ),
            claim(
                "For leaders, the distinction matters: critical code execution exposure and a broad browser update backlog call for different inventory and rollout decisions.",
                talos["id"],
                sans["id"],
            ),
            claim(
                "These release figures describe vulnerabilities, not confirmed compromises; they establish the scope of patch assessment rather than an organization’s incident status.",
                talos["id"],
                sans["id"],
            ),
        ],
    ]
    return original


def edition(package, published_at=None, revised_at=None):
    output = plan(package)
    if output is None:
        return None
    result = factual.edition(package, published_at, revised_at)
    result.update(
        version=5, mode="fact-bound-executive", headline=output["headline"], plan=output
    )
    return result


def automatic(package):
    # Existing independently reviewed prose takes precedence over mechanical prose.
    return executive.fallback(package) or edition(package) or factual.edition(package)


def validate_edition(value):
    expected = edition(
        value["input"], value.get("published_at"), value.get("revised_at")
    )
    if expected is None or value != expected:
        raise ValueError("Executive synthesis differs from its checked source facts")
    return value
