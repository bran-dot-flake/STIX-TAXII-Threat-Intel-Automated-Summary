"""Small original-source STIX projection; private feed/bundle imports stay local."""

import re
from collections import Counter
from pathlib import Path
from .stix_store import StixStore, stix_id

MITRE_MARKING = "marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168"
MITRE_STATEMENT = "Copyright 2015-2026, The MITRE Corporation. MITRE ATT&CK and ATT&CK are registered trademarks of The MITRE Corporation."
TYPES = {
    "attack-pattern",
    "intrusion-set",
    "malware",
    "tool",
    "report",
    "vulnerability",
    "indicator",
}
LICENSE = "https://attack.mitre.org/resources/terms-of-use/"
NODE_FIELDS = {"id", "type", "name", "external_id", "url", "modified", "tactics"}
EDGE_FIELDS = {"id", "source_ref", "target_ref", "relationship_type", "modified"}
CONTEXT_FIELDS = {
    "source",
    "collected_at",
    "status",
    "objects",
    "relationships",
    "counts",
    "license",
}


def empty_context():
    return {
        "source": "mitre-enterprise",
        "collected_at": None,
        "status": "unavailable",
        "objects": [],
        "relationships": [],
        "counts": {},
        "license": LICENSE,
    }


def permits(obj, definitions):
    if obj.get("revoked") or obj.get("x_mitre_deprecated") or obj.get("granular_markings"):
        return False
    refs = obj.get("object_marking_refs", [])
    if not refs:
        return False
    for ref in refs:
        marking = definitions.get(ref, {})
        definition = marking.get("definition", {})
        if marking.get("definition_type") == "tlp" and definition.get("tlp") in {"white", "clear"}:
            continue
        if (
            ref == MITRE_MARKING
            and marking.get("definition_type") == "statement"
            and definition == {"statement": MITRE_STATEMENT}
        ):
            continue
        return False
    return True


def attack_reference(obj):
    patterns = {
        "attack-pattern": r"T\d{4}(?:\.\d{3})?",
        "intrusion-set": r"G\d{4}",
        "malware": r"S\d{4}",
        "tool": r"S\d{4}",
    }
    paths = {
        "attack-pattern": "techniques",
        "intrusion-set": "groups",
        "malware": "software",
        "tool": "software",
    }
    for ref in obj.get("external_references", []):
        external = ref.get("external_id", "")
        if ref.get("source_name") == "mitre-attack" and re.fullmatch(
            patterns.get(obj["type"], r"(?!)"), external
        ):
            expected = (
                "https://attack.mitre.org/"
                + paths[obj["type"]]
                + "/"
                + external.replace(".", "/")
                + "/"
            )
            if ref.get("url", "").rstrip("/") == expected.rstrip("/"):
                return external, expected
    return None


def project_context(path, previous=None):
    from .publication import clean_text

    previous = previous or empty_context()
    if not Path(path).exists():
        return previous
    store = StixStore(path)
    try:
        metadata = store.metadata("mitre-enterprise")
        if metadata.get("status") in {"failed", "syncing"}:
            return {
                **previous,
                "status": "cached" if previous.get("collected_at") else "unavailable",
            }
        if not (
            metadata.get("public") is True
            and metadata.get("discovery") == "https://attack-taxii.mitre.org/taxii2/"
            and metadata.get("collection")
            == "x-mitre-collection--1f5f1533-f617-4ca8-9ab4-6a02367fa019"
            and metadata.get("root", "").rstrip("/") == "https://attack-taxii.mitre.org/api/v21"
        ):
            return previous
        definitions = {
            o["id"]: o
            for o in store.iter_latest("mitre-enterprise")
            if o["type"] == "marking-definition"
        }
        nodes = {}
        for obj in store.iter_latest("mitre-enterprise"):
            if obj["type"] not in TYPES or not permits(obj, definitions):
                continue
            reference = attack_reference(obj)
            if not reference:
                continue
            try:
                nodes[obj["id"]] = {
                    "id": obj["id"],
                    "type": obj["type"],
                    "name": clean_text(obj["name"], 240),
                    "external_id": reference[0],
                    "url": reference[1],
                    "modified": obj["modified"],
                    "tactics": sorted(
                        {
                            clean_text(p["phase_name"], 80)
                            for p in obj.get("kill_chain_phases", [])
                            if p.get("kill_chain_name") == "mitre-attack"
                        }
                    ),
                }
            except (ValueError, KeyError):
                continue
        edges = []
        for obj in store.iter_latest("mitre-enterprise"):
            if obj["type"] != "relationship" or not permits(obj, definitions):
                continue
            if obj["source_ref"] in nodes and obj["target_ref"] in nodes:
                edges.append({k: obj[k] for k in EDGE_FIELDS})
        edges.sort(key=lambda r: r["modified"], reverse=True)
        edges = edges[:60]
        # Include both ends of each displayed source relationship before filling
        # the remaining compact catalog. Never display unresolved links.
        selected = set(r[k] for r in edges for k in ("source_ref", "target_ref"))
        for obj in sorted(nodes.values(), key=lambda r: (r["modified"], r["id"]), reverse=True):
            if len(selected) >= 160:
                break
            selected.add(obj["id"])
        output = [nodes[k] for k in sorted(selected)]
        result = {
            "source": "mitre-enterprise",
            "collected_at": metadata["last_success"],
            "status": "cached" if metadata.get("status") == "failed" else "ok",
            "objects": output,
            "relationships": edges,
            "counts": dict(Counter(r["type"] for r in output)),
            "license": LICENSE,
        }
        validate_context(result)
        return result
    finally:
        store.close()


def validate_context(value):
    from .publication import clean_text, exact_fields, stamp

    exact_fields(value, CONTEXT_FIELDS)
    if (
        value["source"] != "mitre-enterprise"
        or value["license"] != LICENSE
        or value["status"] not in {"ok", "cached", "unavailable"}
    ):
        raise ValueError("Invalid public STIX source")
    if value["collected_at"]:
        stamp(value["collected_at"])
    if (
        not isinstance(value["objects"], list)
        or not isinstance(value["relationships"], list)
        or len(value["objects"]) > 160
        or len(value["relationships"]) > 60
    ):
        raise ValueError("Oversized public STIX context")
    lookup = {}
    for obj in value["objects"]:
        exact_fields(obj, NODE_FIELDS)
        stix_id(obj["id"], obj["type"])
        if obj["id"] in lookup or obj["type"] not in TYPES:
            raise ValueError("Invalid public STIX object")
        clean_text(obj["name"], 240)
        stamp(obj["modified"])
        expected = attack_reference(
            {
                "type": obj["type"],
                "external_references": [
                    {
                        "source_name": "mitre-attack",
                        "external_id": obj["external_id"],
                        "url": obj["url"],
                    }
                ],
            }
        )
        if not expected:
            raise ValueError("Invalid public ATT&CK reference")
        if not isinstance(obj["tactics"], list) or len(obj["tactics"]) > 20:
            raise ValueError("Invalid tactics")
        for tactic in obj["tactics"]:
            clean_text(tactic, 80)
        lookup[obj["id"]] = obj
    ids = set()
    for edge in value["relationships"]:
        exact_fields(edge, EDGE_FIELDS)
        stix_id(edge["id"], "relationship")
        stamp(edge["modified"])
        if (
            edge["id"] in ids
            or edge["source_ref"] not in lookup
            or edge["target_ref"] not in lookup
        ):
            raise ValueError("Unresolved or duplicate public relationship")
        if not re.fullmatch("[a-z][a-z0-9-]{0,60}", edge["relationship_type"]):
            raise ValueError("Invalid relationship type")
        ids.add(edge["id"])
    if value["counts"] != dict(Counter(o["type"] for o in lookup.values())):
        raise ValueError("STIX counts disagree")
