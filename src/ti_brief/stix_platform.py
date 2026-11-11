"""Bounded MITRE catalog bridge via supported OpenCTI native upserts/read-back.

MISP continues to own the existing IOC path. This separate writer imports only
the approved MITRE catalog entity types and source relationships, never IOCs.
"""

import hashlib
import json
from .http import RemoteError
from .stix_publication import permits, attack_reference

MUTATIONS = {
    "attack-pattern": ("attackPatternAdd", "AttackPatternAddInput"),
    "intrusion-set": ("intrusionSetAdd", "IntrusionSetAddInput"),
    "malware": ("malwareAdd", "MalwareAddInput"),
    "tool": ("toolAdd", "ToolAddInput"),
}


class StixPlatform:
    def __init__(self, http, url, token, store):
        self.http, self.url, self.store = http, url.rstrip("/"), store
        self.headers = {"Authorization": "Bearer " + token}

    def query(self, query, variables):
        response = self.http.json(
            self.url + "/graphql", {"query": query, "variables": variables}, self.headers
        )
        if response.get("errors") or not isinstance(response.get("data"), dict):
            raise RemoteError("OpenCTI STIX bridge request failed")
        return response["data"]

    def add(self, field, input_type, value):
        result = self.query(
            "mutation Add($input: " + input_type + "!) { " + field + "(input:$input) { id } }",
            {"input": value},
        )
        node = result.get(field)
        if not isinstance(node, dict) or not node.get("id"):
            raise RemoteError("OpenCTI did not confirm upsert")
        return node["id"]

    def verify(self, uid, raw, relation=False):
        if relation:
            query = """query Verify($id: String!) { stixCoreRelationship(id:$id) {
                id standard_id x_opencti_stix_ids relationship_type
                from { ... on BasicObject { id } } to { ... on BasicObject { id } }
            } }"""
            field = "stixCoreRelationship"
        else:
            query = """query Verify($id: String!) { stixDomainObject(id:$id) {
                id standard_id x_opencti_stix_ids ... on AttackPattern { name }
                ... on IntrusionSet { name } ... on Malware { name } ... on Tool { name }
            } }"""
            field = "stixDomainObject"
        node = self.query(query, {"id": uid}).get(field)
        if not node or raw["id"] not in [
            node.get("standard_id"),
            *(node.get("x_opencti_stix_ids") or []),
        ]:
            raise RemoteError("OpenCTI read-back lost source STIX identity")
        if not relation and node.get("name") != raw["name"]:
            raise RemoteError("OpenCTI entity read-back mismatch")
        return node

    def synchronize(self, source="mitre-enterprise", limit=20):
        metadata = self.store.metadata(source)
        if (
            not metadata.get("public")
            or source != "mitre-enterprise"
            or metadata.get("status") in {"failed", "syncing"}
        ):
            raise ValueError("Bridge accepts approved MITRE catalog only")
        definitions = {
            o["id"]: o for o in self.store.iter_latest(source) if o["type"] == "marking-definition"
        }
        approved = {
            o["id"]: o
            for o in self.store.iter_latest(source)
            if o["type"] in {*MUTATIONS, "relationship"} and permits(o, definitions)
        }
        nodes = {
            k: o for k, o in approved.items() if o["type"] in MUTATIONS and attack_reference(o)
        }
        edges = [
            o
            for o in approved.values()
            if o["type"] == "relationship" and o["source_ref"] in nodes and o["target_ref"] in nodes
        ]
        # Import endpoints before relations, with a bounded mutation budget.
        ordered = []
        for edge in sorted(edges, key=lambda o: o["id"]):
            ordered.extend([nodes[edge["source_ref"]], nodes[edge["target_ref"]], edge])
        ordered.extend(nodes.values())
        attempted = set()
        remote = {}
        changed = verified = 0
        for raw in ordered:
            if raw["id"] in attempted:
                continue
            attempted.add(raw["id"])
            version = hashlib.sha256(json.dumps(raw, sort_keys=True).encode()).hexdigest()
            prior = self.store.db.execute(
                "SELECT version,remote_id FROM platform_versions WHERE source=? AND id=? AND platform='opencti'",
                (source, raw["id"]),
            ).fetchone()
            if prior and prior["version"] == version:
                remote[raw["id"]] = prior["remote_id"]
                continue
            if changed >= limit:
                break
            relation = raw["type"] == "relationship"
            if relation and not all(k in remote for k in (raw["source_ref"], raw["target_ref"])):
                continue
            value = {
                k: raw[k]
                for k in ["created", "modified", "revoked", "description", "confidence"]
                if k in raw
            }
            value.update(stix_id=raw["id"], update=True)
            reference = attack_reference(raw) if not relation else None
            if reference:
                ref = self.add(
                    "externalReferenceAdd",
                    "ExternalReferenceAddInput",
                    {
                        "source_name": "mitre-attack",
                        "external_id": reference[0],
                        "url": reference[1],
                        "update": True,
                    },
                )
                value.update(name=raw["name"], externalReferences=[ref])
                if raw["type"] == "attack-pattern":
                    value["x_mitre_id"] = reference[0]
                if raw["type"] == "malware":
                    value["is_family"] = raw.get("is_family", False)
                field, input_type = MUTATIONS[raw["type"]]
            else:
                value.update(
                    fromId=remote[raw["source_ref"]],
                    toId=remote[raw["target_ref"]],
                    relationship_type=raw["relationship_type"],
                )
                field, input_type = "stixCoreRelationshipAdd", "StixCoreRelationshipAddInput"
            uid = self.add(field, input_type, value)
            readback = self.verify(uid, raw, relation)
            if relation and (
                readback.get("relationship_type") != raw["relationship_type"]
                or readback.get("from", {}).get("id") != remote[raw["source_ref"]]
                or readback.get("to", {}).get("id") != remote[raw["target_ref"]]
            ):
                raise RemoteError("OpenCTI relationship read-back mismatch")
            with self.store.db:
                self.store.db.execute(
                    "INSERT OR REPLACE INTO platform_versions VALUES(?,?,?,'opencti',?)",
                    (source, raw["id"], version, uid),
                )
            remote[raw["id"]] = uid
            changed += 1
            verified += 1
        return {"upserted_and_verified": verified, "checkpointed": len(remote)}
