import uuid
import re
from .http import RemoteError

NAMESPACE = uuid.UUID("827fc62c-9739-43ec-a55b-5f758b832f4a")


def event_uuid(record):
    return str(uuid.uuid5(NAMESPACE, record.key))


def misp_event(record):
    category = "External analysis" if record.kind == "vulnerability" else "Network activity"
    if record.kind in {"md5", "sha1", "sha256"}:
        category = "Payload delivery"
    attributes = []
    for kind, value, cat in ((record.kind, record.value, category), ("link", record.source_url, "External analysis")):
        attributes.append({"uuid": str(uuid.uuid5(NAMESPACE, record.key + kind + value)),
                           "type": kind, "category": cat, "value": value, "to_ids": False,
                           "comment": f"Source: {record.source}. {record.description}\nPublished/catalog-added: {record.published_at or 'unknown'}. Occurred: {record.occurred_at or 'unknown'}"})
    return {"Event": {"uuid": event_uuid(record), "info": record.title, "distribution": 0,
                       "threat_level_id": 4, "analysis": 0, "published": False, "Attribute": attributes}}


class Misp:
    def __init__(self, http, url, token):
        self.http, self.url, self.headers = http, url.rstrip("/"), {"Authorization": token}

    def sync(self, record):
        uid = event_uuid(record)
        found = self.http.json(self.url + "/events/restSearch", {"returnFormat": "json", "uuid": uid, "limit": 1}, self.headers)
        if not isinstance(found, dict) or not isinstance(found.get("response"), list):
            raise RemoteError("Unexpected MISP search response")
        path = "/events/edit/" + uid if found["response"] else "/events/add"
        result = self.http.json(self.url + path, misp_event(record), self.headers)
        if not isinstance(result, dict) or result.get("Event", {}).get("uuid") != uid:
            raise RemoteError("MISP did not confirm the expected event UUID")
        return uid

    def read(self, record):
        result = self.http.json(self.url + "/events/view/" + event_uuid(record), headers=self.headers)
        if not isinstance(result, dict) or result.get("Event", {}).get("uuid") != event_uuid(record):
            raise RemoteError("MISP read-back did not confirm event")
        attrs = result["Event"].get("Attribute", [])
        if not any(a.get("type") == record.kind and a.get("value") == record.value for a in attrs):
            raise RemoteError("MISP read-back missing expected indicator")
        return {"event_uuid": event_uuid(record), "verified": True}


class OpenCti:
    def __init__(self, http, url, token):
        self.http, self.url, self.headers = http, url.rstrip("/"), {"Authorization": "Bearer " + token}

    def context(self, record):
        # Search candidates are operational context, never asserted as relationships.
        query = """query BriefContext($search: String!) {
          stixDomainObjects(first: 5, search: $search) {
            edges { node { id entity_type ... on Vulnerability { name }
              ... on Indicator { name pattern } ... on Report { name }
              externalReferences(first: 10) { edges { node { source_name external_id url } } }
            } }
          }
        }"""
        result = self.http.json(self.url + "/graphql", {"query": query, "variables": {"search": record.value}}, self.headers)
        if result.get("errors") or not isinstance(result.get("data", {}).get("stixDomainObjects", {}).get("edges"), list):
            raise RemoteError("OpenCTI context query failed")
        nodes = [edge["node"] for edge in result["data"]["stixDomainObjects"]["edges"]]
        paths = {"ip-dst": "ipv4-addr:value" if ":" not in record.value else "ipv6-addr:value",
                 "domain": "domain-name:value", "url": "url:value", "md5": "file:hashes.'MD5'",
                 "sha1": "file:hashes.'SHA-1'", "sha256": "file:hashes.'SHA-256'"}
        value = record.value.replace("\\", "\\\\").replace("'", "\\'")
        expected = rf"\[\s*{re.escape(paths.get(record.kind, ''))}\s*=\s*'{re.escape(value)}'\s*\]"
        verified = []
        for node in nodes:
            exact = (record.kind == "vulnerability" and node.get("entity_type") == "Vulnerability" and node.get("name") == record.value) or (
                node.get("entity_type") == "Indicator" and record.kind in paths and re.fullmatch(expected, node.get("pattern") or ""))
            references = node.get("externalReferences", {}).get("edges", [])
            provenance = any(event_uuid(record) in str(edge["node"].get("url", "")) or edge["node"].get("external_id") == event_uuid(record) for edge in references)
            if exact and provenance:
                verified.append(node["id"])
        return {"candidates": nodes, "verified_sync_ids": verified,
                "note": "Only exact indicator/CVE matches carrying the MISP event UUID count as synchronized. No relationships inferred."}
