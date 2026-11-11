import copy
import json
import tempfile
import unittest
import re
from pathlib import Path
from unittest.mock import Mock, patch

from ti_brief.stix_store import StixStore, parse_objects
from ti_brief.stix_publication import project_context, permits, validate_context, empty_context
from ti_brief.taxii import Connection, TaxiiClient, TaxiiError, TaxiiDeferred, TaxiiHTTPError
from ti_brief.stix_platform import StixPlatform

try:
    import stix2
    import taxii2client

    AVAILABLE = True
except ImportError:
    AVAILABLE = False

FIXTURE = Path(__file__).parent / "fixtures/mitre-taxii.sample.json"


class FakeConnection:
    def __init__(self, pages):
        self.pages = pages
        self.calls = []
        self.headers = {}
        self.cross_origin = False

    def get(self, url, headers=None, params=None):
        self.calls.append((url, params))
        if url.endswith("/taxii2/"):
            root = "https://other.invalid/root/" if self.cross_origin else "/root/"
            return {"title": "Test TAXII", "default": root, "api_roots": [root]}
        if url.endswith("/root/"):
            return {
                "title": "Root",
                "versions": ["application/taxii+json;version=2.1"],
                "max_content_length": 8000000,
            }
        if url.endswith("/collections/"):
            return {
                "collections": [
                    {
                        "id": "enterprise",
                        "title": "Enterprise",
                        "can_read": True,
                        "can_write": False,
                        "media_types": ["application/stix+json;version=2.1"],
                    }
                ]
            }
        if "/objects/" in url:
            self.headers = {"x-taxii-date-added-last": "2026-11-10T12:00:00.000Z"}
            if params.get("added_after"):
                return {"objects": [], "more": False}
            token = params.get("next", "0")
            if isinstance(token, (tuple, list)):
                token = token[0]
            value = self.pages[int(token)]
            if isinstance(value, Exception):
                raise value
            return copy.deepcopy(value)
        raise AssertionError("Unexpected test URL")

    def close(self):
        pass


@unittest.skipUnless(AVAILABLE, "Install the optional [stix] dependencies")
class StixTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "intel.sqlite3"
        self.store = StixStore(self.path)
        self.bundle = json.loads(FIXTURE.read_text(encoding="utf-8"))
        self.objects = parse_objects(self.bundle)
        self.entity = next(
            o for o in self.objects if o["type"] not in {"marking-definition", "relationship"}
        )

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def client(self, connection):
        c = TaxiiClient(
            "https://taxii.example.org/taxii2/", self.store, "test", connection=connection
        )
        c.discover()
        c.select("enterprise")
        return c

    def test_recorded_public_bundle_preserves_relationship_and_source_versions(self):
        self.assertEqual(self.store.ingest("mitre-enterprise", self.objects), 4)
        self.assertEqual(self.store.ingest("mitre-enterprise", self.objects), 0)
        metadata = {
            "public": True,
            "discovery": "https://attack-taxii.mitre.org/taxii2/",
            "root": "https://attack-taxii.mitre.org/api/v21/",
            "collection": "x-mitre-collection--1f5f1533-f617-4ca8-9ab4-6a02367fa019",
            "last_success": "2026-11-11T12:00:00Z",
        }
        self.store.metadata("mitre-enterprise", metadata)
        result = project_context(self.path)
        self.assertEqual(len(result["relationships"]), 1)
        self.assertEqual(len(result["objects"]), 2)
        original = next(o for o in self.objects if o["type"] == "relationship")
        self.assertEqual(result["relationships"][0]["id"], original["id"])
        self.assertEqual(result["relationships"][0]["source_ref"], original["source_ref"])
        validate_context(result)
        for status in ["failed", "syncing"]:
            self.store.metadata("mitre-enterprise", {**metadata, "status": status})
            self.assertEqual(project_context(self.path)["objects"], [])
            cached = project_context(self.path, result)
            self.assertEqual(cached["objects"], result["objects"])
            self.assertEqual(cached["status"], "cached")
        metadata["public"] = False
        self.store.metadata("mitre-enterprise", metadata)
        self.assertEqual(project_context(self.path)["objects"], [])

    def test_versions_revocation_and_conflicts_are_atomic(self):
        self.store.ingest("test", [self.entity])
        update = {**self.entity, "modified": "2026-11-11T12:00:00.000Z", "revoked": True}
        self.store.ingest("test", [update])
        self.assertEqual(self.store.latest("test", True), [])
        self.assertEqual(len(self.store.latest("test")), 1)
        conflict = {**update, "name": "Conflicting same-version payload"}
        with self.assertRaises(ValueError):
            self.store.ingest("test", [conflict], ("entities", {"next": "bad"}))
        self.assertEqual(self.store.state("test", "entities"), {})
        self.assertEqual(
            self.store.db.execute("SELECT count(*) FROM stix_objects").fetchone()[0], 2
        )

    def test_supported_sdos_scos_and_report_references(self):
        stamp = "2026-01-01T00:00:00Z"
        common = {"created": stamp, "modified": stamp}
        sco = stix2.v21.IPv4Address(value="8.8.8.8")
        indicator = stix2.v21.Indicator(
            name="Synthetic indicator",
            pattern="[ipv4-addr:value = '8.8.8.8']",
            pattern_type="stix",
            valid_from=stamp,
            **common,
        )
        malware = stix2.v21.Malware(name="Synthetic family", is_family=True, **common)
        intrusion = stix2.v21.IntrusionSet(name="Synthetic group", **common)
        tool = stix2.v21.Tool(name="Synthetic tool", **common)
        vuln = stix2.v21.Vulnerability(name="CVE-2099-10001", **common)
        identity = stix2.v21.Identity(
            name="Synthetic source", identity_class="organization", **common
        )
        report = stix2.v21.Report(
            name="Synthetic report", published=stamp, object_refs=[indicator.id, vuln.id], **common
        )
        edge = stix2.v21.Relationship(
            relationship_type="uses", source_ref=intrusion.id, target_ref=malware.id, **common
        )
        raw = [
            json.loads(o.serialize())
            for o in [sco, indicator, malware, intrusion, tool, vuln, identity, report, edge]
        ]
        self.store.ingest("bundle-test", raw)
        stored = {o["id"]: o for o in self.store.latest("bundle-test")}
        self.assertEqual(stored[report.id]["object_refs"], [indicator.id, vuln.id])
        self.assertEqual(stored[edge.id]["target_ref"], malware.id)
        broken = copy.deepcopy(self.entity)
        broken.pop("modified")
        with self.assertRaises(ValueError):
            parse_objects(broken)
        broken = copy.deepcopy(self.entity)
        broken["spec_version"] = "2.0"
        with self.assertRaises(ValueError):
            parse_objects(broken)

    def test_markings_unknown_granular_revoked_and_deprecated_fail_closed(self):
        definitions = {o["id"]: o for o in self.objects if o["type"] == "marking-definition"}
        self.assertTrue(permits(self.entity, definitions))
        for change in [
            {"revoked": True},
            {"x_mitre_deprecated": True},
            {"granular_markings": [{"selectors": ["name"]}]},
            {"object_marking_refs": ["marking-definition--00000000-0000-4000-8000-000000000001"]},
            {"object_marking_refs": []},
        ]:
            self.assertFalse(permits({**self.entity, **change}, definitions))
        marking = next(iter(definitions.values()))
        definitions[marking["id"]] = {**marking, "definition": {"statement": "Do not redistribute"}}
        self.assertFalse(permits(self.entity, definitions))
        for name, mark in [("white", stix2.v21.TLP_WHITE), ("amber", stix2.v21.TLP_AMBER)]:
            raw = json.loads(mark.serialize())
            node = {**self.entity, "object_marking_refs": [raw["id"]]}
            self.assertEqual(permits(node, {raw["id"]: raw}), name == "white")

    def test_discovery_pagination_resume_and_incremental_checkpoint(self):
        update = {**self.entity, "modified": "2026-11-11T12:00:00.000Z"}
        conn = FakeConnection(
            [
                {"objects": [self.entity], "more": True, "next": "1"},
                {"objects": [update], "more": False},
            ]
        )
        client = self.client(conn)
        result = client.sync_stream("entities", ["attack-pattern"], 1, 1, "release")
        self.assertTrue(result["pending"])
        self.assertEqual(self.store.state("test", "entities")["next"], "1")
        self.assertNotIn("after", self.store.state("test", "entities"))
        result = client.sync_stream("entities", ["attack-pattern"], 1, 1, "release")
        self.assertFalse(result["pending"])
        self.assertIn("after", self.store.state("test", "entities"))
        result = client.sync_stream("entities", ["attack-pattern"], 1, 1, "release")
        self.assertEqual(result["new_versions"], 0)
        self.assertIn("added_after", conn.calls[-1][1])
        self.assertEqual(
            self.store.db.execute("SELECT count(*) FROM stix_objects").fetchone()[0], 2
        )

    def test_changed_page_size_or_release_replays_without_skipping(self):
        conn = FakeConnection(
            [{"objects": [self.entity], "more": True, "next": "1"}, {"objects": [], "more": False}]
        )
        client = self.client(conn)
        client.sync_stream("entities", ["attack-pattern"], 1, 1, "release")
        client.sync_stream("entities", ["attack-pattern"], 1, 2, "release")
        self.assertNotIn("next", conn.calls[-1][1])
        client.sync_stream("entities", ["attack-pattern"], 1, 2, "new-release")
        self.assertNotIn("next", conn.calls[-1][1])

    def test_failed_or_invalid_page_does_not_acknowledge_cursor(self):
        bad = {**self.entity, "spec_version": "2.0"}
        conn = FakeConnection([{"objects": [bad], "more": False}])
        client = self.client(conn)
        with self.assertRaises(ValueError):
            client.sync_stream("entities", ["attack-pattern"], 1, 1)
        self.assertEqual(self.store.state("test", "entities"), {})
        conn.pages = [
            {"objects": [self.entity], "more": True, "next": "1"},
            {"objects": [self.entity], "more": True, "next": "1"},
        ]
        client.sync_stream("entities", ["attack-pattern"], 1, 1)
        with self.assertRaises(TaxiiError):
            client.sync_stream("entities", ["attack-pattern"], 1, 1)
        self.assertEqual(self.store.state("test", "entities")["next"], "1")

    def test_expired_token_queues_replay_without_advancing_watermark(self):
        conn = FakeConnection(
            [{"objects": [self.entity], "more": True, "next": "1"}, TaxiiHTTPError(400)]
        )
        client = self.client(conn)
        client.sync_stream("entities", ["attack-pattern"], 1, 1)
        with self.assertRaises(TaxiiDeferred):
            client.sync_stream("entities", ["attack-pattern"], 1, 1)
        self.assertNotIn("next", self.store.state("test", "entities"))
        self.assertNotIn("after", self.store.state("test", "entities"))

    def test_cross_origin_discovery_cannot_forward_credentials(self):
        conn = FakeConnection([])
        conn.cross_origin = True
        client = TaxiiClient(
            "https://taxii.example.org/taxii2/", self.store, "test", connection=conn
        )
        with self.assertRaises(TaxiiError):
            client.discover()
        self.assertEqual(len(conn.calls), 1)

    def test_private_feed_credentials_are_not_sent_to_public_mitre_job(self):
        from scripts.sync_taxii import main

        client = Mock()
        client.discover.return_value = {"collections": []}
        with (
            patch("scripts.sync_taxii.TaxiiClient", return_value=client) as factory,
            patch.dict("os.environ", {"TAXII_TOKEN": "private-test-token"}),
            patch("builtins.print"),
        ):
            self.assertEqual(main(["--discover", "--database", str(self.path)]), 0)
            self.assertEqual(factory.call_args.kwargs, {})

    def test_rate_limit_budget_and_redacted_errors(self):
        conn = Connection(
            "https://taxii.example.org/taxii2/",
            self.store,
            token="test-secret",
            clock=lambda: 1000,
            sleeper=Mock(),
        )
        with self.assertRaises(TaxiiError):
            conn.get("https://other.example.org/objects/")
        for _ in range(35):
            conn.charge()
        with self.assertRaises(TaxiiDeferred):
            conn.charge()
        self.store.db.execute("DELETE FROM taxii_requests")
        self.store.db.commit()
        response = Mock()
        response.__enter__ = Mock(return_value=response)
        response.__exit__ = Mock(return_value=False)
        response.status_code = 429
        response.headers = {"Retry-After": "600"}
        conn.session.get = Mock(return_value=response)
        with self.assertRaises(TaxiiDeferred) as result:
            conn.get("https://taxii.example.org/objects/")
        self.assertNotIn("test-secret", str(result.exception))
        conn.sleep.assert_not_called()
        conn.close()

    def test_public_schema_rejects_private_fields_and_dangling_relationships(self):
        value = empty_context()
        value["token"] = "secret"
        with self.assertRaises(ValueError):
            validate_context(value)
        value = empty_context()
        value["relationships"] = [
            {
                "id": "relationship--00000000-0000-4000-8000-000000000001",
                "source_ref": self.entity["id"],
                "target_ref": self.entity["id"],
                "relationship_type": "uses",
                "modified": self.entity["modified"],
            }
        ]
        with self.assertRaises(ValueError):
            validate_context(value)

    def test_unversioned_observable_variants_preserve_payloads_without_fake_timestamps(self):
        raw = json.loads(stix2.v21.IPv4Address(value="8.8.8.8").serialize())
        self.store.ingest("local", [{**raw, "x_test_context": "first"}])
        self.store.ingest("local", [{**raw, "x_test_context": "second"}])
        self.assertEqual(self.store.latest("local")[0]["x_test_context"], "second")
        self.assertNotIn("modified", self.store.latest("local")[0])
        self.assertEqual(
            self.store.db.execute("SELECT count(*) FROM stix_objects").fetchone()[0], 2
        )

    def test_platform_bridge_reads_back_source_ids_and_endpoints_then_deduplicates(self):
        self.store.ingest("mitre-enterprise", self.objects)
        self.store.metadata("mitre-enterprise", {"public": True})

        class Platform:
            def __init__(self):
                self.nodes = {}
                self.writes = 0

            def json(self, url, payload, headers):
                query = payload["query"]
                variables = payload["variables"]
                if "mutation" in query:
                    field = re.search(r"\{ (\w+)\(input:", query)[1]
                    value = variables["input"]
                    if field == "externalReferenceAdd":
                        return {"data": {field: {"id": "reference"}}}
                    uid = "native-" + value["stix_id"]
                    self.nodes[uid] = value
                    self.writes += 1
                    return {"data": {field: {"id": uid}}}
                uid = variables["id"]
                raw = self.nodes[uid]
                field = (
                    "stixCoreRelationship"
                    if "stixCoreRelationship(" in query
                    else "stixDomainObject"
                )
                node = {
                    "id": uid,
                    "standard_id": "canonical",
                    "x_opencti_stix_ids": [raw["stix_id"]],
                    "name": raw.get("name"),
                }
                if "relationship_type" in raw:
                    node.update(
                        relationship_type=raw["relationship_type"],
                        **{"from": {"id": raw["fromId"]}, "to": {"id": raw["toId"]}},
                    )
                return {"data": {field: node}}

        http = Platform()
        bridge = StixPlatform(http, "http://127.0.0.1:8080", "test-only", self.store)
        first = bridge.synchronize(limit=3)
        second = bridge.synchronize(limit=3)
        self.assertEqual(first["upserted_and_verified"], 3)
        self.assertEqual(second["upserted_and_verified"], 0)
        self.assertEqual(http.writes, 3)

    def test_failed_readback_does_not_checkpoint_platform_version(self):
        self.store.ingest("mitre-enterprise", self.objects)
        self.store.metadata("mitre-enterprise", {"public": True})
        http = Mock()
        bridge = StixPlatform(http, "http://127.0.0.1:8080", "test-only", self.store)
        bridge.add = Mock(return_value="native")
        bridge.verify = Mock(side_effect=RuntimeError("readback failed"))
        with self.assertRaises(RuntimeError):
            bridge.synchronize(limit=3)
        self.assertEqual(
            self.store.db.execute("SELECT count(*) FROM platform_versions").fetchone()[0], 0
        )

    def test_optional_ingestion_and_bridge_failures_do_not_suppress_publication(self):
        from scripts import daily_staged

        with (
            patch.dict(
                "os.environ",
                {
                    "TI_TAXII_ENABLED": "true",
                    "TI_STIX_OPENCTI_ENABLED": "true",
                    "TI_PUBLICATION_ENABLED": "true",
                },
                clear=True,
            ),
            patch.object(daily_staged, "load_env"),
            patch.object(daily_staged, "orchestrate", return_value=0),
            patch.object(
                daily_staged,
                "invoke",
                side_effect=[
                    RuntimeError("source unavailable"),
                    RuntimeError("platform unavailable"),
                    None,
                    RuntimeError("model unavailable"),
                    None,
                ],
            ) as invoke,
            patch("builtins.print"),
        ):
            self.assertEqual(daily_staged.main(["--manage-project"]), 0)
            self.assertEqual(invoke.call_count, 5)
            self.assertEqual(
                invoke.call_args.args[0][1:], ["scripts/export_publication.py", "--publish-prepared"]
            )

    def test_scheduler_help_has_no_collection_or_environment_side_effects(self):
        import io
        from contextlib import redirect_stdout
        from scripts import daily_staged

        with (
            patch.object(daily_staged, "invoke") as invoke,
            patch.object(daily_staged, "load_env") as load_env,
            redirect_stdout(io.StringIO()),
        ):
            with self.assertRaises(SystemExit) as result:
                daily_staged.main(["--help"])
            self.assertEqual(result.exception.code, 0)
            invoke.assert_not_called()
            load_env.assert_not_called()


if __name__ == "__main__":
    unittest.main()
