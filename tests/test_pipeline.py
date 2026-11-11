import importlib.util
import json
import os
import sqlite3
import tempfile
import threading
import unittest
from dataclasses import asdict, replace
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

from ti_brief.cli import main, run_lock
from ti_brief.feeds import circl_records, demo_records, feodo_records, kev_records
from ti_brief.http import Http, RemoteError
from ti_brief.model import Record, canonical
from ti_brief.platforms import Misp, OpenCti, event_uuid, misp_event
from ti_brief.report import excerpt_options, llm_select, render, validate_selection
from ti_brief.store import Store


class StateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.tmp.name) / "state.sqlite3")
        self.record = demo_records()[0]

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def test_restart_dedup_and_changed_records(self):
        self.assertEqual(self.store.upsert([self.record, self.record]), 1)
        self.store.checkpoint(self.record, "reported_version")
        self.assertEqual(self.store.pending("reported_version", 8), [])
        changed = replace(self.record, description="Changed source evidence")
        self.store.upsert([changed])
        self.store.checkpoint(self.record, "reported_version")
        self.assertEqual(self.store.pending("reported_version", 8), [changed])

    def test_failure_does_not_drop_backlog(self):
        self.store.upsert(demo_records())
        chosen = self.store.pending("reported_version", 1)
        self.assertEqual(len(chosen), 1)
        self.assertEqual(len(self.store.pending("reported_version", 10)), 2)
        self.assertEqual(self.store.pending_count("reported_version"), 2)
        self.store.checkpoint(chosen[0], "reported_version")
        self.assertEqual(len(self.store.pending("reported_version", 10)), 1)

    def test_report_escapes_hostile_feed_content(self):
        bad = replace(self.record, description='<script>alert(1)</script> [click](https://evil.example) ![image](x)')
        self.store.upsert([bad])
        output = render([bad], [{"record_id": bad.key, "excerpt": bad.description}], self.store, "test", {})
        self.assertNotIn("<script>", output)
        self.assertNotIn("[click](", output)
        self.assertIn("&lt;script&gt;", output)

    def test_no_new_findings_is_explicit(self):
        report = render([], [], self.store, "test", {})
        self.assertIn("No new or changed records", report)
        self.assertIn("No mappings inferred", report)

    def test_os_lock_rejects_overlap(self):
        with run_lock(Path(self.tmp.name) / "run.lock"):
            with self.assertRaises(RuntimeError):
                with run_lock(Path(self.tmp.name) / "run.lock"):
                    pass

    def test_legacy_state_migration_preserves_existing_checkpoints(self):
        path = Path(self.tmp.name) / "legacy.sqlite3"
        old = sqlite3.connect(path)
        old.execute("CREATE TABLE records (key TEXT PRIMARY KEY,version TEXT,payload TEXT,first_seen TEXT,last_seen TEXT,misp_version TEXT,misp_uuid TEXT,reported_version TEXT)")
        r = self.record
        old.execute("INSERT INTO records VALUES(?,?,?,?,?,?,?,?)", (r.key, r.version, json.dumps(asdict(r)), "first", "last", r.version, event_uuid(r), r.version))
        old.commit()
        old.close()
        migrated = Store(path)
        try:
            self.assertEqual(migrated.pending("misp_version", 8), [])
            self.assertEqual(migrated.pending("reported_version", 8), [])
            self.assertEqual(migrated.pending("opencti_version", 8), [r])
            self.assertEqual(migrated.pending_count("reported_version"), 0)
        finally:
            migrated.close()


class ValidationTests(unittest.TestCase):
    def test_normalization(self):
        self.assertEqual(canonical("ip-dst", "2001:0db8::1"), "2001:db8::1")
        self.assertEqual(canonical("domain", "Example.ORG."), "example.org")
        self.assertEqual(canonical("sha256", "A" * 64), "a" * 64)
        for kind, value in [("ip-dst", "999.0.0.1"), ("sha256", "x" * 64), ("url", "file:///etc/passwd"), ("domain", "bad..org")]:
            with self.assertRaises(ValueError):
                canonical(kind, value)

    def test_model_cannot_invent_claims_or_references(self):
        r = demo_records()[0]
        good = {"items": [{"record_id": r.key, "excerpt": r.description}]}
        self.assertEqual(len(validate_selection(good, {r.key: r})), 1)
        for value in ({"items": [{"record_id": "invented", "excerpt": r.title}]},
                      {"items": [{"record_id": r.key, "excerpt": "APT99 exploited CVE-2026-9999"}]},
                      {"items": [{"record_id": r.key, "excerpt": r.title, "tool": "shell"}]},
                      {"items": [good["items"][0]] * 2}, {"items": [], "system": "override"}):
            with self.assertRaises(ValueError):
                validate_selection(value, {r.key: r})
        with self.assertRaises(ValueError):
            validate_selection({"items": []}, {r.key: r})

    def test_excerpt_choices_preserve_complete_conditions(self):
        r = replace(demo_records()[0], title="Complete source title", description="A vulnerability affects " + "one specific configuration " * 15 + "only after authentication.")
        self.assertEqual(excerpt_options(r), [r.title])
        short = replace(r, description="Authentication is required. The remaining source details are longer.")
        self.assertIn("Authentication is required.", excerpt_options(short))

    def test_kev_dates_are_not_exploitation_dates(self):
        rows = {"vulnerabilities": [{"cveID": "CVE-2026-1234", "dateAdded": "2026-11-09", "vulnerabilityName": "Example", "shortDescription": "Evidence", "requiredAction": "Apply updates"},
                                    {"cveID": "CVE-2020-1234", "dateAdded": "2020-01-01"}]}
        records = list(kev_records(rows, now=datetime(2026, 11, 10, tzinfo=timezone.utc)))
        self.assertEqual(len(records), 1)
        self.assertIsNone(records[0].occurred_at)
        self.assertEqual(records[0].published_at, "2026-11-09")

    def test_feodo_schema_and_ip_validation(self):
        csv = "# Last updated: 2026-11-09 00:00:00 UTC\nfirst_seen_utc,dst_ip,dst_port,c2_status,last_online,malware\n2026-11-09 00:00:00,192.0.2.1,443,online,2026-11-09,Example\n"
        self.assertEqual(list(feodo_records(csv, datetime(2026, 11, 10, tzinfo=timezone.utc)))[0].value, "192.0.2.1")
        with self.assertRaises(ValueError):
            list(feodo_records(csv, datetime(2027, 1, 1, tzinfo=timezone.utc)))
        with self.assertRaises(ValueError):
            list(feodo_records("<html>blocked</html>"))

    def test_circl_bounded_and_manifest_paths_rejected(self):
        uid = "a8c6402a-713e-48e6-b581-f2d38c5923ea"
        event = {"Event": {"info": "Sourced report", "Attribute": [{"type": "domain", "value": "Example.ORG"}] * 30}}
        with patch.object(Http, "json", side_effect=[{uid: {"timestamp": int(datetime.now(timezone.utc).timestamp())}}, event]):
            rows = list(circl_records(Http(), max_attributes=2))
            self.assertEqual(len(rows), 2)
            self.assertEqual(rows[0].value, "example.org")
            self.assertIsNone(rows[0].occurred_at)
        with patch.object(Http, "json", return_value={"../../etc/passwd": {"timestamp": int(datetime.now(timezone.utc).timestamp())}}):
            with self.assertRaises(ValueError):
                list(circl_records(Http()))

    def test_misp_uuid_stable_and_private(self):
        r = demo_records()[0]
        changed = replace(r, title="Changed")
        self.assertEqual(event_uuid(r), event_uuid(changed))
        payload = misp_event(r)["Event"]
        self.assertEqual(payload["distribution"], 0)
        self.assertFalse(payload["published"])
        self.assertFalse(payload["Attribute"][0]["to_ids"])


class ApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.requests = []
        cls.events = {}
        record = demo_records()[0]
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                if self.path == "/redirect":
                    self.send_response(302)
                    self.send_header("Location", "/secret-leak")
                    self.end_headers()
                    return
                if self.path == "/large":
                    data = "X" * 300
                elif self.path.startswith("/events/view/"):
                    data = json.dumps(cls.events[self.path.rsplit("/", 1)[1]])
                else:
                    self.send_error(401, "SECRET must never appear")
                    return
                self.send_response(200)
                self.end_headers()
                self.wfile.write(data.encode())

            def do_POST(self):
                value = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                cls.requests.append((self.path, value, self.headers.get("Authorization")))
                if self.path == "/events/restSearch":
                    result = {"response": [cls.events[value["uuid"]]] if value["uuid"] in cls.events else []}
                elif self.path == "/events/add" or self.path.startswith("/events/edit/"):
                    cls.events[value["Event"]["uuid"]] = value
                    result = value
                elif self.path == "/graphql":
                    if "externalReferenceAdd" in value["query"]:
                        result = {"data": {"externalReferenceAdd": {"id": "reference-id"}}}
                    elif "vulnerabilityAdd" in value["query"]:
                        result = {"data": {"vulnerabilityAdd": {"id": "vulnerability-id"}}}
                    else:
                        result = {"data": {"stixDomainObjects": {"edges": [{"node": {"id": "known", "entity_type": "Vulnerability", "name": record.value}}]}}}
                elif self.path == "/api/chat":
                    result = {"done": True, "message": {"content": json.dumps({"items": [{"record_id": record.key, "excerpt": record.title}]})}}
                else:
                    self.send_error(404)
                    return
                self.send_response(200)
                self.end_headers()
                self.wfile.write(json.dumps(result).encode())
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.url = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def test_misp_create_update_and_readback(self):
        r = demo_records()[0]
        api = Misp(Http(), self.url, "private-token")
        api.sync(r)
        api.sync(replace(r, title="Updated"))
        self.assertTrue(api.read(r)["verified"])
        self.assertEqual(len(self.events), 1)
        self.assertTrue(any(path.startswith("/events/edit/") for path, _, _ in self.requests))

    def test_opencti_query_and_ollama_contract(self):
        r = demo_records()[0]
        self.assertEqual(OpenCti(Http(), self.url, "token").context(r)["candidates"][0]["id"], "known")
        selected = llm_select(Http(), self.url, "existing-model", [r])
        self.assertEqual(selected[0]["record_id"], r.key)
        request = self.requests[-1][1]
        self.assertEqual(request["keep_alive"], 0)
        self.assertNotIn("tools", request)

    def test_cve_bridge_uses_native_upsert_and_two_evidence_references(self):
        r = demo_records()[0]
        cti = OpenCti(Http(), self.url, "token")
        self.assertEqual(cti.sync_vulnerability(r, "http://localhost:8081"), "vulnerability-id")
        self.assertEqual(len(self.requests[-1][1]["variables"]["input"]["externalReferences"]), 2)
        self.assertTrue(self.requests[-1][1]["variables"]["input"]["update"])
        with self.assertRaises(ValueError):
            cti.sync_vulnerability(demo_records()[1], "http://localhost:8081")

    def test_http_blocks_redirects_oversize_and_secret_errors(self):
        for path, size in [("/redirect", 1000), ("/large", 100), ("/denied?token=SECRET", 1000)]:
            with self.assertRaises(RemoteError) as captured:
                Http(max_bytes=size, retries=0).request(self.url + path, headers={"Authorization": "SECRET"})
            self.assertNotIn("SECRET", str(captured.exception))
        self.assertFalse(any(p == "/secret-leak" for p, _, _ in self.requests))

    def test_live_pipeline_with_mock_services_and_real_sqlite(self):
        r = demo_records()[0]
        with tempfile.TemporaryDirectory() as d, patch("ti_brief.cli.collect", return_value=[r]), patch.dict(os.environ, {
            "MISP_URL": self.url, "MISP_API_KEY": "private", "OPENCTI_URL": self.url,
            "OPENCTI_TOKEN": "private", "OLLAMA_URL": self.url, "OLLAMA_MODEL": "local"}):
            args = ["--data-dir", d + "/data", "--reports-dir", d + "/reports", "--env", d + "/absent"]
            self.assertEqual(main(args), 0)
            reports = list(Path(d).glob("reports/live/*.md"))
            self.assertEqual(len(reports), 1)
            self.assertIn("Ollama selected", reports[0].read_text())
            # This mock serves excerpt JSON for both calls. The narrative gate
            # rejects that wrong schema but preserves the completed evidence run.
            sidecar=json.loads(reports[0].with_suffix('.json').read_text())
            self.assertEqual(sidecar['narrative']['mode'],'deterministic-fallback')
            self.assertEqual(len(sidecar['observations']),1)
            store = Store(Path(d) / "data/live/state.sqlite3")
            self.assertEqual(store.pending("reported_version", 8), [])
            store.close()

    def test_failed_model_preserves_retry_queue(self):
        r = demo_records()[0]
        with tempfile.TemporaryDirectory() as d, patch("ti_brief.cli.collect", return_value=[r]), patch("ti_brief.cli.llm_select", side_effect=ValueError("invented")), patch.dict(os.environ, {
            "MISP_URL": self.url, "MISP_API_KEY": "private", "OPENCTI_URL": self.url,
            "OPENCTI_TOKEN": "private", "OLLAMA_MODEL": "local"}):
            self.assertEqual(main(["--data-dir", d, "--reports-dir", d + "/reports", "--env", d + "/absent"]), 2)
            store = Store(Path(d) / "live/state.sqlite3")
            self.assertEqual(len(store.pending("reported_version", 8)), 1)
            store.close()

    def test_misp_only_stage_keeps_reporting_queue_without_opencti(self):
        r = demo_records()[0]
        with tempfile.TemporaryDirectory() as d, patch("ti_brief.cli.collect", return_value=[r]), patch.dict(os.environ, {
            "MISP_URL": self.url, "MISP_API_KEY": "private"}), patch("ti_brief.cli.OpenCti", side_effect=AssertionError("No OpenCTI in this stage")):
            self.assertEqual(main(["--sync-misp-only", "--data-dir", d, "--env", d + "/absent"]), 0)
            store = Store(Path(d) / "live/state.sqlite3")
            self.assertEqual(store.pending("misp_version", 8), [])
            self.assertEqual(len(store.pending("reported_version", 8)), 1)
            store.close()


class DemoTests(unittest.TestCase):
    def test_demo_never_uses_network_and_isolated(self):
        with tempfile.TemporaryDirectory() as d, patch.object(Http, "request", side_effect=AssertionError("network forbidden")):
            self.assertEqual(main(["--demo", "--data-dir", d + "/data", "--reports-dir", d + "/reports"]), 0)
            self.assertTrue((Path(d) / "data/demo/state.sqlite3").exists())
            self.assertFalse((Path(d) / "data/live").exists())


if __name__ == "__main__":
    unittest.main()
