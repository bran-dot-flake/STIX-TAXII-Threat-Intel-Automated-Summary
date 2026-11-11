import base64
import json
import os
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from scripts.daily_staged import verify_ownership
from scripts.init_env import initialize
from scripts.preflight import check
from ti_brief.cli import main
from ti_brief.feeds import demo_records
from ti_brief.http import Http
from ti_brief.platforms import OpenCti, event_uuid
from ti_brief.store import Store


class OperationTests(unittest.TestCase):
    def test_secret_generation_is_exclusive_and_well_formed(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / ".env"
            initialize(path)
            original = path.read_text()
            values = dict(line.split("=", 1) for line in original.splitlines() if line and not line.startswith("#"))
            self.assertEqual(values["ADMIN_KEY"], values["MISP_API_KEY"])
            self.assertEqual(len(values["ADMIN_KEY"]), 40)
            self.assertEqual(values["OPENCTI_ADMIN_TOKEN"], values["OPENCTI_TOKEN"])
            self.assertEqual(len(base64.b64decode(values["OPENCTI_ENCRYPTION_KEY"])), 32)
            self.assertNotIn("CHANGE_", original)
            with self.assertRaises(FileExistsError):
                initialize(path)
            self.assertEqual(path.read_text(), original)

    def test_preflight_refuses_low_memory_missing_profiles_and_ports(self):
        self.assertFalse(check(["misp"], 4000, 30, 1048576)["errors"])
        self.assertEqual(check(["misp", "opencti", "integration"], 8000, 30, 1048576)["container_caps_mib"], 6464)
        for profiles, memory, disk, maps, ports in [(["misp"], 2000, 30, 1048576, ()),
            (["integration"], 8000, 30, 1048576, ()), (["opencti"], 8000, 20, 1048576, ()),
            (["opencti"], 8000, 30, 1000, ()), (["misp"], 8000, 30, 1048576, (8081,))]:
            self.assertTrue(check(profiles, memory, disk, maps, ports)["errors"])

    def test_orchestrator_refuses_foreign_project_containers(self):
        with patch("scripts.daily_staged.invoke", return_value=SimpleNamespace(stdout=json.dumps("com.docker.compose.project=ti-lab") + "\n")):
            with self.assertRaises(RuntimeError):
                verify_ownership()
        with patch("scripts.daily_staged.invoke", return_value=SimpleNamespace(stdout=json.dumps("com.docker.compose.project=ti-lab,org.ti-brief.managed=true") + "\n")):
            verify_ownership()

    def test_opencti_candidates_require_exact_value_and_misp_provenance(self):
        r = demo_records()[0]
        node = {"id": "verified", "entity_type": "Vulnerability", "name": r.value,
                "externalReferences": {"edges": [{"node": {"url": "http://localhost:8081/events/view/" + event_uuid(r)}}]}}
        result = {"data": {"stixDomainObjects": {"edges": [{"node": node}]}}}
        with patch.object(Http, "json", return_value=result):
            self.assertEqual(OpenCti(Http(), "http://localhost", "token").context(r)["verified_sync_ids"], ["verified"])
            node["name"] = "Different CVE"
            self.assertEqual(OpenCti(Http(), "http://localhost", "token").context(r)["verified_sync_ids"], [])

    def test_actual_connector_md5_pattern_and_exact_query(self):
        r = replace(demo_records()[0], kind="md5", value="a" * 32)
        node = {"id": "verified-md5", "entity_type": "Indicator", "name": r.value,
                "pattern": "[file:hashes.MD5 = '" + r.value + "']",
                "externalReferences": {"edges": [{"node": {"external_id": event_uuid(r)}}]}}
        result = {"data": {"stixDomainObjects": {"edges": [{"node": node}]}}}
        with patch.object(Http, "json", return_value=result) as request:
            self.assertEqual(OpenCti(Http(), "http://localhost", "token").context(r)["verified_sync_ids"], ["verified-md5"])
            variables = request.call_args.args[1]["variables"]
            self.assertEqual(variables["types"], ["Indicator"])
            self.assertEqual(variables["filters"]["filters"][0]["values"], [r.value])

    def test_prepare_render_is_offline_and_changed_snapshot_fails(self):
        with tempfile.TemporaryDirectory() as d:
            args = ["--demo", "--data-dir", d + "/data", "--reports-dir", d + "/reports"]
            self.assertEqual(main(args + ["--prepare-only"]), 0)
            store = Store(Path(d) / "data/demo/state.sqlite3")
            self.assertEqual(len(store.pending("reported_version", 8)), 2)
            store.close()
            with patch.object(Http, "request", side_effect=AssertionError("Network forbidden")):
                self.assertEqual(main(args + ["--render-prepared"]), 0)
            # Successful rendering acknowledged the records; the old snapshot cannot be reused.
            self.assertEqual(main(args + ["--render-prepared"]), 1)

    def test_expired_prepared_snapshot_does_not_acknowledge_records(self):
        with tempfile.TemporaryDirectory() as d:
            args = ["--demo", "--data-dir", d + "/data", "--reports-dir", d + "/reports"]
            self.assertEqual(main(args + ["--prepare-only"]), 0)
            path = Path(d) / "data/demo/prepared.json"
            prepared = json.loads(path.read_text())
            prepared["prepared_at"] = "2000-01-01T00:00:00+00:00"
            path.write_text(json.dumps(prepared))
            self.assertEqual(main(args + ["--render-prepared"]), 1)
            store = Store(Path(d) / "data/demo/state.sqlite3")
            self.assertEqual(len(store.pending("reported_version", 8)), 2)
            store.close()
