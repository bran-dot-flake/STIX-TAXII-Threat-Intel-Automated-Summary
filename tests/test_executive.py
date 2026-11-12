"""Weekly regression and source-bound free-prose review, with public source fixtures."""

import copy
import json
import tempfile
import unittest
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import patch

from ti_brief import executive as e, hybrid
from ti_brief.publication import empty_snapshot, validate_snapshot
from ti_brief.stix_publication import empty_context
from scripts import compose_brief, export_publication

FIXTURE = Path(__file__).parent / "fixtures/executive-public.json"
CONFIG = {"weekday": 0, "hour": 8}


def package():
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def snapshot():
    p = package()
    s = empty_snapshot()
    s.update(
        exported_at=p["generated_at"],
        collected_at=p["generated_at"],
        sources=p["sources"],
        records=p["records"],
        news=p["news"],
        stix=empty_context(),
        editions=[],
    )
    e.prepare(s, CONFIG)
    return s


class ExecutiveTests(unittest.TestCase):
    def test_completed_windows_configurable_and_adjacent(self):
        now = datetime.fromisoformat(package()["generated_at"])
        a, b = e.weekly_window(now, CONFIG)
        self.assertEqual(b.isoformat(), "2026-11-09T08:00:00+00:00")
        self.assertEqual(b - a, timedelta(days=7))
        self.assertEqual(e.weekly_window(b + timedelta(days=7), CONFIG)[0], b)
        self.assertEqual(e.weekly_window(b - timedelta(seconds=1), CONFIG)[1], a)
        self.assertEqual(e.weekly_window(now, {"weekday": 3, "hour": 9})[1].hour, 9)

    def test_free_paraphrase_is_reviewed_not_fixed_sentence_selection(self):
        p = package()
        result = e.fallback(p)
        self.assertEqual(result["version"], 3)
        self.assertEqual(result["mode"], "ollama-edited-reviewed")
        self.assertEqual(len(result["plan"]["overview"]), 3)
        self.assertEqual(
            sum(
                len(c["text"].split())
                for para in result["plan"]["overview"]
                for c in para
            ),
            225,
        )
        e.validate_edition(result)
        for cl in e.claims(result["plan"]):
            self.assertTrue(cl["evidence_ids"])

    def test_daily_runs_publish_once_preserve_original_date(self):
        s = snapshot()
        e.refresh(s, config=CONFIG)
        validate_snapshot(s)
        original = copy.deepcopy(s["editions"])
        self.assertEqual(len(original), 1)
        self.assertEqual(original[0]["publication_kind"], "weekly")
        for days in (0, 1, 2):
            s["exported_at"] = (
                datetime.fromisoformat(package()["generated_at"]) + timedelta(days=days)
            ).isoformat()
            e.refresh(s, config=CONFIG)
            self.assertEqual(s["editions"], original)
            self.assertEqual(s["collection"]["status"], "quiet")
            validate_snapshot(s)

    def test_next_week_unknown_prose_holds_last_valid_edition(self):
        s = snapshot()
        e.refresh(s, config=CONFIG)
        original = copy.deepcopy(s["editions"])
        s["exported_at"] = "2026-11-17T14:00:00+00:00"
        for row in s["news"]:
            row["published_at"] = "2026-11-13T12:00:00+00:00"
            row["first_seen"] = row["last_seen"] = "2026-11-17T14:00:00+00:00"
        self.assertIsNotNone(e.candidate(s, CONFIG))
        e.refresh(s, config=CONFIG)
        self.assertEqual(s["collection"]["status"], "withheld")
        self.assertEqual(s["editions"], original)
        validate_snapshot(s)

    def test_quiet_or_failed_sources_cannot_create_empty_or_interim(self):
        s = snapshot()
        s["news"] = []
        s["records"] = []
        e.refresh(s, config=CONFIG)
        self.assertEqual(s["editions"], [])
        s = snapshot()
        for source in s["sources"]:
            source["status"] = "cached"
        e.refresh(s, config=CONFIG)
        self.assertEqual(s["editions"], [])
        self.assertEqual(s["collection"]["status"], "source-failure")

    def test_explicit_revision_uses_frozen_evidence_and_keeps_identity(self):
        s = snapshot()
        hybrid.refresh(s, config={**CONFIG, "update_hours": 48})
        old = copy.deepcopy(s["editions"][0])
        s["news"] = []
        s["exported_at"] = "2026-11-12T17:00:00+00:00"
        self.assertIsNone(e.candidate(s, CONFIG))
        self.assertEqual(
            e.evidence_digest(e.candidate(s, CONFIG, revision=True)),
            e.evidence_digest(package()),
        )
        e.refresh(
            s, config=CONFIG, published_at="2026-11-12T17:00:00+00:00", revision=True
        )
        result = s["editions"][0]
        self.assertEqual(result["id"], old["id"])
        self.assertEqual(result["published_at"], old["published_at"])
        self.assertEqual(result["revised_at"], "2026-11-12T17:00:00+00:00")
        self.assertEqual(len(s["editions"]), 1)
        validate_snapshot(s)

    def test_valid_citation_alone_cannot_approve_unsupported_analysis(self):
        p = package()
        plan = copy.deepcopy(e.fallback(p)["plan"])
        for text in (
            "A foreign intelligence service directed these operations.",
            "The attempts successfully compromised every targeted organization.",
            "The botnet proves these reports belong to one campaign.",
        ):
            plan["overview"][0][0]["text"] = text
            with self.assertRaises(e.NeedsReview):
                e.validate_plan(plan, p)

    def test_unsupported_numbers_units_and_identifiers_fail_mechanical_gate(self):
        p = package()
        plan = copy.deepcopy(e.fallback(p)["plan"])
        for text in (
            "The backdoor enrolled more than 1.3 billion devices.",
            "Operators exploited CVE-2026-99999.",
            "The activity used technique T1059.",
        ):
            plan["overview"][0][0] = {
                "text": text,
                "evidence_ids": [p["news"][1]["id"]],
            }
            with self.assertRaises(ValueError):
                e.mechanical_checks(plan, p)

    def test_long_copy_filler_unrelated_and_repeated_text_rejected(self):
        p = package()
        original = e.fallback(p)["plan"]
        for text in (
            p["news"][0]["excerpt"],
            "Organizations must remain vigilant in the evolving threat landscape.",
        ):
            plan = copy.deepcopy(original)
            plan["overview"][0][0] = {
                "text": text,
                "evidence_ids": [p["news"][0]["id"]],
            }
            with self.assertRaises(ValueError):
                e.mechanical_checks(plan, p)
        plan = copy.deepcopy(original)
        plan["topics"][0]["summary"]["evidence_ids"] = [p["news"][1]["id"]]
        with self.assertRaises(ValueError):
            e.mechanical_checks(plan, p)
        plan = copy.deepcopy(original)
        plan["topics"][0]["summary"] = copy.deepcopy(plan["overview"][0][1])
        with self.assertRaises(ValueError):
            e.mechanical_checks(plan, p)

    def test_review_binds_text_source_spans_dates_and_origin(self):
        p = package()
        review = copy.deepcopy(e.approved_plan(p))
        plan = review["plan"]
        for field, value in (("origin", "automatic"), ("evidence_digest", "0" * 64)):
            bad = copy.deepcopy(review)
            bad[field] = value
            bad["id"] = e.digest({k: v for k, v in bad.items() if k != "id"})[:24]
            with self.assertRaises(ValueError):
                e.check_review(bad, plan, p)
        for change in (
            lambda r: r["claims"][0]["spans"][0].update(digest="0" * 64),
            lambda r: r["claims"].pop(),
            lambda r: r["claims"][0].update(rationale="yes"),
        ):
            bad = copy.deepcopy(review)
            change(bad)
            bad["id"] = e.digest({k: v for k, v in bad.items() if k != "id"})[:24]
            with self.assertRaises(ValueError):
                e.check_review(bad, plan, p)
        p["news"][0]["excerpt"] += " New assertion."
        self.assertIsNone(e.fallback(p))

    def test_fact_notes_match_exact_versions_and_preserve_qualifications(self):
        row = package()["news"][1]
        writer = e.writer_source(row)
        self.assertIn("reviewed_facts", writer)
        self.assertNotIn("untrusted_excerpt", writer)
        self.assertTrue(any("week before" in q for q in writer["qualifications"]))
        row["excerpt"] += " Changed."
        self.assertIn("untrusted_excerpt", e.writer_source(row))

    def test_fetch_clock_does_not_change_review_but_source_dates_do(self):
        p = package()
        proof = e.evidence_digest(p)
        p["generated_at"] = "2026-11-13T14:00:00+00:00"
        for row in p["news"] + p["records"]:
            row["last_seen"] = p["generated_at"]
        self.assertEqual(proof, e.evidence_digest(p))
        self.assertIsNotNone(e.fallback(p))
        p["news"][0]["published_at"] = "2026-11-03T14:00:00+00:00"
        self.assertNotEqual(proof, e.evidence_digest(p))
        self.assertIsNone(e.fallback(p))

    def test_patch_tuesday_shared_release_preserves_both_publishers(self):
        s = snapshot()
        s["exported_at"] = "2026-11-19T14:00:00+00:00"
        rows = json.loads(
            FIXTURE.with_name("patch-tuesday-public.json").read_text(encoding="utf-8")
        )
        s["news"] = rows
        p = e.candidate(s, CONFIG)
        ts = e.topics(p)
        self.assertEqual(len(ts), 1)
        self.assertEqual(len(ts[0]["evidence_ids"]), 2)
        self.assertEqual({r["source"] for r in p["news"]}, {"sans-isc", "cisco-talos"})
        self.assertTrue(any("1,260" in r["excerpt"] for r in p["news"]))
        self.assertTrue(any("1328" in r["excerpt"] for r in p["news"]))
        self.assertIsNone(
            e.fallback(p)
        )  # conflicting counts are not synthesized without source review
        rows[1]["title"] = "Microsoft Patch Tuesday for October 2026"
        self.assertNotEqual(e.story_key(rows[0]), e.story_key(rows[1]))
        rows[1]["title"] = "Microsoft cloud campaign"
        self.assertNotEqual(e.story_key(rows[0]), e.story_key(rows[1]))

    def test_publication_dates_not_collection_and_post_cutoff_modifications_excluded(
        self,
    ):
        s = snapshot()
        row = s["news"][0]
        row["published_at"] = "2025-11-02T14:00:00+00:00"
        p = e.candidate(s, CONFIG)
        self.assertNotIn(row["id"], [r["id"] for r in p["news"]])
        row["modified_at"] = "2026-11-06T14:00:00+00:00"
        row["content_changed_at"] = row["modified_at"]
        self.assertIn(row["id"], [r["id"] for r in e.candidate(s, CONFIG)["news"]])
        row["modified_at"] = "2026-11-10T14:00:00+00:00"
        self.assertNotIn(row["id"], [r["id"] for r in e.candidate(s, CONFIG)["news"]])

    def test_meaningful_selection_does_not_reward_cve_or_fresh_clock_alone(self):
        row = copy.deepcopy(package()["news"][0])
        row.update(
            title="CVE-2026-99999 product bulletin",
            excerpt="A product update is now available.",
        )
        self.assertFalse(e.meaningful(row))
        row.update(
            title="Join our webinar",
            excerpt="We observed a backdoor and invite you to register now.",
        )
        self.assertFalse(e.meaningful(row))
        for row in package()["news"]:
            self.assertTrue(e.meaningful(row))

    def run_cli(self, s, cache, **patches):
        path = cache.parent / "snapshot.json"
        path.write_text(json.dumps(s), encoding="utf-8")
        with (
            patch(
                "sys.argv",
                [
                    "compose",
                    "--editorial",
                    "--snapshot",
                    str(path),
                    "--cache-dir",
                    str(cache),
                ],
            ),
            patch.object(compose_brief, "load_env"),
            patch("builtins.print"),
        ):
            return compose_brief.main(), path

    def test_reviewed_plan_skips_model_and_caches_unpublished_candidate(self):
        with (
            tempfile.TemporaryDirectory() as d,
            patch.object(
                compose_brief,
                "required",
                side_effect=AssertionError("No repeat inference"),
            ),
        ):
            cache = Path(d) / "cache"
            status, path = self.run_cli(snapshot(), cache)
            self.assertEqual(status, 0)
            result = json.loads(next(cache.glob("*.json")).read_text(encoding="utf-8"))
            e.validate_edition(result)
            self.assertIsNone(result["published_at"])
            self.assertEqual(json.loads(path.read_text())["editions"], [])

    def test_model_unavailable_and_pending_review_never_publish_fallback_excerpts(self):
        s = snapshot()
        s["news"][0]["excerpt"] += " Additional context."
        with (
            tempfile.TemporaryDirectory() as d,
            patch.object(compose_brief, "required", return_value="existing-model"),
            patch.object(e, "compose", side_effect=RuntimeError("offline")) as model,
        ):
            cache = Path(d) / "cache"
            status, path = self.run_cli(s, cache)
            self.assertEqual(status, 0)
            self.assertEqual(list(cache.glob("*.json")), [])
            self.assertEqual(json.loads(path.read_text())["editions"], [])
            self.assertEqual(model.call_count, 1)
        draft = copy.deepcopy(e.fallback(package())["plan"])
        with (
            tempfile.TemporaryDirectory() as d,
            patch.object(compose_brief, "required", return_value="existing-model"),
            patch.object(
                e, "compose", side_effect=e.NeedsReview(draft, "unverified")
            ) as model,
        ):
            cache = Path(d) / "cache"
            self.assertEqual(self.run_cli(s, cache)[0], 0)
            self.assertEqual(self.run_cli(s, cache)[0], 0)
            self.assertEqual(model.call_count, 1)
            self.assertEqual(list(cache.glob("*.json")), [])
            self.assertEqual(len(list((cache / "review").glob("*.json"))), 1)

    def test_model_json_uses_free_text_not_sentence_enumerations(self):
        p = package()
        plan = e.fallback(p)["plan"]

        class Model:
            def json(self, url, payload):
                self.payload = payload
                return {"done": True, "message": {"content": json.dumps(plan)}}

        model = Model()
        result = e.compose(model, "http://127.0.0.1:11434", "existing-model", p)
        self.assertEqual(result["mode"], "ollama-edited-reviewed")
        atom = model.payload["format"]["properties"]["overview"]["items"]["items"]
        self.assertEqual(atom["properties"]["text"], {"type": "string"})
        self.assertEqual(model.payload["keep_alive"], 0)

    def test_failed_upload_preserves_accepted_local_checkpoint(self):
        s = snapshot()
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "snapshot.json"
            path.write_text(json.dumps(s), encoding="utf-8")
            original = path.read_bytes()
            with (
                patch(
                    "sys.argv", ["export", "--publish-prepared", "--output", str(path)]
                ),
                patch.object(export_publication, "load_env"),
                patch.object(
                    export_publication, "publish", side_effect=RuntimeError("offline")
                ),
                patch("builtins.print"),
                patch.object(export_publication, "datetime") as clock,
            ):
                clock.now.return_value = datetime.fromisoformat(s["exported_at"])
                clock.fromisoformat.side_effect = datetime.fromisoformat
                self.assertEqual(export_publication.main(), 1)
            self.assertEqual(path.read_bytes(), original)

    def test_daily_recollection_preserves_weekly_without_interim(self):
        from ti_brief.publication import collect_public

        s = snapshot()
        e.refresh(s, config=CONFIG)
        original = copy.deepcopy(s["editions"])

        class Offline:
            def json(self, *a, **k):
                raise RuntimeError("offline")

            def get(self, *a, **k):
                raise RuntimeError("offline")

            def text(self, *a, **k):
                raise RuntimeError("offline")

        result, _ = collect_public(
            Offline(), s, datetime.fromisoformat("2026-11-13T14:00:00+00:00")
        )
        self.assertEqual(result["schema_version"], 6)
        self.assertEqual(result["editions"], original)
        e.refresh(result, config=CONFIG)
        validate_snapshot(result)
        self.assertEqual(result["editions"], original)

    def test_explicit_revision_prefers_latest_review_over_old_accepted_cache(self):
        s = snapshot()
        e.refresh(s, config=CONFIG)
        old = copy.deepcopy(s["editions"][0])
        registry = json.loads(e.APPROVALS.read_text(encoding="utf-8"))
        new = copy.deepcopy(registry["reviews"][0])
        new["plan"]["headline"] = "Cloud Misuse and Limited SSH Observations"
        new["reviewed_at"] = "2026-11-12T18:00:00+00:00"
        new["id"] = e.digest({k: v for k, v in new.items() if k != "id"})[:24]
        registry["reviews"].append(new)
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            approvals = root / "review.json"
            approvals.write_text(json.dumps(registry), encoding="utf-8")
            (root / (old["id"] + ".json")).write_text(json.dumps(old), encoding="utf-8")
            with patch.object(e, "APPROVALS", approvals):
                e.refresh(
                    s,
                    root,
                    CONFIG,
                    published_at="2026-11-12T18:01:00+00:00",
                    revision=True,
                )
                self.assertEqual(s["editions"][0]["headline"], new["plan"]["headline"])
                self.assertEqual(s["editions"][0]["published_at"], old["published_at"])
                validate_snapshot(s)
