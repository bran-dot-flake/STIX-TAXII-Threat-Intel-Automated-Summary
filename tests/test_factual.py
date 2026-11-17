import copy, json, os, tempfile, unittest
from argparse import Namespace
from pathlib import Path
from unittest.mock import patch
from ti_brief import factual as f, executive as e, editorial
from ti_brief.publication import validate_snapshot
from scripts import compose_brief
from test_executive import snapshot


def current():
    return json.loads(
        (Path(__file__).parent / "fixtures/weekly-2026-11-16.json").read_text(
            encoding="utf-8"
        )
    )


class FactualTests(unittest.TestCase):
    def test_independent_publisher_counts_and_subset_scope(self):
        p = current()
        result = f.edition(p)
        text = " ".join(c["text"] for para in result["plan"]["overview"] for c in para)
        for expected in [
            "1,260",
            "68 critical",
            "167 Chromium",
            "1,328",
            "60 critical",
            "45 critical remote code execution",
        ]:
            self.assertIn(expected, text)
        self.assertEqual(result["headline"], "Microsoft Patch Tuesday — November 2026")
        self.assertEqual(result["mode"], "deterministic-factual")
        self.assertIsNone(result["approval_id"])
        editorial.validate_edition(result)

    def test_negated_or_conditional_source_cannot_become_positive_fact(self):
        for row in current()["news"]:
            for prefix in ["It is false that ", "If confirmed, ", "Correction: "]:
                changed = {**row, "excerpt": prefix + row["excerpt"]}
                self.assertIn("published a report titled", f.finding(changed))
                self.assertNotIn("coverage lists", f.finding(changed))

    def test_impossible_subsets_fall_back_to_attributed_title(self):
        for row in current()["news"]:
            changed = copy.deepcopy(row)
            changed["excerpt"] = (
                changed["excerpt"].replace("1,260", "1").replace("1328", "1")
            )
            self.assertIn("published a report titled", f.finding(changed))

    def test_unsupported_text_numbers_ids_mode_and_metadata_rejected(self):
        for field, value in [
            ("headline", "Actively exploited"),
            ("mode", "ollama-reviewed"),
            ("approval_id", "fake"),
            ("evidence_digest", "fake"),
        ]:
            result = f.edition(current())
            result[field] = value
            with self.assertRaises(ValueError):
                editorial.validate_edition(result)
        result = f.edition(current())
        for value in [
            "SAP allows remote code execution.",
            "Microsoft patched 999 issues.",
        ]:
            changed = copy.deepcopy(result)
            changed["plan"]["overview"][0][0]["text"] = value
            with self.assertRaises(ValueError):
                editorial.validate_edition(changed)
        changed = copy.deepcopy(result)
        changed["plan"]["overview"][0][0]["evidence_ids"] = ["fake"]
        with self.assertRaises(ValueError):
            editorial.validate_edition(changed)

    def test_unknown_story_is_only_attributed_title(self):
        row = {
            **current()["news"][0],
            "title": "Vendor investigates a reported incident",
            "excerpt": "A detailed but unrecognized assertion.",
        }
        text = f.finding(row)
        self.assertEqual(
            text,
            "SANS ISC published a report titled “Vendor investigates a reported incident”.",
        )
        self.assertNotIn("exploited", text)

    def test_source_outage_or_out_of_window_cannot_publish(self):
        p = current()
        p["sources"][0]["status"] = "failed"
        # The two news sources may not be first in the source list.
        for source in p["sources"]:
            if source["id"] == p["news"][0]["source"]:
                source["status"] = "failed"
        with self.assertRaises(ValueError):
            f.edition(p)
        p = current()
        p["news"][0]["published_at"] = "2026-01-01T00:00:00+00:00"
        with self.assertRaises(ValueError):
            f.edition(p)

    def test_automatic_publication_is_idempotent_and_preserves_history(self):
        s = snapshot()
        with patch.object(
            e, "fallback", side_effect=AssertionError("No prose approvals")
        ):
            e.refresh(s, factual=True)
        validate_snapshot(s)
        self.assertEqual(len(s["editions"]), 1)
        before = copy.deepcopy(s["editions"])
        e.refresh(s, factual=True)
        self.assertEqual(s["editions"], before)
        # A new daily collection clock cannot mutate the frozen weekly edition.
        s["exported_at"] = "2026-11-13T08:00:00+00:00"
        e.refresh(s, factual=True)
        self.assertEqual(s["editions"], before)

    def test_default_cli_never_calls_model_or_prose_gate(self):
        s = snapshot()
        with (
            tempfile.TemporaryDirectory() as tmp,
            patch.dict(os.environ, {"TI_WEEKLY_COMPOSITION": "factual"}),
            patch.object(e, "compose", side_effect=AssertionError("No model")),
        ):
            args = Namespace(
                cache_dir=Path(tmp), revise_latest=False, retry_draft=False
            )
            self.assertEqual(compose_brief.compose_weekly(args, s), 0)
            files = list(Path(tmp).glob("*.json"))
            self.assertEqual(len(files), 1)
            editorial.validate_edition(json.loads(files[0].read_text()))
