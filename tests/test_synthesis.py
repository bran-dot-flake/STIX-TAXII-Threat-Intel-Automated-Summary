import copy, unittest
from ti_brief import synthesis, factual, editorial, executive
from test_factual import current


class SynthesisTests(unittest.TestCase):
    def test_takeaway_and_implications_replace_publisher_inventory(self):
        p = current()
        result = synthesis.edition(p)
        editorial.validate_edition(result)
        text = " ".join(c["text"] for para in result["plan"]["overview"] for c in para)
        self.assertIn("Dominate", result["headline"])
        self.assertIn("more than half", text)
        self.assertIn("rollout decisions", text)
        self.assertNotIn("coverage lists", text)
        self.assertNotIn("1,328", text)
        self.assertGreater(len(text.split()), 100)
        self.assertEqual(factual.edition(p)["version"], 4)

    def test_unknown_negated_or_minority_patterns_cannot_receive_this_analysis(self):
        for old, new in [
            ("45 are", "4 are"),
            ("Microsoft has", "It is false that Microsoft has"),
        ]:
            p = current()
            for r in p["news"]:
                r["excerpt"] = r["excerpt"].replace(old, new)
            self.assertIsNone(synthesis.edition(p))

    def test_arbitrary_analysis_and_changed_citations_rejected(self):
        result = synthesis.edition(current())
        for change in [
            "Attackers have compromised these products.",
            "Patch every system immediately.",
        ]:
            value = copy.deepcopy(result)
            value["plan"]["overview"][0][0]["text"] = change
            with self.assertRaises(ValueError):
                editorial.validate_edition(value)
        value = copy.deepcopy(result)
        value["plan"]["overview"][0][0]["evidence_ids"] = ["fake"]
        with self.assertRaises(ValueError):
            editorial.validate_edition(value)

    def test_explicit_revision_retains_publication_time_and_history(self):
        from test_executive import snapshot
        from ti_brief.publication import validate_snapshot

        p = current()
        s = snapshot()
        s.update(
            exported_at=p["generated_at"],
            collected_at=p["generated_at"],
            sources=p["sources"],
            news=p["news"],
            records=p["records"],
        )
        executive.refresh(s, factual=True)
        before = copy.deepcopy(s["editions"][0])
        executive.refresh(s, factual=True)
        self.assertEqual(before, s["editions"][0])
        validate_snapshot(s)
