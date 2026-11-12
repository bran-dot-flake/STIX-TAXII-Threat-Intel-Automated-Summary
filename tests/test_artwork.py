import copy
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from ti_brief import artwork as a, executive
from ti_brief.publication import validate_snapshot, collect_public
from test_executive import snapshot, CONFIG
from scripts.build_dashboard import build


class ArtworkTests(unittest.TestCase):
    def fixture(self):
        s = snapshot()
        executive.refresh(s, config=CONFIG)
        return s

    def test_original_compositions_are_bounded_safe_and_repeatable(self):
        for kind in a.ALTS:
            svg = a.render(kind)
            self.assertEqual(a.sanitize(svg), svg)
            self.assertLess(len(svg.encode()), 12000)
            self.assertNotIn("<text", svg)

    def test_artwork_binds_approved_lead_without_changing_the_brief(self):
        s = self.fixture()
        old = copy.deepcopy(s)
        a.enrich(s)
        validate_snapshot(s)
        self.assertEqual(s["editions"], old["editions"])
        self.assertEqual(s["records"], old["records"])
        self.assertEqual(s["schema_version"], 7)
        self.assertEqual(s["illustrations"][0]["kind"], "llm")
        self.assertIn("cloud AI", s["illustrations"][0]["alt"])

    def test_repeated_daily_artwork_reuses_exact_cache_without_generation(self):
        s = self.fixture()
        a.enrich(s)
        original = copy.deepcopy(s["illustrations"])
        with patch.object(a, "make", side_effect=AssertionError("No regeneration")):
            a.enrich(s)
        self.assertEqual(s["illustrations"], original)

    def test_unsupported_lead_omits_art(self):
        edition = self.fixture()["editions"][0]
        edition["headline"] = "Quarterly policy review"
        edition["plan"]["overview"][0] = [{"text": "Policy findings."}]
        self.assertIsNone(a.make(edition))

    def test_failed_artwork_does_not_interrupt_publication(self):
        s = self.fixture()
        with patch.object(a, "render", side_effect=ValueError("failure")):
            a.enrich(s)
        self.assertEqual(s["illustrations"], [])
        validate_snapshot(s)

    def test_unsafe_svg_payloads_are_rejected(self):
        base = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 640 400">{}</svg>'
        payloads = [
            "<script/>",
            "<foreignObject/>",
            '<image href="https://example.com/a"/>',
            '<path onload="bad()"/>',
            '<path style="fill:url(x)"/>',
            '<a href="x"/>',
            '<use href="#x"/>',
            '<rect fill="url(https://example.com)"/>',
            '<path d="M 1e999 0"/>',
            "<text>Claim</text>",
            '<g xmlns="https://evil.invalid"/>',
            '<path stroke-width="10000"/>',
        ]
        for payload in payloads:
            with self.subTest(payload=payload), self.assertRaises(ValueError):
                a.sanitize(base.format(payload))
        for svg in [
            "<!DOCTYPE svg><svg/>",
            "<?xml x?><svg/>",
            base.format("<path/>") + " " * 13000,
            base.format("<g/>" * 65),
            base.format("&entity;"),
        ]:
            with self.assertRaises(ValueError):
                a.sanitize(svg)

    def test_tampered_or_unrelated_artwork_cannot_cross_public_boundary(self):
        s = self.fixture()
        a.enrich(s)
        for field, value in [
            ("alt", "Invented victim"),
            ("kind", "phishing"),
            ("digest", "f" * 64),
            ("edition_id", "f" * 24),
            ("svg", a.render("phishing")),
        ]:
            bad = copy.deepcopy(s)
            bad["illustrations"][0][field] = value
            with self.assertRaises(ValueError):
                validate_snapshot(bad)

    def test_historical_art_is_associated_by_edition_and_not_live_collection(self):
        s = self.fixture()
        a.enrich(s)
        first = copy.deepcopy(s["illustrations"][0])
        s["news"] = []
        s["exported_at"] = "2026-11-13T14:00:00+00:00"
        executive.prepare(s, CONFIG)
        a.enrich(s)
        self.assertEqual(s["illustrations"][0], first)
        validate_snapshot(s)

    def test_build_writes_only_validated_static_svg_assets(self):
        import json

        s = self.fixture()
        a.enrich(s)
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            source = root / "snapshot.json"
            source.write_text(json.dumps(s), encoding="utf-8")
            build(source, root / "dist")
            path = root / "dist" / a.asset_path(s["illustrations"][0])
            self.assertEqual(path.read_text(), s["illustrations"][0]["svg"])
            (root / "dist" / "arbitrary.svg").write_text("<svg/>")
            with self.assertRaises(ValueError):
                build(source, root / "dist")

    def test_collector_and_enrichment_preserve_schema_and_artwork(self):
        s = self.fixture()
        a.enrich(s)

        class Offline:
            def json(self, *args, **kw):
                raise RuntimeError("offline")

            def request(self, *args, **kw):
                raise RuntimeError("offline")

        from datetime import datetime

        result, _ = collect_public(
            Offline(), s, datetime.fromisoformat("2026-11-13T14:00:00+00:00")
        )
        self.assertEqual(result["schema_version"], 7)
        self.assertEqual(result["illustrations"], s["illustrations"])
        validate_snapshot(result)

    def test_explicit_headline_takes_priority_over_secondary_paragraph_subjects(self):
        edition = self.fixture()["editions"][0]
        edition["headline"] = "Botnet access disrupted"
        self.assertEqual(a.subject(edition), "botnet")

    def test_invalid_generated_markup_is_omitted_without_touching_reporting(self):
        s = self.fixture()
        before = copy.deepcopy(s["editions"])
        with patch.object(a, "render", return_value="<svg><script/></svg>"):
            a.enrich(s)
        self.assertEqual(s["illustrations"], [])
        self.assertEqual(s["editions"], before)
        validate_snapshot(s)
