import copy, json, os, tempfile, unittest
from datetime import datetime
from pathlib import Path
from unittest.mock import patch
from scripts import daily_staged as d, export_publication as x
from ti_brief import executive as e
from ti_brief import factual
from test_executive import snapshot


def fixture():
    s = snapshot()
    e.refresh(s)
    return s


class DailyPublicationTests(unittest.TestCase):
    def test_daily_publish_happens_before_model_even_when_it_fails(self):
        calls = []

        def invoke(args, **kwargs):
            calls.append(args)
            if "scripts/compose_brief.py" in args:
                raise RuntimeError("model failed")

        with (
            patch.object(d, "load_env"),
            patch.object(d, "orchestrate", return_value=0),
            patch.object(d, "invoke", side_effect=invoke),
            patch.dict(
                os.environ,
                {
                    "TI_PUBLICATION_ENABLED": "true",
                    "TI_TAXII_ENABLED": "false",
                    "TI_STIX_OPENCTI_ENABLED": "false",
                    "TI_NARRATIVE_ENABLED": "true",
                },
            ),
        ):
            self.assertEqual(d.main(["--manage-project"]), 0)
        self.assertIn("--data-only", calls[0])
        self.assertIn("scripts/compose_brief.py", calls[1])
        self.assertIn("--only-new-weekly", calls[2])

    def test_data_only_publishes_new_data_without_changing_editions(self):
        s = fixture()
        before = copy.deepcopy(s["editions"])
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "s.json"
            path.write_text(json.dumps(s), encoding="utf-8")
            with (
                patch(
                    "sys.argv",
                    ["export", "--publish", "--data-only", "--output", str(path)],
                ),
                patch.object(x, "load_env"),
                patch.object(x, "collect_public", return_value=(s, [])),
                patch.object(x, "project_context", return_value=s["stix"]),
                patch.object(
                    x, "refresh", side_effect=AssertionError("No editorial refresh")
                ),
                patch.object(x, "publish", return_value="commit") as pub,
            ):
                self.assertEqual(x.main(), 0)
                self.assertEqual(pub.call_args.args[0]["editions"], before)

    def test_no_second_publish_when_weekly_is_unchanged(self):
        s = fixture()
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "s.json"
            path.write_text(json.dumps(s), encoding="utf-8")
            with (
                patch(
                    "sys.argv",
                    [
                        "export",
                        "--publish-prepared",
                        "--only-new-weekly",
                        "--output",
                        str(path),
                    ],
                ),
                patch.object(x, "load_env"),
                patch.object(
                    x, "publish", side_effect=AssertionError("No duplicate dispatch")
                ),
                patch.object(x, "datetime") as clock,
            ):
                clock.now.return_value = datetime.fromisoformat(s["exported_at"])
                clock.fromisoformat.side_effect = datetime.fromisoformat
                self.assertEqual(x.main(), 0)

    def test_fragment_cannot_drive_weekly_but_stays_in_daily_data(self):
        s = fixture()
        row = copy.deepcopy(s["news"][0])
        row.update(
            title="Attackers searching for webshells",
            excerpt="Just saw a URL in our honeypot data today:",
        )
        s["news"].append(row)
        self.assertFalse(e.meaningful(row))
        self.assertIn(row, s["news"])

    def test_current_factual_weekly_is_supported_and_does_not_contain_rejected_SAP_claims(
        self,
    ):
        p = json.loads(
            (Path(__file__).parent / "fixtures/weekly-2026-11-16.json").read_text(
                encoding="utf-8"
            )
        )
        result = factual.edition(p)
        factual.validate_edition(result)
        prose = json.dumps(result["plan"])
        self.assertNotIn("SAP", prose)
        self.assertNotIn("actively exploited", prose)
