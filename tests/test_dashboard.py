"""Tests for the SENTINEL JSON dashboard adapter and renderer."""
import io
import json
import unittest

from rich.console import Console

from src.dashboard import _plain, _timestamp, build_dashboard, normalize_report


def valid_report(**overrides):
    report = {
        "tool": "SENTINEL",
        "events_analyzed": 0,
        "unique_sources": 0,
        "alert_count": 0,
        "severity_counts": {},
        "alerts": [],
        "correlated_incidents": [],
    }
    report.update(overrides)
    return report


class DashboardReportTests(unittest.TestCase):
    def test_rejects_empty_object_as_not_a_sentinel_report(self):
        with self.assertRaisesRegex(ValueError, "does not look like a SENTINEL report"):
            normalize_report({})

    def test_preserves_unknown_severity_and_rule_specific_evidence(self):
        source = valid_report(
            severity_counts={"HIGH": 1, "CRITICAL": 1},
            alerts=[{
                "rule_id": "HIGH_EVENT_RATE",
                "severity": "CRITICAL",
                "evidence": {"events_in_window": 11, "sample": ["a", "b"]},
                "timestamp": 10005.0,
            }],
        )
        report = normalize_report(source)
        alert = report["alerts"][0]
        self.assertEqual(alert["severity"], "CRITICAL")
        self.assertEqual(alert["evidence"]["events_in_window"], 11)
        self.assertEqual(report["severity_counts"]["CRITICAL"], 1)

    def test_uses_alert_and_incident_lengths_when_incident_count_missing(self):
        report = normalize_report(valid_report(
            alerts=[{"rule_id": "R1"}],
            correlated_incidents=[{"incident_id": "INC-1"}],
        ))
        self.assertEqual(report["alert_count"], 0)
        self.assertEqual(report["correlated_incident_count"], 1)

    def test_rejects_invalid_alert_container(self):
        with self.assertRaisesRegex(ValueError, "'alerts' must be a list"):
            normalize_report(valid_report(alerts={}))

    def test_rejects_non_object_report(self):
        with self.assertRaisesRegex(ValueError, "JSON object"):
            normalize_report([])

    def test_rejects_wrong_tool_name(self):
        with self.assertRaisesRegex(ValueError, "tool.*SENTINEL"):
            normalize_report(valid_report(tool="OTHER"))

    def test_timestamp_is_not_converted_to_calendar_time(self):
        self.assertEqual(_timestamp(10005.0), "10005s")
        self.assertEqual(_timestamp("unknown-origin"), "unknown-origin")

    def test_generic_evidence_values(self):
        self.assertEqual(_plain({"a": 1}), json.dumps({"a": 1}, sort_keys=True))
        self.assertEqual(_plain(None), "—")

    def test_rule_names_wrap_instead_of_truncating(self):
        rule = "REPEATED_FAILED_CONNECTIONS"
        report = normalize_report(valid_report(
            alert_count=1,
            alerts=[{"rule_id": rule, "severity": "HIGH", "source": "192.0.2.1"}],
        ))
        output = io.StringIO()
        Console(file=output, width=42, force_terminal=False).print(build_dashboard(report))
        self.assertIn(rule, output.getvalue())

    def test_untrusted_markup_in_alert_data_is_rendered_literally(self):
        hostile = "[red]10.0.0.1[/red]"
        report = normalize_report(valid_report(
            alert_count=1,
            alerts=[{"rule_id": "TEST", "severity": "HIGH", "source": hostile}],
        ))
        output = io.StringIO()
        Console(file=output, width=100, force_terminal=False).print(build_dashboard(report))
        self.assertIn(hostile, output.getvalue())


if __name__ == "__main__":
    unittest.main()
