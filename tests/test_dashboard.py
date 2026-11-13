"""Tests for the SENTINEL JSON dashboard adapter."""
import json
import unittest

from src.dashboard import _plain, _timestamp, normalize_report


class DashboardReportTests(unittest.TestCase):
    def test_normalizes_empty_report(self):
        report = normalize_report({})
        self.assertEqual(report["alerts"], [])
        self.assertEqual(report["correlated_incidents"], [])
        self.assertEqual(report["severity_counts"], {})
        self.assertEqual(report["alert_count"], 0)

    def test_preserves_unknown_severity_and_rule_specific_evidence(self):
        source = {
            "severity_counts": {"HIGH": 1, "CRITICAL_FUTURE": 1},
            "alerts": [{
                "rule_id": "HIGH_EVENT_RATE",
                "severity": "CRITICAL_FUTURE",
                "evidence": {"events_in_window": 11, "sample": ["a", "b"]},
                "timestamp": 10005.0,
            }],
        }
        report = normalize_report(source)
        alert = report["alerts"][0]
        self.assertEqual(alert["severity"], "CRITICAL_FUTURE")
        self.assertEqual(alert["evidence"]["events_in_window"], 11)
        self.assertEqual(report["severity_counts"]["CRITICAL_FUTURE"], 1)

    def test_uses_alert_and_incident_lengths_when_counts_missing(self):
        report = normalize_report({
            "alerts": [{"rule_id": "R1"}],
            "correlated_incidents": [{"incident_id": "INC-1"}],
        })
        self.assertEqual(report["alert_count"], 1)
        self.assertEqual(report["correlated_incident_count"], 1)

    def test_rejects_invalid_alert_container(self):
        with self.assertRaisesRegex(ValueError, "'alerts' must be a list"):
            normalize_report({"alerts": {}})

    def test_rejects_non_object_report(self):
        with self.assertRaisesRegex(ValueError, "JSON object"):
            normalize_report([])

    def test_timestamp_is_not_converted_to_calendar_time(self):
        self.assertEqual(_timestamp(10005.0), "10005s")
        self.assertEqual(_timestamp("unknown-origin"), "unknown-origin")

    def test_generic_evidence_values(self):
        self.assertEqual(_plain({"a": 1}), json.dumps({"a": 1}, sort_keys=True))
        self.assertEqual(_plain(None), "—")


if __name__ == "__main__":
    unittest.main()
