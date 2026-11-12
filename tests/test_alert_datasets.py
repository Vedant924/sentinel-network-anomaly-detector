import unittest

from src.detector import detect_anomalies, detect_high_event_rate, detect_many_destination_ports
from src.run_detector import load_events


class TestStructuredAlertContract(unittest.TestCase):
    def test_port_alert_has_explainable_fields_and_legacy_alias(self):
        events = [{"timestamp": i, "src_ip": "192.0.2.90", "dst_port": i + 1} for i in range(12)]
        alert = detect_many_destination_ports(events)[0]
        for field in ("alert_id", "rule_id", "observed", "threshold", "evidence",
                      "severity_reason", "recommended_action", "uncertainty",
                      "window_start", "window_end"):
            self.assertIn(field, alert)
        self.assertEqual(alert["observed"], alert["unique_destination_ports"])

    def test_rate_alert_has_rate_evidence_and_legacy_alias(self):
        events = [{"timestamp": i * 0.2, "src_ip": "192.0.2.91", "dst_port": 443} for i in range(15)]
        alert = detect_high_event_rate(events)[0]
        self.assertEqual(alert["rule_id"], "HIGH_EVENT_RATE")
        self.assertEqual(alert["observed"], alert["observed_count"])
        self.assertIn("events_per_second", alert["evidence"])

    def test_alert_id_is_deterministic_for_same_detection(self):
        events = [{"timestamp": i, "src_ip": "192.0.2.92", "dst_port": i + 1} for i in range(12)]
        first = detect_many_destination_ports(events)[0]["alert_id"]
        second = detect_many_destination_ports(list(reversed(events)))[0]["alert_id"]
        self.assertEqual(first, second)


class TestCuratedDatasets(unittest.TestCase):
    def rules_for(self, filename):
        return {alert["rule_id"] for alert in detect_anomalies(load_events(f"data/datasets/{filename}"))}

    def test_normal_dataset_has_no_alerts(self):
        self.assertEqual(self.rules_for("normal_traffic.jsonl"), set())

    def test_port_scan_dataset_triggers_port_rule(self):
        self.assertIn("MANY_DESTINATION_PORTS", self.rules_for("port_scan.jsonl"))

    def test_high_event_rate_dataset_triggers_rate_rule(self):
        self.assertIn("HIGH_EVENT_RATE", self.rules_for("high_event_rate.jsonl"))

    def test_mixed_dataset_triggers_both_rules(self):
        self.assertEqual(self.rules_for("mixed_scenarios.jsonl"),
                         {"MANY_DESTINATION_PORTS", "HIGH_EVENT_RATE"})


if __name__ == "__main__":
    unittest.main()
