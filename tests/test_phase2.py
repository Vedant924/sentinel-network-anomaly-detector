import unittest

from src.detector import (
    correlate_alerts, deduplicate_alerts, detect_anomalies, detect_dns_anomalies,
    detect_failed_connections, detect_high_traffic_volume, detect_many_destination_hosts,
)
from src.run_detector import load_events


def event(timestamp, source="192.0.2.100", port=443, **extra):
    return {"timestamp": timestamp, "src_ip": source, "dst_port": port, **extra}


class TestPhase2DetectionRules(unittest.TestCase):
    def test_failed_connection_burst(self):
        rows = [event(i, connection_status="refused") for i in range(12)]
        alerts = detect_failed_connections(rows, window_seconds=60, threshold=10)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["rule_id"], "REPEATED_FAILED_CONNECTIONS")
        self.assertEqual(alerts[0]["evidence"]["failed_attempts"], 11)

    def test_successful_connections_do_not_trigger_failure_rule(self):
        rows = [event(i, connection_status="success") for i in range(20)]
        self.assertEqual(detect_failed_connections(rows), [])

    def test_traffic_volume_threshold_is_exceeded_not_met(self):
        rows = [event(i, bytes_transferred=500000) for i in range(2)]
        self.assertEqual(detect_high_traffic_volume(rows, byte_threshold=1000000), [])
        rows.append(event(2, bytes_transferred=1))
        self.assertEqual(len(detect_high_traffic_volume(rows, byte_threshold=1000000)), 1)

    def test_dns_query_burst_and_long_query(self):
        rows = [event(i, 53, dns_query=f"node-{i}.example.test") for i in range(55)]
        rows.append(event(55, 53, dns_query=("x" * 90) + ".example.test"))
        alerts = detect_dns_anomalies(rows)
        rules = {alert["rule_id"] for alert in alerts}
        self.assertIn("DNS_QUERY_BURST", rules)
        self.assertIn("SUSPICIOUS_DNS_QUERY", rules)

    def test_many_destination_hosts(self):
        rows = [event(i, dst_ip=f"198.51.100.{i+1}") for i in range(22)]
        alerts = detect_many_destination_hosts(rows)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["rule_id"], "MANY_DESTINATION_HOSTS")

    def test_rejects_negative_traffic_bytes(self):
        with self.assertRaisesRegex(ValueError, "bytes_transferred must be a non-negative integer"):
            detect_high_traffic_volume([event(1, bytes_transferred=-1)])

    def test_rejects_fractional_traffic_bytes(self):
        with self.assertRaisesRegex(ValueError, "bytes_transferred must be a non-negative integer"):
            detect_high_traffic_volume([event(1, bytes_transferred=1.5)])

    def test_detect_anomalies_accepts_one_pass_iterable(self):
        rows = (event(i, connection_status="timeout") for i in range(12))
        alerts = detect_anomalies(rows)
        self.assertIn("REPEATED_FAILED_CONNECTIONS", {a["rule_id"] for a in alerts})


class TestAlertCorrelation(unittest.TestCase):
    def test_correlates_different_rules_for_same_source(self):
        first = {"alert_id": "A1", "rule_id": "FAILED", "source": "192.0.2.1", "timestamp": 10}
        second = {"alert_id": "A2", "rule_id": "DNS", "source": "192.0.2.1", "timestamp": 30}
        incidents = correlate_alerts([first, second], correlation_window_seconds=60)
        self.assertEqual(len(incidents), 1)
        self.assertEqual(incidents[0]["alert_count"], 2)
        self.assertEqual(incidents[0]["correlated_rules"], ["DNS", "FAILED"])

    def test_does_not_correlate_different_sources(self):
        rows = [
            {"alert_id": "A1", "rule_id": "ONE", "source": "192.0.2.1", "timestamp": 10},
            {"alert_id": "A2", "rule_id": "TWO", "source": "192.0.2.2", "timestamp": 11},
        ]
        self.assertEqual(correlate_alerts(rows), [])

    def test_does_not_correlate_outside_time_window(self):
        rows = [
            {"alert_id": "A1", "rule_id": "ONE", "source": "192.0.2.1", "timestamp": 10},
            {"alert_id": "A2", "rule_id": "TWO", "source": "192.0.2.1", "timestamp": 100},
        ]
        self.assertEqual(correlate_alerts(rows, 60), [])

    def test_deduplicates_exact_alert_ids(self):
        alert = {"alert_id": "SNT-1", "rule_id": "ONE", "source": "192.0.2.1", "timestamp": 10}
        self.assertEqual(deduplicate_alerts([alert, alert]), [alert])

    def test_correlation_window_must_be_positive(self):
        with self.assertRaises(ValueError):
            correlate_alerts([], 0)


class TestPhase2Datasets(unittest.TestCase):
    def rules_for(self, filename):
        return {a["rule_id"] for a in detect_anomalies(load_events(f"data/datasets/{filename}"))}

    def test_failed_connection_fixture(self):
        self.assertIn("REPEATED_FAILED_CONNECTIONS", self.rules_for("failed_connections.jsonl"))

    def test_high_volume_fixture(self):
        self.assertIn("HIGH_TRAFFIC_VOLUME", self.rules_for("high_traffic_volume.jsonl"))

    def test_dns_fixture(self):
        rules = self.rules_for("dns_anomalies.jsonl")
        self.assertIn("DNS_QUERY_BURST", rules)
        self.assertIn("SUSPICIOUS_DNS_QUERY", rules)

    def test_many_hosts_fixture(self):
        self.assertIn("MANY_DESTINATION_HOSTS", self.rules_for("many_destination_hosts.jsonl"))

    def test_mixed_fixture_exercises_all_phase2_rules(self):
        rules = self.rules_for("phase2_mixed_scenarios.jsonl")
        self.assertTrue({
            "REPEATED_FAILED_CONNECTIONS", "HIGH_TRAFFIC_VOLUME",
            "DNS_QUERY_BURST", "SUSPICIOUS_DNS_QUERY", "MANY_DESTINATION_HOSTS",
        }.issubset(rules))


if __name__ == "__main__":
    unittest.main()
