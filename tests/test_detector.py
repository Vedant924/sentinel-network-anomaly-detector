import unittest

from src.detector import detect_many_destination_ports, validate_ip


def event(timestamp, source, port):
    return {"timestamp": timestamp, "src_ip": source, "dst_port": port}


class TestManyDestinationPorts(unittest.TestCase):
    def test_detects_many_distinct_ports(self):
        events = [event(t, "192.168.1.10", port) for t, port in enumerate(range(1, 13))]
        alerts = detect_many_destination_ports(events, window_seconds=10, threshold=10)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["rule"], "MANY_DESTINATION_PORTS")
        self.assertEqual(alerts[0]["source"], "192.168.1.10")
        self.assertEqual(alerts[0]["unique_destination_ports"], 11)
        self.assertEqual(alerts[0]["severity"], "HIGH")

    def test_does_not_alert_below_threshold(self):
        events = [event(t, "192.168.1.20", port) for t, port in enumerate(range(1, 6))]
        self.assertEqual(
            detect_many_destination_ports(events, window_seconds=10, threshold=10),
            [],
        )

    def test_repeated_port_counts_once(self):
        events = [event(t, "192.168.1.30", 443) for t in range(12)]
        self.assertEqual(
            detect_many_destination_ports(events, window_seconds=10, threshold=3),
            [],
        )

    def test_sources_are_counted_separately(self):
        events = []
        for port in range(1, 7):
            events.append(event(port, "192.168.1.40", port))
            events.append(event(port, "192.168.1.41", port + 100))
        self.assertEqual(
            detect_many_destination_ports(events, window_seconds=10, threshold=10),
            [],
        )

    def test_rejects_invalid_port(self):
        with self.assertRaises(ValueError):
            detect_many_destination_ports([event(1, "192.168.1.50", 70000)])

    def test_rejects_fractional_port_instead_of_truncating(self):
        with self.assertRaisesRegex(ValueError, "dst_port must be an integer"):
            detect_many_destination_ports([event(1, "192.168.1.50", 80.5)])

    def test_rejects_non_finite_timestamp(self):
        for timestamp in (float("nan"), float("inf"), float("-inf")):
            with self.subTest(timestamp=timestamp):
                with self.assertRaisesRegex(ValueError, "timestamp must be a finite number"):
                    detect_many_destination_ports([event(timestamp, "192.168.1.50", 80)])

    def test_rejects_boolean_timestamp(self):
        for timestamp in (True, False):
            with self.subTest(timestamp=timestamp):
                with self.assertRaisesRegex(ValueError, "timestamp must be a finite number"):
                    detect_many_destination_ports([event(timestamp, "192.168.1.50", 80)])

    def test_rejects_empty_source(self):
        with self.assertRaisesRegex(ValueError, "src_ip must be a non-empty string"):
            detect_many_destination_ports([event(1, "  ", 80)])

    def test_rejects_non_object_event(self):
        with self.assertRaisesRegex(ValueError, "Each event must be an object"):
            detect_many_destination_ports(["not an event"])

    def test_rejects_invalid_threshold(self):
        with self.assertRaises(ValueError):
            detect_many_destination_ports([], threshold=0)

    def test_rejects_non_integer_threshold(self):
        with self.assertRaisesRegex(ValueError, "threshold must be a positive integer"):
            detect_many_destination_ports([], threshold=1.5)

    def test_rejects_non_finite_window(self):
        with self.assertRaisesRegex(ValueError, "window_seconds must be a finite number"):
            detect_many_destination_ports([], window_seconds=float("nan"))



    def test_alerts_only_after_exceeding_threshold(self):
        events = [event(t, "192.168.1.60", port) for t, port in enumerate(range(1, 11))]
        self.assertEqual(
            detect_many_destination_ports(events, window_seconds=10, threshold=10),
            [],
        )
        events.append(event(10, "192.168.1.60", 11))
        alerts = detect_many_destination_ports(events, window_seconds=10, threshold=10)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["unique_destination_ports"], 11)


    def test_event_exactly_at_window_boundary_is_included(self):
        events = [event(0, "192.168.1.70", 80)]
        events.extend(
            event(t, "192.168.1.70", port)
            for t, port in zip(range(1, 11), range(81, 91))
        )
        alerts = detect_many_destination_ports(events, window_seconds=10, threshold=10)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["unique_destination_ports"], 11)

    def test_alert_can_trigger_again_after_anomaly_clears(self):
        events = [
            event(t, "192.168.1.80", port)
            for t, port in enumerate(range(1, 12))
        ]
        events.extend(
            event(t, "192.168.1.80", port)
            for t, port in zip(range(20, 31), range(20, 31))
        )
        alerts = detect_many_destination_ports(events, window_seconds=10, threshold=10)
        self.assertEqual(len(alerts), 2)

    def test_rejects_invalid_src_ip_address_format(self):
        invalid_ips = ["not_an_ip", "999.999.999.999", "192.168.1", "192.168.1.1.1", "fe80:::1"]
        for bad_ip in invalid_ips:
            with self.subTest(bad_ip=bad_ip):
                with self.assertRaisesRegex(ValueError, "src_ip must be a valid IPv4 or IPv6 address"):
                    detect_many_destination_ports([event(1, bad_ip, 80)])

    def test_rejects_non_string_src_ip(self):
        with self.assertRaisesRegex(ValueError, "src_ip must be a non-empty string"):
            detect_many_destination_ports([{"timestamp": 1, "src_ip": 192168, "dst_port": 80}])

    def test_supports_ipv6_addresses(self):
        events = [event(t, "2001:db8::1", port) for t, port in enumerate(range(1, 13))]
        alerts = detect_many_destination_ports(events, window_seconds=10, threshold=10)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["source"], "2001:db8::1")
        self.assertEqual(alerts[0]["unique_destination_ports"], 11)

    def test_normalizes_ipv6_representations(self):
        # Two representations of the same IPv6 address should group under the canonical form
        events = [
            event(1, "2001:0db8:0000:0000:0000:0000:0000:0001", 80),
            event(2, "2001:db8::1", 443),
        ]
        alerts = detect_many_destination_ports(events, window_seconds=10, threshold=1)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["source"], "2001:db8::1")
        self.assertEqual(alerts[0]["unique_destination_ports"], 2)

    def test_validates_optional_dst_ip_when_provided(self):
        # Valid dst_ip succeeds
        valid_event = {"timestamp": 1, "src_ip": "192.168.1.10", "dst_ip": "10.0.0.1", "dst_port": 80}
        self.assertEqual(detect_many_destination_ports([valid_event]), [])

        # Invalid dst_ip raises ValueError
        invalid_event = {"timestamp": 1, "src_ip": "192.168.1.10", "dst_ip": "bad_dst_ip", "dst_port": 80}
        with self.assertRaisesRegex(ValueError, "dst_ip must be a valid IPv4 or IPv6 address"):
            detect_many_destination_ports([invalid_event])

    def test_validate_ip_helper(self):
        self.assertEqual(validate_ip("192.168.1.1"), "192.168.1.1")
        self.assertEqual(validate_ip("  10.0.0.1  "), "10.0.0.1")
        self.assertEqual(validate_ip("::1"), "::1")
        with self.assertRaisesRegex(ValueError, "src_ip must be a non-empty string"):
            validate_ip("   ")
        with self.assertRaisesRegex(ValueError, "src_ip must be a non-empty string"):
            validate_ip(None)
        with self.assertRaisesRegex(ValueError, "src_ip must be a valid IPv4 or IPv6 address"):
            validate_ip("invalid-ip")

if __name__ == "__main__":
    unittest.main()
