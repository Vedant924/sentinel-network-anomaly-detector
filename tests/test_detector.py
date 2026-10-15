import unittest

from src.detector import detect_many_destination_ports


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

    def test_rejects_invalid_threshold(self):
        with self.assertRaises(ValueError):
            detect_many_destination_ports([], threshold=0)


if __name__ == "__main__":
    unittest.main()
