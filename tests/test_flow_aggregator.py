"""Regression tests for the shared packet-to-flow aggregator."""
import json
import tempfile
import unittest
from pathlib import Path

from src.flow_aggregator import aggregate_packets, load_packet_records


def packet(timestamp, src="192.0.2.10", dst="198.51.100.20",
           sport=50000, dport=443, protocol="TCP", length=60, **extra):
    record = {
        "timestamp": timestamp,
        "src_ip": src,
        "dst_ip": dst,
        "src_port": sport,
        "dst_port": dport,
        "protocol": protocol,
        "packet_length": length,
    }
    record.update(extra)
    return record


class FlowAggregatorTests(unittest.TestCase):
    def test_reverse_direction_packets_share_one_flow(self):
        events = aggregate_packets([
            packet(1, tcp_flags="S"),
            packet(2, src="198.51.100.20", dst="192.0.2.10",
                   sport=443, dport=50000, length=52, tcp_flags="SA"),
            packet(3, length=100, tcp_flags="PA"),
        ])
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertEqual(event["src_ip"], "192.0.2.10")
        self.assertEqual(event["dst_ip"], "198.51.100.20")
        self.assertEqual(event["dst_port"], 443)
        self.assertEqual(event["timestamp"], 3.0)
        self.assertEqual(event["bytes_transferred"], 160)
        self.assertEqual(event["protocol"], "TCP")

    def test_flow_metadata_is_omitted_until_enabled(self):
        records = [packet(1, tcp_flags="SA"), packet(2, tcp_flags="R")]
        default_event = aggregate_packets(records)[0]
        self.assertNotIn("tcp_flags", default_event)
        self.assertNotIn("packets", default_event)

        extended_event = aggregate_packets(records, include_flow_metadata=True)[0]
        self.assertEqual(extended_event["tcp_flags"], "SRA")
        self.assertEqual(extended_event["packets"], 2)

    def test_idle_timeout_closes_flow_at_exact_boundary(self):
        events = aggregate_packets([
            packet(1),
            packet(31, length=70),
        ], idle_timeout=30)
        self.assertEqual(len(events), 2)
        self.assertEqual([event["timestamp"] for event in events], [1.0, 31.0])

    def test_records_are_sorted_and_output_events_are_timestamp_ordered(self):
        records = [
            packet(3, dst="198.51.100.30", dport=80),
            packet(2, dst="198.51.100.40", dport=8080),
            packet(1, dst="198.51.100.30", dport=80),
        ]
        events = aggregate_packets(records)
        self.assertEqual([event["timestamp"] for event in events], [2.0, 3.0])

    def test_dns_questions_are_events_not_generic_flows(self):
        records = [
            packet(1, dport=53, protocol="UDP", is_dns=True, dns_query="example.com."),
            packet(1, dport=53, protocol="UDP", is_dns=True, dns_query="example.org"),
            packet(2, dport=53, protocol="UDP", is_dns=True),
        ]
        events = aggregate_packets(records)
        self.assertEqual(len(events), 2)
        self.assertEqual([event["dns_query"] for event in events], ["example.com", "example.org"])
        self.assertTrue(all("bytes_transferred" not in event for event in events))

    def test_flow_direction_and_ports_are_part_of_flow_key(self):
        events = aggregate_packets([
            packet(1, dport=80),
            packet(2, dport=443),
            packet(3, src="192.0.2.11"),
        ])
        self.assertEqual(len(events), 3)

    def test_rejects_invalid_timestamp(self):
        with self.assertRaisesRegex(ValueError, "timestamp must be finite"):
            aggregate_packets([packet(float("nan"))])

    def test_rejects_invalid_ip(self):
        with self.assertRaisesRegex(ValueError, "invalid IP"):
            aggregate_packets([packet(1, src="not-an-ip")])

    def test_rejects_unsupported_protocol(self):
        with self.assertRaisesRegex(ValueError, "TCP or UDP"):
            aggregate_packets([packet(1, protocol="ICMP")])

    def test_rejects_invalid_ports_and_tcp_flags(self):
        with self.assertRaisesRegex(ValueError, "dst_port"):
            aggregate_packets([packet(1, dport=70000)])
        with self.assertRaisesRegex(ValueError, "unknown TCP flags"):
            aggregate_packets([packet(1, tcp_flags="X")])

    def test_rejects_invalid_idle_timeout(self):
        with self.assertRaisesRegex(ValueError, "idle_timeout"):
            aggregate_packets([packet(1)], idle_timeout=0)

    def test_loads_packet_jsonl_and_reports_bad_line(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "packets.jsonl"
            path.write_text(json.dumps(packet(1)) + "\n\n", encoding="utf-8")
            self.assertEqual(len(load_packet_records(path)), 1)
            path.write_text(json.dumps(packet(1)) + "\nnot-json\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "packet record 2"):
                load_packet_records(path)


if __name__ == "__main__":
    unittest.main()
