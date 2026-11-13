"""Scapy-backed tests for offline PCAP decoding."""
import importlib.util
import tempfile
import unittest
from pathlib import Path

SCAPY_AVAILABLE = importlib.util.find_spec("scapy") is not None

if SCAPY_AVAILABLE:
    from scapy.layers.dns import DNS, DNSQR
    from scapy.layers.inet import ICMP, IP, TCP, UDP
    from scapy.packet import Raw
    from scapy.utils import wrpcap

from src.pcap_replay import read_pcap_packet_records
from src.flow_aggregator import aggregate_packets


@unittest.skipUnless(SCAPY_AVAILABLE, "Scapy optional dependency is not installed")
class PcapReplayTests(unittest.TestCase):
    def test_reads_tcp_flow_and_dns_query_but_skips_icmp_and_fragments(self):
        tcp = (
            IP(src="192.0.2.10", dst="198.51.100.20")
            / TCP(sport=50000, dport=443, flags="S")
            / Raw(load=b"hello")
        )
        dns = (
            IP(src="192.0.2.10", dst="198.51.100.53")
            / UDP(sport=53000, dport=53)
            / DNS(rd=1, qdcount=1, qd=DNSQR(qname="example.com"))
        )
        icmp = IP(src="192.0.2.10", dst="198.51.100.1") / ICMP()
        fragment = (
            IP(src="192.0.2.10", dst="198.51.100.20", flags="MF", frag=0)
            / UDP(sport=50000, dport=9999)
        )

        with tempfile.TemporaryDirectory() as directory:
            capture = Path(directory) / "sample.pcap"
            wrpcap(str(capture), [tcp, dns, icmp, fragment])
            records, stats = read_pcap_packet_records(capture)

        self.assertEqual(stats["packets_read"], 4)
        self.assertEqual(stats["skipped_non_tcp_udp"], 1)
        self.assertEqual(stats["skipped_fragment"], 1)
        self.assertEqual(stats["packet_records"], 2)
        self.assertEqual(records[0]["protocol"], "TCP")
        self.assertEqual(records[0]["tcp_flags"], "S")
        self.assertEqual(records[1]["dns_query"], "example.com")
        self.assertTrue(records[1]["is_dns"])

        events = aggregate_packets(records)
        self.assertEqual(len(events), 2)
        self.assertEqual(events[0]["protocol"], "TCP")
        self.assertEqual(events[1]["dns_query"], "example.com")
        self.assertNotIn("tcp_flags", events[0])
        self.assertNotIn("packets", events[0])


if __name__ == "__main__":
    unittest.main()
