"""Offline PCAP replay into the shared SENTINEL flow aggregator.

Requires the optional Scapy dependency: pip install -e ".[pcap]".
No live packet capture is performed.
"""
import argparse
import json
import sys
from pathlib import Path

from src.flow_aggregator import aggregate_packets


def _dns_questions(packet, dns_layer, dnsqr_type):
    """Return successfully decoded DNS question names from one DNS query."""
    if dns_layer is None:
        return []
    try:
        if int(getattr(dns_layer, "qr", 1)) != 0:
            return []
    except (TypeError, ValueError):
        return []

    question = getattr(dns_layer, "qd", None)
    if not isinstance(question, dnsqr_type):
        question = packet.getlayer(dnsqr_type)
    if not isinstance(question, dnsqr_type):
        return []

    question_count = int(getattr(dns_layer, "qdcount", 0) or 0)
    names = []
    # A parsed DNS question is still useful if qdcount was omitted or zero.
    for _ in range(max(1, min(question_count, 64))):
        if not isinstance(question, dnsqr_type):
            break
        raw_name = getattr(question, "qname", b"")
        if isinstance(raw_name, bytes):
            name = raw_name.decode("utf-8", errors="replace")
        else:
            name = str(raw_name)
        name = name.rstrip(".")
        if name:
            names.append(name)
        question = getattr(question, "payload", None)
    return names

def read_pcap_packet_records(path):
    """Read supported TCP/UDP packets and normalize them for flow_aggregator."""
    try:
        from scapy.layers.dns import DNS, DNSQR
        from scapy.layers.inet import IP, TCP, UDP
        from scapy.layers.inet6 import IPv6, IPv6ExtHdrFragment
        from scapy.utils import PcapNgReader, PcapReader
    except ImportError as exc:
        raise RuntimeError(
            'PCAP replay requires Scapy. Install it with: python -m pip install -e ".[pcap]"'
        ) from exc

    stats = {
        "packets_read": 0,
        "packet_records": 0,
        "skipped_non_ip": 0,
        "skipped_fragment": 0,
        "skipped_non_tcp_udp": 0,
    }
    records = []
    capture_path = Path(path)
    reader_class = PcapNgReader if capture_path.suffix.lower() == ".pcapng" else PcapReader
    reader = reader_class(str(capture_path))
    try:
        for packet in reader:
            stats["packets_read"] += 1
            if packet.haslayer(IP):
                network = packet[IP]
                if int(network.frag) != 0 or (int(network.flags) & 0x1):
                    stats["skipped_fragment"] += 1
                    continue
            elif packet.haslayer(IPv6):
                network = packet[IPv6]
                if packet.haslayer(IPv6ExtHdrFragment):
                    stats["skipped_fragment"] += 1
                    continue
            else:
                stats["skipped_non_ip"] += 1
                continue

            if packet.haslayer(TCP):
                transport = packet[TCP]
                protocol = "TCP"
                flags = str(transport.flags)
            elif packet.haslayer(UDP):
                transport = packet[UDP]
                protocol = "UDP"
                flags = ""
            else:
                stats["skipped_non_tcp_udp"] += 1
                continue

            base = {
                "timestamp": float(packet.time),
                "src_ip": str(network.src),
                "dst_ip": str(network.dst),
                "src_port": int(transport.sport),
                "dst_port": int(transport.dport),
                "protocol": protocol,
                "packet_length": len(bytes(network)),
            }
            if protocol == "TCP":
                base["tcp_flags"] = flags

            dns_layer = packet.getlayer(DNS)
            if dns_layer is not None:
                questions = _dns_questions(packet, dns_layer, DNSQR)
                if questions:
                    for question_name in questions:
                        record = dict(base)
                        record["is_dns"] = True
                        record["dns_query"] = question_name
                        records.append(record)
                else:
                    record = dict(base)
                    record["is_dns"] = True
                    records.append(record)
            else:
                records.append(base)
            stats["packet_records"] = len(records)
    finally:
        reader.close()

    return records, stats


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Replay an offline PCAP file through SENTINEL's shared flow aggregator."
    )
    parser.add_argument("--input", required=True, help="Path to an offline .pcap/.pcapng capture")
    parser.add_argument("--output", help="Optional output JSONL path (default: stdout)")
    parser.add_argument(
        "--idle-timeout", type=float, default=30.0,
        help="Seconds of inactivity before a flow is closed (default: 30)",
    )
    args = parser.parse_args(argv)

    try:
        packet_records, stats = read_pcap_packet_records(args.input)
        events = aggregate_packets(packet_records, idle_timeout=args.idle_timeout)
        output = "".join(json.dumps(event, sort_keys=True) + "\n" for event in events)
        if args.output:
            Path(args.output).write_text(output, encoding="utf-8")
        else:
            sys.stdout.write(output)
    except (OSError, ValueError, RuntimeError) as exc:
        parser.error(str(exc))

    skipped = (
        stats["skipped_non_ip"]
        + stats["skipped_fragment"]
        + stats["skipped_non_tcp_udp"]
    )
    print(
        f"PCAP packets read: {stats['packets_read']}; "
        f"packet records: {stats['packet_records']}; "
        f"events emitted: {len(events)}; skipped packets: {skipped}",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
