"""Shared packet-to-flow aggregation for PCAP replay and the C sniffer.

The module accepts normalized raw packet records and emits detector-compatible
JSONL events. It intentionally has no Scapy dependency.
"""
import argparse
import ipaddress
import json
import math
import sys
from pathlib import Path


DEFAULT_IDLE_TIMEOUT = 30.0
TCP_FLAG_ORDER = "FSRPAUEC"


def _normalize_packet(packet, line_number=None):
    location = f" on packet record {line_number}" if line_number is not None else ""
    if not isinstance(packet, dict):
        raise ValueError(f"Packet record{location} must be a JSON object.")

    required = (
        "timestamp", "src_ip", "dst_ip", "src_port", "dst_port",
        "protocol", "packet_length",
    )
    missing = [key for key in required if key not in packet]
    if missing:
        raise ValueError(f"Packet record{location} is missing: {', '.join(missing)}")

    timestamp = packet["timestamp"]
    if isinstance(timestamp, bool) or not isinstance(timestamp, (int, float)) or not math.isfinite(timestamp):
        raise ValueError(f"Packet record{location} timestamp must be finite numeric seconds.")

    try:
        src_ip = str(ipaddress.ip_address(packet["src_ip"]))
        dst_ip = str(ipaddress.ip_address(packet["dst_ip"]))
    except (ValueError, TypeError) as exc:
        raise ValueError(f"Packet record{location} contains an invalid IP address.") from exc

    for field in ("src_port", "dst_port"):
        value = packet[field]
        if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 65535:
            raise ValueError(f"Packet record{location} {field} must be an integer from 1 to 65535.")

    protocol = str(packet["protocol"]).upper()
    if protocol not in {"TCP", "UDP"}:
        raise ValueError(f"Packet record{location} protocol must be TCP or UDP.")

    packet_length = packet["packet_length"]
    if isinstance(packet_length, bool) or not isinstance(packet_length, int) or packet_length < 0:
        raise ValueError(f"Packet record{location} packet_length must be a non-negative integer.")

    flags = packet.get("tcp_flags", "")
    if flags is None:
        flags = ""
    if not isinstance(flags, str):
        raise ValueError(f"Packet record{location} tcp_flags must be a string.")
    invalid_flags = set(flags.upper()) - set(TCP_FLAG_ORDER)
    if invalid_flags:
        raise ValueError(f"Packet record{location} contains unknown TCP flags: {''.join(sorted(invalid_flags))}")
    if protocol != "TCP" and flags:
        raise ValueError(f"Packet record{location} cannot set tcp_flags for UDP.")

    is_dns = packet.get("is_dns", False)
    if not isinstance(is_dns, bool):
        raise ValueError(f"Packet record{location} is_dns must be a boolean.")
    dns_query = packet.get("dns_query")
    if dns_query is not None:
        if not isinstance(dns_query, str) or not dns_query.strip():
            raise ValueError(f"Packet record{location} dns_query must be a non-empty string.")
        is_dns = True

    return {
        "timestamp": float(timestamp),
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": packet["src_port"],
        "dst_port": packet["dst_port"],
        "protocol": protocol,
        "packet_length": packet_length,
        "tcp_flags": flags.upper(),
        "is_dns": is_dns,
        "dns_query": dns_query.rstrip(".") if dns_query else None,
    }


class _Flow:
    def __init__(self, packet):
        self.protocol = packet["protocol"]
        self.src_ip = packet["src_ip"]
        self.dst_ip = packet["dst_ip"]
        self.src_port = packet["src_port"]
        self.dst_port = packet["dst_port"]
        self.last_seen = packet["timestamp"]
        self.forward_bytes = 0
        self.packet_count = 0
        self.flags = set()
        self.add(packet)

    def add(self, packet):
        self.last_seen = packet["timestamp"]
        self.packet_count += 1
        same_direction = (
            packet["src_ip"] == self.src_ip
            and packet["dst_ip"] == self.dst_ip
            and packet["src_port"] == self.src_port
            and packet["dst_port"] == self.dst_port
        )
        if same_direction:
            self.forward_bytes += packet["packet_length"]
        self.flags.update(packet["tcp_flags"])

    def to_event(self, include_flow_metadata=False):
        event = {
            "timestamp": self.last_seen,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "bytes_transferred": self.forward_bytes,
        }
        # Proposed fields remain opt-in until the shared event schema is merged.
        if include_flow_metadata:
            event["packets"] = self.packet_count
            if self.protocol == "TCP":
                event["tcp_flags"] = "".join(
                    flag for flag in TCP_FLAG_ORDER if flag in self.flags
                )
        return event


def _flow_key(packet):
    endpoints = tuple(sorted((
        (packet["src_ip"], packet["src_port"]),
        (packet["dst_ip"], packet["dst_port"]),
    )))
    return packet["protocol"], endpoints


def aggregate_packets(packet_records, idle_timeout=DEFAULT_IDLE_TIMEOUT, include_flow_metadata=False):
    """Aggregate packet records into timestamp-ordered detector events.

    The bidirectional 5-tuple identifies a flow. The first observed direction
    is retained for src/dst fields and forward-byte accounting. A gap equal to
    or greater than idle_timeout closes the old flow. DNS query records become
    one event per parsed question and are excluded from generic flow aggregation.

    Proposed packets and flow-level tcp_flags output remains opt-in until the
    shared event schema update is reviewed and merged.
    """
    if isinstance(idle_timeout, bool) or not isinstance(idle_timeout, (int, float)) or not math.isfinite(idle_timeout) or idle_timeout <= 0:
        raise ValueError("idle_timeout must be a finite number greater than zero.")
    if not isinstance(include_flow_metadata, bool):
        raise ValueError("include_flow_metadata must be a boolean.")

    packets = [
        _normalize_packet(packet, index)
        for index, packet in enumerate(packet_records, 1)
    ]
    packets.sort(key=lambda item: item["timestamp"])

    active = {}
    emitted = []
    sequence = 0

    def emit(event):
        nonlocal sequence
        sequence += 1
        emitted.append((event["timestamp"], sequence, event))

    for packet in packets:
        if packet["is_dns"]:
            if packet["dns_query"]:
                emit({
                    "timestamp": packet["timestamp"],
                    "src_ip": packet["src_ip"],
                    "dst_ip": packet["dst_ip"],
                    "dst_port": packet["dst_port"],
                    "protocol": packet["protocol"],
                    "dns_query": packet["dns_query"],
                })
            continue

        key = _flow_key(packet)
        flow = active.get(key)
        if flow is not None and packet["timestamp"] - flow.last_seen >= idle_timeout:
            emit(flow.to_event(include_flow_metadata))
            del active[key]
            flow = None

        if flow is None:
            active[key] = _Flow(packet)
        else:
            flow.add(packet)

    for flow in active.values():
        emit(flow.to_event(include_flow_metadata))

    emitted.sort(key=lambda item: (item[0], item[1]))
    return [event for _, _, event in emitted]


def load_packet_records(source):
    """Load raw packet records from a JSONL file or stdin ('-')."""
    if source == "-":
        lines = sys.stdin
    else:
        lines = Path(source).open("r", encoding="utf-8")

    records = []
    try:
        for line_number, line in enumerate(lines, 1):
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"Invalid JSON on packet record {line_number}: {exc.msg}") from exc
            if not isinstance(record, dict):
                raise ValueError(f"Packet record {line_number} must contain a JSON object.")
            records.append(record)
    finally:
        if source != "-":
            lines.close()
    return records


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Aggregate raw SENTINEL packet JSONL records into flow events."
    )
    parser.add_argument("--input", default="-", help="Packet-record JSONL path, or '-' for stdin")
    parser.add_argument("--idle-timeout", type=float, default=DEFAULT_IDLE_TIMEOUT)
    parser.add_argument("--output", help="Optional output JSONL path")
    args = parser.parse_args(argv)

    try:
        records = load_packet_records(args.input)
        events = aggregate_packets(records, idle_timeout=args.idle_timeout)
        output = "".join(json.dumps(event, sort_keys=True) + "\n" for event in events)
        if args.output:
            Path(args.output).write_text(output, encoding="utf-8")
        else:
            sys.stdout.write(output)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
