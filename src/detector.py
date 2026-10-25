"""Small, explainable rules for detecting suspicious network events."""

import ipaddress
import math
from collections import defaultdict


def validate_ip(ip_value, field_name="src_ip"):
    """Validate that ip_value is a valid IPv4 or IPv6 address string.

    Returns the canonical string representation of the IP address.

    Raises:
        ValueError: If ip_value is not a non-empty string or not a valid IP address.
    """
    if not isinstance(ip_value, str) or not ip_value.strip():
        raise ValueError(f"{field_name} must be a non-empty string")
    try:
        return str(ipaddress.ip_address(ip_value.strip()))
    except ValueError as exc:
        raise ValueError(
            f"{field_name} must be a valid IPv4 or IPv6 address, got {ip_value!r}"
        ) from exc


def detect_many_destination_ports(events, window_seconds=10, threshold=10):
    """Return alerts when one source contacts too many distinct ports in a time window.

    Each event must contain: timestamp (number of seconds), src_ip, and dst_port.
    The time window includes events from the current timestamp back to
    current timestamp - window_seconds, inclusive.
    """
    if not isinstance(window_seconds, (int, float)) or isinstance(window_seconds, bool):
        raise ValueError("window_seconds must be a finite number greater than 0")
    if not math.isfinite(window_seconds) or window_seconds <= 0:
        raise ValueError("window_seconds must be a finite number greater than 0")
    if not isinstance(threshold, int) or isinstance(threshold, bool) or threshold < 1:
        raise ValueError("threshold must be a positive integer")

    events_by_source = defaultdict(list)
    for event in events:
        if not isinstance(event, dict):
            raise ValueError("Each event must be an object with timestamp, src_ip, and dst_port")

        if isinstance(event.get("timestamp"), bool):
            raise ValueError("timestamp must be a finite number")

        try:
            timestamp = float(event["timestamp"])
            source_raw = event["src_ip"]
            port_value = event["dst_port"]
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError(
                "Each event must have a numeric timestamp, src_ip, and integer dst_port"
            ) from exc

        if not math.isfinite(timestamp):
            raise ValueError("timestamp must be a finite number")

        source_value = validate_ip(source_raw, field_name="src_ip")
        if "dst_ip" in event and event["dst_ip"] is not None:
            validate_ip(event["dst_ip"], field_name="dst_ip")

        if isinstance(port_value, bool):
            raise ValueError("dst_port must be an integer between 1 and 65535")
        try:
            port = int(port_value)
        except (TypeError, ValueError, OverflowError) as exc:
            raise ValueError("dst_port must be an integer between 1 and 65535") from exc
        if isinstance(port_value, float) and not port_value.is_integer():
            raise ValueError("dst_port must be an integer between 1 and 65535")
        if isinstance(port_value, str) and str(port) != port_value.strip():
            raise ValueError("dst_port must be an integer between 1 and 65535")
        if not 1 <= port <= 65535:
            raise ValueError("dst_port must be between 1 and 65535")

        events_by_source[source_value].append((timestamp, port))

    alerts = []
    for source, source_events in events_by_source.items():
        source_events.sort(key=lambda item: item[0])
        left = 0
        ports_in_window = defaultdict(int)
        anomaly_active = False

        for right, (timestamp, port) in enumerate(source_events):
            ports_in_window[port] += 1

            while (
                left <= right
                and source_events[left][0] < timestamp - window_seconds
            ):
                old_port = source_events[left][1]
                ports_in_window[old_port] -= 1
                if ports_in_window[old_port] == 0:
                    del ports_in_window[old_port]
                left += 1

            unique_ports = len(ports_in_window)
            if unique_ports <= threshold:
                anomaly_active = False
            elif not anomaly_active:
                alerts.append(
                    {
                        "rule": "MANY_DESTINATION_PORTS",
                        "source": source,
                        "unique_destination_ports": unique_ports,
                        "threshold": threshold,
                        "window_seconds": window_seconds,
                        "severity": "HIGH",
                        "reason": (
                            f"One source contacted {unique_ports} different "
                            f"destination ports within {window_seconds} seconds."
                        ),
                        "timestamp": timestamp,
                    }
                )
                anomaly_active = True

    return alerts
