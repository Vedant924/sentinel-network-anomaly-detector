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


def _validate_and_extract_event(event):
    """Validate a raw event dictionary and return (timestamp, canonical_src_ip, dst_port).

    Raises ValueError with descriptive context if any field violates schema rules.
    """
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

    return timestamp, source_value, port


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
        timestamp, source_value, port = _validate_and_extract_event(event)
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


def detect_high_event_rate(events, window_seconds=10, max_events=10):
    """Return alerts when one source generates more than max_events within a sliding time window.

    Useful for flagging connection floods, rapid automated probes, or DoS-like traffic bursts.
    """
    if not isinstance(window_seconds, (int, float)) or isinstance(window_seconds, bool):
        raise ValueError("window_seconds must be a finite number greater than 0")
    if not math.isfinite(window_seconds) or window_seconds <= 0:
        raise ValueError("window_seconds must be a finite number greater than 0")
    if not isinstance(max_events, int) or isinstance(max_events, bool) or max_events < 1:
        raise ValueError("max_events must be a positive integer")

    events_by_source = defaultdict(list)
    for event in events:
        timestamp, source_value, _ = _validate_and_extract_event(event)
        events_by_source[source_value].append(timestamp)

    alerts = []
    for source, timestamps in events_by_source.items():
        timestamps.sort()
        left = 0
        anomaly_active = False

        for right, ts in enumerate(timestamps):
            while left <= right and timestamps[left] < ts - window_seconds:
                left += 1

            count = right - left + 1
            if count <= max_events:
                anomaly_active = False
            elif not anomaly_active:
                alerts.append(
                    {
                        "rule": "HIGH_EVENT_RATE",
                        "source": source,
                        "observed_count": count,
                        "threshold": max_events,
                        "window_seconds": window_seconds,
                        "severity": "HIGH",
                        "reason": (
                            f"One source generated {count} events within "
                            f"{window_seconds} seconds (threshold: {max_events})."
                        ),
                        "timestamp": ts,
                    }
                )
                anomaly_active = True

    return alerts


def detect_anomalies(events, window_seconds=10, port_threshold=10, rate_threshold=20):
    """Run all explainable network detection rules across events."""
    alerts = []
    alerts.extend(detect_many_destination_ports(events, window_seconds=window_seconds, threshold=port_threshold))
    alerts.extend(detect_high_event_rate(events, window_seconds=window_seconds, max_events=rate_threshold))
    alerts.sort(key=lambda item: item["timestamp"])
    return alerts
