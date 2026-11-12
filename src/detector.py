"""Explainable network anomaly rules with structured alert evidence."""
import hashlib
import ipaddress
import json
import math
from collections import defaultdict


def validate_ip(value, field_name="src_ip"):
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field_name} must be a non-empty string")
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError as exc:
        raise ValueError(f"{field_name} must be a valid IPv4 or IPv6 address, got {value!r}") from exc


def _validate_and_extract_event(event):
    if not isinstance(event, dict):
        raise ValueError("Each event must be an object with timestamp, src_ip, and dst_port")
    if isinstance(event.get("timestamp"), bool):
        raise ValueError("timestamp must be a finite number")
    try:
        ts, raw_ip, raw_port = float(event["timestamp"]), event["src_ip"], event["dst_port"]
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("Each event must have a numeric timestamp, src_ip, and integer dst_port") from exc
    if not math.isfinite(ts):
        raise ValueError("timestamp must be a finite number")
    src = validate_ip(raw_ip, "src_ip")
    if "dst_ip" in event and event["dst_ip"] is not None:
        validate_ip(event["dst_ip"], "dst_ip")
    if isinstance(raw_port, bool):
        raise ValueError("dst_port must be an integer between 1 and 65535")
    try:
        port = int(raw_port)
    except (TypeError, ValueError, OverflowError) as exc:
        raise ValueError("dst_port must be an integer between 1 and 65535") from exc
    if (isinstance(raw_port, float) and not raw_port.is_integer()) or (isinstance(raw_port, str) and str(port) != raw_port.strip()):
        raise ValueError("dst_port must be an integer between 1 and 65535")
    if not 1 <= port <= 65535:
        raise ValueError("dst_port must be between 1 and 65535")
    return ts, src, port


def _make_alert(rule, source, timestamp, window, threshold, observed, evidence, reason, action, uncertainty):
    fingerprint = json.dumps([rule, source, timestamp, window, threshold, observed], separators=(",", ":"))
    alert = {
        "alert_id": "SNT-" + hashlib.sha256(fingerprint.encode()).hexdigest()[:16].upper(),
        "rule_id": rule, "rule": rule, "category": "NETWORK_BEHAVIOR",
        "source": source, "timestamp": timestamp,
        "first_seen": max(0, timestamp-window), "last_seen": timestamp,
        "window_start": timestamp-window, "window_end": timestamp, "window_seconds": window,
        "severity": "HIGH",
        "severity_reason": "The configured detection threshold was exceeded; analyst review is recommended.",
        "observed": observed, "threshold": threshold, "evidence": evidence, "reason": reason,
        "recommended_action": action, "uncertainty": uncertainty,
        "classification": "SUSPICIOUS_PATTERN",
    }
    alert["unique_destination_ports" if rule == "MANY_DESTINATION_PORTS" else "observed_count"] = observed
    return alert


def detect_many_destination_ports(events, window_seconds=10, threshold=10):
    if not isinstance(window_seconds, (int, float)) or isinstance(window_seconds, bool) or not math.isfinite(window_seconds) or window_seconds <= 0:
        raise ValueError("window_seconds must be a finite number greater than 0")
    if not isinstance(threshold, int) or isinstance(threshold, bool) or threshold < 1:
        raise ValueError("threshold must be a positive integer")
    grouped = defaultdict(list)
    for event in events:
        ts, src, port = _validate_and_extract_event(event)
        grouped[src].append((ts, port))
    alerts = []
    for src, rows in grouped.items():
        rows.sort()
        left, counts, active = 0, defaultdict(int), False
        for right, (ts, port) in enumerate(rows):
            counts[port] += 1
            while left <= right and rows[left][0] < ts-window_seconds:
                old = rows[left][1]
                counts[old] -= 1
                if counts[old] == 0:
                    del counts[old]
                left += 1
            observed = len(counts)
            if observed <= threshold:
                active = False
            elif not active:
                alerts.append(_make_alert(
                    "MANY_DESTINATION_PORTS", src, ts, window_seconds, threshold, observed,
                    {"distinct_destination_ports": observed, "destination_ports_sample": sorted(counts)[:20],
                     "events_in_window": right-left+1},
                    f"One source contacted {observed} different destination ports within {window_seconds} seconds.",
                    "Review the source host and related connection records; confirm whether the scan was authorized.",
                    "Approved inventory or diagnostic tools can also contact many destination ports.",
                ))
                active = True
    return alerts


def detect_high_event_rate(events, window_seconds=10, max_events=10):
    if not isinstance(window_seconds, (int, float)) or isinstance(window_seconds, bool) or not math.isfinite(window_seconds) or window_seconds <= 0:
        raise ValueError("window_seconds must be a finite number greater than 0")
    if not isinstance(max_events, int) or isinstance(max_events, bool) or max_events < 1:
        raise ValueError("max_events must be a positive integer")
    grouped = defaultdict(list)
    for event in events:
        ts, src, _ = _validate_and_extract_event(event)
        grouped[src].append(ts)
    alerts = []
    for src, times in grouped.items():
        times.sort()
        left, active = 0, False
        for right, ts in enumerate(times):
            while left <= right and times[left] < ts-window_seconds:
                left += 1
            observed = right-left+1
            if observed <= max_events:
                active = False
            elif not active:
                alerts.append(_make_alert(
                    "HIGH_EVENT_RATE", src, ts, window_seconds, max_events, observed,
                    {"events_in_window": observed, "events_per_second": round(observed/window_seconds, 3)},
                    f"One source generated {observed} events within {window_seconds} seconds (threshold: {max_events}).",
                    "Inspect connection logs and the source process; verify whether the burst is expected.",
                    "Legitimate workloads can also generate short traffic bursts.",
                ))
                active = True
    return alerts


def detect_anomalies(events, window_seconds=10, port_threshold=10, rate_threshold=20):
    alerts = detect_many_destination_ports(events, window_seconds, port_threshold)
    alerts.extend(detect_high_event_rate(events, window_seconds, rate_threshold))
    return sorted(alerts, key=lambda a: (a["timestamp"], a["rule_id"], a["source"]))
