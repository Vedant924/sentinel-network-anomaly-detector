"""Explainable network anomaly rules for SENTINEL."""
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
    if event.get("dst_ip") is not None:
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


def _event_details(event):
    ts, src, port = _validate_and_extract_event(event)
    raw_bytes = event.get("bytes_transferred", event.get("bytes", 0))
    if isinstance(raw_bytes, bool):
        raise ValueError("bytes_transferred must be a non-negative integer")
    try:
        byte_count = int(raw_bytes)
    except (TypeError, ValueError, OverflowError) as exc:
        raise ValueError("bytes_transferred must be a non-negative integer") from exc
    if byte_count < 0 or (isinstance(raw_bytes, float) and not raw_bytes.is_integer()):
        raise ValueError("bytes_transferred must be a non-negative integer")
    dst = validate_ip(event["dst_ip"], "dst_ip") if event.get("dst_ip") is not None else None
    status = str(event.get("connection_status", event.get("status", ""))).strip().lower()
    query = event.get("dns_query", event.get("query_name"))
    if query is not None and (not isinstance(query, str) or not query.strip()):
        raise ValueError("dns_query must be a non-empty string when provided")
    return {"timestamp": ts, "src_ip": src, "dst_port": port, "dst_ip": dst,
            "bytes_transferred": byte_count, "status": status,
            "dns_query": query.strip().lower().rstrip(".") if query else None}


def _make_alert(rule, source, timestamp, window, threshold, observed, evidence, reason, action, uncertainty):
    fingerprint = json.dumps([rule, source, timestamp, window, threshold, observed], separators=(",", ":"))
    return {
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
        "unique_destination_ports" if rule == "MANY_DESTINATION_PORTS" else "observed_count": observed,
    }


def _validate_window(window_seconds):
    if not isinstance(window_seconds, (int, float)) or isinstance(window_seconds, bool) or not math.isfinite(window_seconds) or window_seconds <= 0:
        raise ValueError("window_seconds must be a finite number greater than 0")


def _validate_threshold(threshold, name="threshold"):
    if not isinstance(threshold, int) or isinstance(threshold, bool) or threshold < 1:
        raise ValueError(f"{name} must be a positive integer")


def _group_events(events):
    grouped = defaultdict(list)
    for event in events:
        item = _event_details(event)
        grouped[item["src_ip"]].append(item)
    for rows in grouped.values():
        rows.sort(key=lambda item: item["timestamp"])
    return grouped


def _sliding_windows(rows, window_seconds):
    left = 0
    for right, item in enumerate(rows):
        while left <= right and rows[left]["timestamp"] < item["timestamp"] - window_seconds:
            left += 1
        yield right, rows[left:right + 1]


def detect_many_destination_ports(events, window_seconds=10, threshold=10):
    _validate_window(window_seconds)
    _validate_threshold(threshold)
    alerts = []
    for source, rows in _group_events(events).items():
        active = False
        for _, window in _sliding_windows(rows, window_seconds):
            ports = sorted({item["dst_port"] for item in window})
            observed = len(ports)
            if observed <= threshold:
                active = False
            elif not active:
                ts = window[-1]["timestamp"]
                alerts.append(_make_alert(
                    "MANY_DESTINATION_PORTS", source, ts, window_seconds, threshold, observed,
                    {"distinct_destination_ports": observed, "destination_ports_sample": ports[:20],
                     "events_in_window": len(window)},
                    f"One source contacted {observed} different destination ports within {window_seconds} seconds.",
                    "Review the source host and related connection records; confirm whether the scan was authorized.",
                    "Approved inventory or diagnostic tools can also contact many destination ports."))
                active = True
    return alerts


def detect_high_event_rate(events, window_seconds=10, max_events=10):
    _validate_window(window_seconds)
    _validate_threshold(max_events, "max_events")
    alerts = []
    for source, rows in _group_events(events).items():
        active = False
        for _, window in _sliding_windows(rows, window_seconds):
            observed = len(window)
            if observed <= max_events:
                active = False
            elif not active:
                ts = window[-1]["timestamp"]
                alerts.append(_make_alert(
                    "HIGH_EVENT_RATE", source, ts, window_seconds, max_events, observed,
                    {"events_in_window": observed, "events_per_second": round(observed/window_seconds, 3)},
                    f"One source generated {observed} events within {window_seconds} seconds (threshold: {max_events}).",
                    "Inspect connection logs and the source process; verify whether the burst is expected.",
                    "Legitimate workloads can also generate short traffic bursts."))
                active = True
    return alerts


def detect_failed_connections(events, window_seconds=60, threshold=10):
    """Detect repeated failed, refused, reset, or timed-out connection attempts."""
    _validate_window(window_seconds)
    _validate_threshold(threshold)
    failed_states = {"failed", "failure", "timeout", "timed_out", "refused", "reset", "rejected", "error"}
    grouped = defaultdict(list)
    for item in (_event_details(event) for event in events):
        if item["status"] in failed_states:
            grouped[item["src_ip"]].append(item)
    alerts = []
    for source, rows in grouped.items():
        rows.sort(key=lambda item: item["timestamp"])
        active = False
        for _, window in _sliding_windows(rows, window_seconds):
            observed = len(window)
            if observed <= threshold:
                active = False
            elif not active:
                ts = window[-1]["timestamp"]
                alerts.append(_make_alert(
                    "REPEATED_FAILED_CONNECTIONS", source, ts, window_seconds, threshold, observed,
                    {"failed_attempts": observed, "destination_ports": sorted({x["dst_port"] for x in window})[:20],
                     "failure_reasons": dict((state, sum(x["status"] == state for x in window)) for state in sorted({x["status"] for x in window}))},
                    f"Source generated {observed} failed connection attempts within {window_seconds} seconds.",
                    "Check the source process, destination availability, authentication logs, and whether repeated retries are expected.",
                    "Misconfigured clients, outages, and temporary network faults can cause legitimate failures."))
                active = True
    return alerts


def detect_high_traffic_volume(events, window_seconds=10, byte_threshold=1000000):
    """Detect a source transferring more than byte_threshold bytes in a sliding window."""
    _validate_window(window_seconds)
    _validate_threshold(byte_threshold, "byte_threshold")
    alerts = []
    for source, rows in _group_events(events).items():
        active = False
        for _, window in _sliding_windows(rows, window_seconds):
            total = sum(x["bytes_transferred"] for x in window)
            if total <= byte_threshold:
                active = False
            elif not active:
                ts = window[-1]["timestamp"]
                alerts.append(_make_alert(
                    "HIGH_TRAFFIC_VOLUME", source, ts, window_seconds, byte_threshold, total,
                    {"bytes_in_window": total, "megabytes_in_window": round(total/1000000, 3),
                     "events_in_window": len(window), "destination_ips": len({x["dst_ip"] for x in window if x["dst_ip"]})},
                    f"Source transferred {total} bytes within {window_seconds} seconds (threshold: {byte_threshold}).",
                    "Review transfer destination, process ownership, and expected workload before escalating.",
                    "Backups, software updates, media streaming, and bulk transfers may be legitimate."))
                active = True
    return alerts


def _dns_entropy(value):
    if not value:
        return 0.0
    counts = {char: value.count(char) for char in set(value)}
    return -sum((count/len(value))*math.log2(count/len(value)) for count in counts.values())


def detect_dns_anomalies(events, window_seconds=60, query_threshold=50, suspicious_length=80):
    """Detect DNS query bursts and unusually long/high-entropy query names."""
    _validate_window(window_seconds)
    _validate_threshold(query_threshold, "query_threshold")
    _validate_threshold(suspicious_length, "suspicious_length")
    grouped = defaultdict(list)
    for item in (_event_details(event) for event in events):
        if item["dns_query"]:
            grouped[item["src_ip"]].append(item)
    alerts = []
    for source, rows in grouped.items():
        rows.sort(key=lambda item: item["timestamp"])
        active = False
        for _, window in _sliding_windows(rows, window_seconds):
            observed = len(window)
            if observed <= query_threshold:
                active = False
            elif not active:
                ts = window[-1]["timestamp"]
                alerts.append(_make_alert(
                    "DNS_QUERY_BURST", source, ts, window_seconds, query_threshold, observed,
                    {"dns_queries": observed, "unique_query_names": len({x["dns_query"] for x in window}),
                     "sample_query_names": sorted({x["dns_query"] for x in window})[:5]},
                    f"Source issued {observed} DNS queries within {window_seconds} seconds.",
                    "Review queried domains, client process, and resolver logs for unexpected automation or tunnelling.",
                    "Browsers, endpoint agents, and busy shared hosts can generate high DNS query rates."))
                active = True
        for item in rows:
            query = item["dns_query"]
            labels = query.split(".")
            longest_label = max(map(len, labels))
            entropy = _dns_entropy(query.replace(".", ""))
            if len(query) >= suspicious_length or (len(query) >= 35 and longest_label >= 30 and entropy >= 3.5):
                ts = item["timestamp"]
                alerts.append(_make_alert(
                    "SUSPICIOUS_DNS_QUERY", source, ts, window_seconds, suspicious_length, len(query),
                    {"query_name": query[:200], "query_length": len(query), "longest_label_length": longest_label,
                     "character_entropy_bits": round(entropy, 3)},
                    f"DNS query name length ({len(query)}) or label/entropy pattern is unusual.",
                    "Inspect the queried domain, endpoint process, and DNS logs; check for known legitimate generated hostnames.",
                    "CDNs, tracking systems, and machine-generated service names can be long or high entropy."))
    return alerts


def detect_many_destination_hosts(events, window_seconds=30, threshold=20):
    """Detect one source connecting to many distinct destination IPs in a short window."""
    _validate_window(window_seconds)
    _validate_threshold(threshold)
    alerts = []
    for source, rows in _group_events(events).items():
        active = False
        for _, window in _sliding_windows(rows, window_seconds):
            hosts = sorted({x["dst_ip"] for x in window if x["dst_ip"]})
            observed = len(hosts)
            if observed <= threshold:
                active = False
            elif not active:
                ts = window[-1]["timestamp"]
                alerts.append(_make_alert(
                    "MANY_DESTINATION_HOSTS", source, ts, window_seconds, threshold, observed,
                    {"unique_destination_ips": observed, "destination_ip_sample": hosts[:20],
                     "events_in_window": len(window)},
                    f"Source contacted {observed} distinct destination IP addresses within {window_seconds} seconds.",
                    "Review destination reputation, process ownership, and whether the source is an approved scanner or service.",
                    "Browsers, proxies, CDNs, and update services may contact many hosts."))
                active = True
    return alerts


def deduplicate_alerts(alerts):
    """Remove exact repeated alerts while preserving first-seen order."""
    result, seen = [], set()
    for alert in alerts:
        key = alert.get("alert_id") or (alert.get("rule_id"), alert.get("source"),
                                        alert.get("timestamp"), alert.get("observed"))
        if key not in seen:
            seen.add(key)
            result.append(alert)
    return result


def correlate_alerts(alerts, correlation_window_seconds=60):
    """Group alerts from the same source that occur within a rolling time gap."""
    _validate_window(correlation_window_seconds)
    grouped = defaultdict(list)
    for alert in alerts:
        grouped[alert["source"]].append(alert)
    incidents = []
    for source, rows in grouped.items():
        rows.sort(key=lambda item: item["timestamp"])
        clusters = []
        for alert in rows:
            if not clusters or alert["timestamp"] - clusters[-1][-1]["timestamp"] > correlation_window_seconds:
                clusters.append([alert])
            else:
                clusters[-1].append(alert)
        for cluster in clusters:
            if len(cluster) < 2:
                continue
            alert_ids = sorted({item["alert_id"] for item in cluster})
            rules = sorted({item["rule_id"] for item in cluster})
            fingerprint = json.dumps([source, alert_ids], separators=(",", ":"))
            incidents.append({
                "incident_id": "INC-" + hashlib.sha256(fingerprint.encode()).hexdigest()[:16].upper(),
                "source": source, "first_seen": min(x["timestamp"] for x in cluster),
                "last_seen": max(x["timestamp"] for x in cluster), "alert_count": len(cluster),
                "correlated_rules": rules, "alert_ids": alert_ids,
                "summary": f"{len(cluster)} alerts across {len(rules)} detection rule(s) were observed for {source}.",
            })
    return sorted(incidents, key=lambda item: (item["first_seen"], item["source"]))


def detect_anomalies(events, window_seconds=10, port_threshold=10, rate_threshold=20,
                     failed_threshold=10, byte_threshold=1000000, dns_query_threshold=50,
                     dns_suspicious_length=80, host_threshold=20):
    """Run all Phase 1 and Phase 2 rules, then deduplicate exact alert repeats."""
    alerts = []
    alerts.extend(detect_many_destination_ports(events, window_seconds, port_threshold))
    alerts.extend(detect_high_event_rate(events, window_seconds, rate_threshold))
    alerts.extend(detect_failed_connections(events, max(window_seconds, 60), failed_threshold))
    alerts.extend(detect_high_traffic_volume(events, window_seconds, byte_threshold))
    alerts.extend(detect_dns_anomalies(events, max(window_seconds, 60), dns_query_threshold, dns_suspicious_length))
    alerts.extend(detect_many_destination_hosts(events, max(window_seconds, 30), host_threshold))
    alerts = deduplicate_alerts(alerts)
    return sorted(alerts, key=lambda item: (item["timestamp"], item["rule_id"], item["source"]))
