"""Small, explainable rules for detecting suspicious network events."""

from collections import defaultdict


def detect_many_destination_ports(events, window_seconds=10, threshold=10):
    """Return alerts when one source contacts too many distinct ports in a time window.

    Each event must contain: timestamp (number of seconds), src_ip, and dst_port.
    The time window includes events from the current timestamp back to
    current timestamp - window_seconds, inclusive.
    """
    if window_seconds <= 0:
        raise ValueError("window_seconds must be greater than 0")
    if threshold < 1:
        raise ValueError("threshold must be at least 1")

    events_by_source = defaultdict(list)
    for event in events:
        try:
            timestamp = float(event["timestamp"])
            source = str(event["src_ip"])
            port = int(event["dst_port"])
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError(
                "Each event must have a numeric timestamp, src_ip, and integer dst_port"
            ) from exc

        if not 1 <= port <= 65535:
            raise ValueError("dst_port must be between 1 and 65535")

        events_by_source[source].append((timestamp, port))

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
