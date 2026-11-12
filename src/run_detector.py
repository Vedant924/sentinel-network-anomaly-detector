"""Run SENTINEL's explainable detector against JSONL event data."""
import argparse
import json
from pathlib import Path
from src.detector import (
    correlate_alerts, detect_anomalies, detect_dns_anomalies,
    detect_failed_connections, detect_high_event_rate,
    detect_high_traffic_volume, detect_many_destination_hosts,
    detect_many_destination_ports,
)


def load_events(path):
    events = []
    with Path(path).open("r", encoding="utf-8") as file:
        for number, line in enumerate(file, 1):
            if not line.strip():
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"Invalid JSON on line {number} of {path}: {exc.msg}") from exc
            if not isinstance(event, dict):
                raise ValueError(f"Line {number} of {path} must contain a JSON object")
            events.append(event)
    return events


def _text_report(events, alerts, incidents=None):
    lines = ["SENTINEL | NETWORK ANOMALY REPORT",
             f"SENTINEL analyzed {len(events)} event(s).",
             f"Unique sources: {len({event.get('src_ip') for event in events})}",
             f"Alerts: {len(alerts)}"]
    if not alerts:
        lines.append("No anomalies detected.")
    for number, alert in enumerate(alerts, 1):
        lines.extend([
            f"[{number}] {alert['severity']} | {alert['alert_id']} | {alert['rule_id']}",
            f"    Source: {alert['source']}",
            f"    Observed: {alert['observed']} (threshold: {alert['threshold']})",
            f"    Window: {alert['window_start']:.3f} - {alert['window_end']:.3f}s",
            f"    Why: {alert['reason']}",
            f"    Evidence: {json.dumps(alert['evidence'], sort_keys=True)}",
            f"    Suggested review: {alert['recommended_action']}",
            f"    Limitation: {alert['uncertainty']}",
        ])
    if incidents:
        lines.append(f"Correlated incidents: {len(incidents)}")
        for incident in incidents:
            lines.append(f"  {incident['incident_id']} | {incident['source']} | rules: {', '.join(incident['correlated_rules'])}")
    return "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Detect suspicious patterns in SENTINEL JSONL network events.")
    parser.add_argument("--input", default="data/sample_events.jsonl", help="Path to a JSONL event file")
    parser.add_argument("--window", type=float, default=10, help="Detection window in seconds")
    parser.add_argument("--threshold", type=int, default=10, help="Legacy port/rate threshold")
    parser.add_argument("--rule", choices=("ports", "rate", "failed", "volume", "dns", "hosts", "all"), default="ports")
    parser.add_argument("--byte-threshold", type=int, default=1000000, help="Bytes per window before traffic-volume alert")
    parser.add_argument("--failed-threshold", type=int, default=10, help="Failed connection attempts per window")
    parser.add_argument("--dns-query-threshold", type=int, default=50, help="DNS queries per window")
    parser.add_argument("--host-threshold", type=int, default=20, help="Distinct destination IPs per window")
    parser.add_argument("--correlate", action="store_true", help="Group related alerts from the same source")
    parser.add_argument("--correlation-window", type=float, default=60, help="Maximum gap between alerts to correlate")
    parser.add_argument("--format", choices=("text", "json"), default="text")
    parser.add_argument("--output", help="Optional path to save the report")
    args = parser.parse_args(argv)
    try:
        events = load_events(args.input)
        if args.rule == "ports":
            alerts = detect_many_destination_ports(events, args.window, args.threshold)
        elif args.rule == "rate":
            alerts = detect_high_event_rate(events, args.window, args.threshold)
        elif args.rule == "failed":
            alerts = detect_failed_connections(events, max(args.window, 60), args.failed_threshold)
        elif args.rule == "volume":
            alerts = detect_high_traffic_volume(events, args.window, args.byte_threshold)
        elif args.rule == "dns":
            alerts = detect_dns_anomalies(events, max(args.window, 60), args.dns_query_threshold)
        elif args.rule == "hosts":
            alerts = detect_many_destination_hosts(events, max(args.window, 30), args.host_threshold)
        else:
            alerts = detect_anomalies(
                events, args.window, args.threshold, args.threshold,
                args.failed_threshold, args.byte_threshold,
                args.dns_query_threshold, 80, args.host_threshold,
            )
        incidents = correlate_alerts(alerts, args.correlation_window) if args.correlate else []
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    if args.format == "json":
        sources = {event.get("src_ip") for event in events}
        report = {"tool": "SENTINEL", "events_analyzed": len(events), "unique_sources": len(sources),
                  "alert_count": len(alerts), "correlated_incident_count": len(incidents),
                  "severity_counts": {level: sum(a["severity"] == level for a in alerts)
                                      for level in sorted({a["severity"] for a in alerts})},
                  "alerts": alerts, "correlated_incidents": incidents}
        output = json.dumps(report, indent=2, sort_keys=True)
    else:
        output = _text_report(events, alerts, incidents)
    if args.output:
        try:
            Path(args.output).write_text(output + "\n", encoding="utf-8")
        except OSError as exc:
            parser.error(f"Could not write report to {args.output}: {exc}")
        print(f"Report saved to {args.output}")
    else:
        print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
