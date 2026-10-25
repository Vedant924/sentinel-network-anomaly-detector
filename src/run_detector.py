"""Run SENTINEL's explainable detector against JSONL event data."""

import argparse
import json
from pathlib import Path

from src.detector import (
    detect_anomalies,
    detect_high_event_rate,
    detect_many_destination_ports,
)


def load_events(path):
    """Load JSONL events, reporting the exact line containing invalid JSON."""
    events = []
    with Path(path).open("r", encoding="utf-8") as file:
        for line_number, line in enumerate(file, start=1):
            if not line.strip():
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"Invalid JSON on line {line_number} of {path}: {exc.msg}"
                ) from exc
            if not isinstance(event, dict):
                raise ValueError(
                    f"Line {line_number} of {path} must contain a JSON object"
                )
            events.append(event)
    return events


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Detect unusual destination-port activity in JSONL events."
    )
    parser.add_argument(
        "--input",
        default="data/sample_events.jsonl",
        help="Path to a JSONL event file (default: data/sample_events.jsonl)",
    )
    parser.add_argument(
        "--window",
        type=float,
        default=10,
        help="Detection window in seconds (default: 10)",
    )
    parser.add_argument(
        "--threshold",
        type=int,
        default=10,
        help="Maximum allowed distinct destination ports before alerting (default: 10)",
    )
    parser.add_argument(
        "--rule",
        choices=("ports", "rate", "all"),
        default="ports",
        help="Detection rule to apply: 'ports' (distinct ports), 'rate' (event frequency), or 'all' (default: ports)",
    )
    parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="Output format: readable text or machine-readable JSON (default: text)",
    )
    parser.add_argument(
        "--output",
        help="Optional path to save the report instead of printing it to the terminal",
    )
    args = parser.parse_args(argv)

    try:
        events = load_events(args.input)
        if args.rule == "rate":
            alerts = detect_high_event_rate(
                events,
                window_seconds=args.window,
                max_events=args.threshold,
            )
        elif args.rule == "all":
            alerts = detect_anomalies(
                events,
                window_seconds=args.window,
                port_threshold=args.threshold,
                rate_threshold=args.threshold,
            )
        else:
            alerts = detect_many_destination_ports(
                events,
                window_seconds=args.window,
                threshold=args.threshold,
            )
    except (OSError, ValueError) as exc:
        parser.error(str(exc))

    if args.format == "json":
        sources = {event["src_ip"] for event in events}
        report = {
            "tool": "SENTINEL",
            "events_analyzed": len(events),
            "unique_sources": len(sources),
            "alert_count": len(alerts),
            "severity_counts": {
                severity: sum(alert["severity"] == severity for alert in alerts)
                for severity in sorted({alert["severity"] for alert in alerts})
            },
            "alerts": alerts,
        }
        output_text = json.dumps(report, indent=2, sort_keys=True)
    else:
        lines = [f"SENTINEL analyzed {len(events)} event(s)."]
        if not alerts:
            lines.append("No anomalies detected.")
        else:
            lines.append(f"Detected {len(alerts)} alert(s):")
            for number, alert in enumerate(alerts, start=1):
                lines.append(
                    f"[{number}] {alert['severity']} | {alert['rule']} | "
                    f"source={alert['source']} | "
                    f"distinct_ports={alert['unique_destination_ports']} | "
                    f"window={alert['window_seconds']}s"
                )
                lines.append(f"    {alert['reason']}")
        output_text = "\n".join(lines)

    if args.output:
        try:
            Path(args.output).write_text(output_text + "\n", encoding="utf-8")
        except OSError as exc:
            parser.error(f"Could not write report to {args.output}: {exc}")
        print(f"Report saved to {args.output}")
    else:
        print(output_text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
