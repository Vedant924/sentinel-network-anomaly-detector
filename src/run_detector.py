"""Run SENTINEL's explainable detector against JSONL event data."""
import argparse
import json
from pathlib import Path
from src.detector import detect_anomalies, detect_high_event_rate, detect_many_destination_ports


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


def _text_report(events, alerts):
    lines = ["SENTINEL | NETWORK ANOMALY REPORT",
             f"Events analyzed: {len(events)}",
             f"Unique sources: {len({event.get('src_ip') for event in events})}",
             f"Alerts: {len(alerts)}"]
    if not alerts:
        lines.append("Status: No configured anomalies detected.")
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
    return "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Detect suspicious patterns in SENTINEL JSONL network events.")
    parser.add_argument("--input", default="data/sample_events.jsonl", help="Path to a JSONL event file")
    parser.add_argument("--window", type=float, default=10, help="Detection window in seconds")
    parser.add_argument("--threshold", type=int, default=10, help="Rule threshold")
    parser.add_argument("--rule", choices=("ports", "rate", "all"), default="ports")
    parser.add_argument("--format", choices=("text", "json"), default="text")
    parser.add_argument("--output", help="Optional path to save the report")
    args = parser.parse_args(argv)
    try:
        events = load_events(args.input)
        if args.rule == "rate":
            alerts = detect_high_event_rate(events, args.window, args.threshold)
        elif args.rule == "all":
            alerts = detect_anomalies(events, args.window, args.threshold, args.threshold)
        else:
            alerts = detect_many_destination_ports(events, args.window, args.threshold)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    if args.format == "json":
        sources = {event["src_ip"] for event in events}
        report = {"tool": "SENTINEL", "events_analyzed": len(events), "unique_sources": len(sources),
                  "alert_count": len(alerts),
                  "severity_counts": {level: sum(a["severity"] == level for a in alerts)
                                      for level in sorted({a["severity"] for a in alerts})},
                  "alerts": alerts}
        output = json.dumps(report, indent=2, sort_keys=True)
    else:
        output = _text_report(events, alerts)
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
