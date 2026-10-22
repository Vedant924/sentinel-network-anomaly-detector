"""Run SENTINEL's explainable detector against JSONL event data."""

import argparse
import json
from pathlib import Path

from src.detector import detect_many_destination_ports


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
    args = parser.parse_args(argv)

    try:
        events = load_events(args.input)
        alerts = detect_many_destination_ports(
            events,
            window_seconds=args.window,
            threshold=args.threshold,
        )
    except (OSError, ValueError) as exc:
        parser.error(str(exc))

    print(f"SENTINEL analyzed {len(events)} event(s).")
    if not alerts:
        print("No anomalies detected.")
        return 0

    print(f"Detected {len(alerts)} alert(s):")
    for number, alert in enumerate(alerts, start=1):
        print(
            f"[{number}] {alert['severity']} | {alert['rule']} | "
            f"source={alert['source']} | "
            f"distinct_ports={alert['unique_destination_ports']} | "
            f"window={alert['window_seconds']}s"
        )
        print(f"    {alert['reason']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
