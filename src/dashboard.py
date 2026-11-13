"""Refreshable Rich terminal dashboard for SENTINEL JSON reports.

The dashboard consumes the public JSON report emitted by src.run_detector.
It deliberately does not import detector implementation details.
"""
import argparse
import json
import sys
import time
from pathlib import Path


KNOWN_SEVERITIES = ("LOW", "MEDIUM", "HIGH")
REQUIRED_REPORT_KEYS = {
    "tool", "events_analyzed", "unique_sources", "alert_count",
    "severity_counts", "alerts",
}


def normalize_report(report):
    """Validate and normalize the public runner JSON report."""
    if not isinstance(report, dict):
        raise ValueError("The report must be a JSON object.")

    missing = sorted(REQUIRED_REPORT_KEYS - report.keys())
    if missing:
        raise ValueError(
            "This does not look like a SENTINEL report; missing keys: "
            + ", ".join(missing)
        )
    if report.get("tool") != "SENTINEL":
        raise ValueError("The report's 'tool' field must be 'SENTINEL'.")

    alerts = report["alerts"]
    incidents = report.get("correlated_incidents", [])
    severity_counts = report["severity_counts"]
    if not isinstance(alerts, list) or not all(isinstance(item, dict) for item in alerts):
        raise ValueError("'alerts' must be a list of JSON objects.")
    if not isinstance(incidents, list) or not all(isinstance(item, dict) for item in incidents):
        raise ValueError("'correlated_incidents' must be a list of JSON objects.")
    if not isinstance(severity_counts, dict):
        raise ValueError("'severity_counts' must be a JSON object.")

    return {
        "tool": report["tool"],
        "events_analyzed": report["events_analyzed"],
        "unique_sources": report["unique_sources"],
        "alert_count": report["alert_count"],
        "correlated_incident_count": report.get(
            "correlated_incident_count", len(incidents)
        ),
        "severity_counts": severity_counts,
        "alerts": alerts,
        "correlated_incidents": incidents,
    }


def load_report(source):
    """Load a report from a path, or from stdin when source is '-'."""
    raw = sys.stdin.read() if source == "-" else Path(source).read_text(encoding="utf-8")
    try:
        return normalize_report(json.loads(raw))
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON report at {source}: {exc.msg}") from exc


def _plain(value):
    """Render arbitrary JSON values without assuming a fixed evidence schema."""
    if isinstance(value, (dict, list)):
        return json.dumps(value, sort_keys=True, ensure_ascii=False)
    if value is None:
        return "—"
    return str(value)


def _timestamp(value):
    """Keep timestamps numeric/raw; their epoch or relative-time origin is unknown."""
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return f"{value:g}s"
    return _plain(value)


def build_dashboard(report):
    """Build a Rich renderable for one report snapshot."""
    try:
        from rich.console import Group
        from rich.panel import Panel
        from rich.table import Table
        from rich.text import Text
    except ImportError as exc:
        raise RuntimeError(
            "The dashboard requires Rich. Install the project with: python -m pip install -e ."
        ) from exc

    severity_styles = {
        "LOW": "green",
        "MEDIUM": "yellow",
        "HIGH": "bold red",
    }

    summary = Table.grid(padding=(0, 2))
    summary.add_column(style="bold")
    summary.add_column(justify="right")
    summary.add_row("Events analyzed", _plain(report["events_analyzed"]))
    summary.add_row("Unique sources", _plain(report["unique_sources"]))
    summary.add_row("Alerts", _plain(report["alert_count"]))
    summary.add_row("Correlated incidents", _plain(report["correlated_incident_count"]))

    counts = report["severity_counts"]
    severity_items = []
    ordered_levels = [level for level in KNOWN_SEVERITIES if level in counts]
    ordered_levels.extend(sorted(str(level) for level in counts if level not in KNOWN_SEVERITIES))
    for level in ordered_levels:
        severity_items.append(
            Text(f"{level}: {_plain(counts[level])}", style=severity_styles.get(level, "white"))
        )
    if not severity_items:
        severity_items = [Text("No alerts", style="dim")]
    severity_content = []
    for index, item in enumerate(severity_items):
        if index:
            severity_content.append(Text("   "))
        severity_content.append(item)

    alerts_table = Table(title="Alert feed", show_lines=True)
    alerts_table.add_column("Severity")
    alerts_table.add_column("Rule", overflow="fold", no_wrap=False)
    alerts_table.add_column("Source", overflow="fold", no_wrap=False)
    alerts_table.add_column("Observed / threshold")
    alerts_table.add_column("Window (seconds)")
    if report["alerts"]:
        for alert in report["alerts"]:
            severity = str(alert.get("severity", "UNKNOWN"))
            evidence = alert.get("evidence", {})
            port_count = (
                evidence.get("unique_destination_ports", "—")
                if isinstance(evidence, dict) else "—"
            )
            observed = alert.get("observed", alert.get("observed_count", port_count))
            threshold = alert.get("threshold", "—")
            start = _timestamp(alert.get("window_start", "—"))
            end = _timestamp(alert.get("window_end", "—"))
            alerts_table.add_row(
                Text(severity, style=severity_styles.get(severity, "white")),
                Text(str(alert.get("rule_id", "UNKNOWN"))),
                Text(str(alert.get("source", "—"))),
                Text(f"{_plain(observed)} / {_plain(threshold)}"),
                Text(f"{start} → {end}"),
            )
    else:
        alerts_table.add_row("—", "No alerts", "—", "—", "—")

    incidents_table = Table(title="Correlated incidents", show_lines=True)
    incidents_table.add_column("Incident", overflow="fold", no_wrap=False)
    incidents_table.add_column("Source", overflow="fold", no_wrap=False)
    incidents_table.add_column("Alerts", justify="right")
    incidents_table.add_column("Rules", overflow="fold", no_wrap=False)
    if report["correlated_incidents"]:
        for incident in report["correlated_incidents"]:
            rules = incident.get("correlated_rules", [])
            incidents_table.add_row(
                Text(str(incident.get("incident_id", "—"))),
                Text(str(incident.get("source", "—"))),
                Text(_plain(incident.get("alert_count", "—"))),
                Text(", ".join(str(rule) for rule in rules) if isinstance(rules, list) else _plain(rules)),
            )
    else:
        incidents_table.add_row("—", "No correlated incidents", "0", "—")

    sections = [
        Panel(summary, title=Text(str(report["tool"])), border_style="cyan"),
        Panel(Text.assemble(*severity_content), title=Text("Severity distribution"), border_style="cyan"),
        alerts_table,
        incidents_table,
    ]

    for index, alert in enumerate(report["alerts"], 1):
        evidence = alert.get("evidence", {})
        if isinstance(evidence, dict):
            evidence_lines = [
                f"{key}: {_plain(value)}" for key, value in sorted(evidence.items())
            ]
        else:
            evidence_lines = [_plain(evidence)]
        details = [
            f"Source: {_plain(alert.get('source', '—'))}",
            f"Time: {_timestamp(alert.get('timestamp', '—'))}",
            f"Reason: {_plain(alert.get('reason', '—'))}",
            "Evidence:",
            *(f"  {line}" for line in evidence_lines),
            f"Recommended action: {_plain(alert.get('recommended_action', '—'))}",
            f"Uncertainty: {_plain(alert.get('uncertainty', '—'))}",
        ]
        severity = str(alert.get("severity", "UNKNOWN"))
        title = f"Alert {index} · {alert.get('rule_id', 'UNKNOWN')} · {severity}"
        sections.append(
            Panel(
                Text("\n".join(details)),
                title=Text(title),
                border_style=severity_styles.get(severity, "white"),
            )
        )
    return Group(*sections)


def render_dashboard(report):
    """Render a single report snapshot."""
    from rich.console import Console
    Console().print(build_dashboard(report))


def follow_report(source, refresh_interval):
    """Refresh the dashboard while a report file is updated by another process."""
    from rich.live import Live
    from rich.panel import Panel
    from rich.text import Text

    initial = load_report(source)
    with Live(build_dashboard(initial), refresh_per_second=4, screen=True) as live:
        while True:
            time.sleep(refresh_interval)
            try:
                report = load_report(source)
                live.update(build_dashboard(report), refresh=True)
            except (OSError, ValueError) as exc:
                live.update(
                    Panel(
                        Text(f"Waiting for a valid SENTINEL report: {exc}"),
                        title=Text("SENTINEL dashboard"),
                        border_style="yellow",
                    ),
                    refresh=True,
                )


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Display or follow a SENTINEL JSON report in a Rich terminal dashboard."
    )
    parser.add_argument(
        "--input", default="-",
        help="JSON report path, or '-' to read JSON from stdin (default: stdin)",
    )
    parser.add_argument(
        "--follow", action="store_true",
        help="Refresh the dashboard as the report file changes (requires --input PATH)",
    )
    parser.add_argument(
        "--refresh-interval", type=float, default=1.0,
        help="Seconds between report refreshes when --follow is enabled (default: 1)",
    )
    args = parser.parse_args(argv)

    if args.refresh_interval <= 0:
        parser.error("--refresh-interval must be greater than zero")
    if args.follow and args.input == "-":
        parser.error("--follow requires --input PATH; stdin can only be read once")

    try:
        if args.follow:
            follow_report(args.input, args.refresh_interval)
        else:
            render_dashboard(load_report(args.input))
    except KeyboardInterrupt:
        return 0
    except (OSError, ValueError, RuntimeError) as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
