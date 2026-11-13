"""Rich terminal dashboard for SENTINEL JSON reports.

The dashboard consumes the public JSON report emitted by src.run_detector.
It deliberately does not import detector implementation details.
"""
import argparse
import json
import sys
from pathlib import Path


KNOWN_SEVERITIES = ("LOW", "MEDIUM", "HIGH")


def normalize_report(report):
    """Return a safe, predictable view of a runner JSON report."""
    if not isinstance(report, dict):
        raise ValueError("The report must be a JSON object.")

    alerts = report.get("alerts", [])
    incidents = report.get("correlated_incidents", [])
    severity_counts = report.get("severity_counts", {})

    if not isinstance(alerts, list) or not all(isinstance(item, dict) for item in alerts):
        raise ValueError("'alerts' must be a list of JSON objects.")
    if not isinstance(incidents, list) or not all(isinstance(item, dict) for item in incidents):
        raise ValueError("'correlated_incidents' must be a list of JSON objects.")
    if not isinstance(severity_counts, dict):
        raise ValueError("'severity_counts' must be a JSON object.")

    return {
        "tool": report.get("tool", "SENTINEL"),
        "events_analyzed": report.get("events_analyzed", 0),
        "unique_sources": report.get("unique_sources", 0),
        "alert_count": report.get("alert_count", len(alerts)),
        "correlated_incident_count": report.get(
            "correlated_incident_count", len(incidents)
        ),
        "severity_counts": severity_counts,
        "alerts": alerts,
        "correlated_incidents": incidents,
    }


def load_report(source):
    """Load a report from a path, or from stdin when source is '-'."""
    if source == "-":
        raw = sys.stdin.read()
    else:
        raw = Path(source).read_text(encoding="utf-8")
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


def render_dashboard(report):
    """Render the normalized report using Rich (a runtime dependency)."""
    try:
        from rich.console import Console
        from rich.panel import Panel
        from rich.table import Table
        from rich.text import Text
    except ImportError as exc:
        raise RuntimeError(
            "The dashboard requires Rich. Install the project with: python -m pip install -e ."
        ) from exc

    console = Console()
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
    severity_line = []
    ordered_levels = [level for level in KNOWN_SEVERITIES if level in counts]
    ordered_levels.extend(sorted(str(level) for level in counts if level not in KNOWN_SEVERITIES))
    for level in ordered_levels:
        style = severity_styles.get(level, "white")
        severity_line.append(Text(f"{level}: {_plain(counts[level])}", style=style))
    if not severity_line:
        severity_line = [Text("No alerts", style="dim")]

    console.print(Panel(summary, title=Text(str(report["tool"])), border_style="cyan"))
    console.print(Panel(Text.assemble(*sum(([item, Text("   ")] for item in severity_line), [])[:-1]),
                        title=Text("Severity distribution"), border_style="cyan"))

    alerts = Table(title="Alert feed", show_lines=True)
    for heading in ("Severity", "Rule", "Source", "Observed / threshold", "Window (seconds)"):
        alerts.add_column(heading)
    if report["alerts"]:
        for alert in report["alerts"]:
            severity = str(alert.get("severity", "UNKNOWN"))
            observed = alert.get("observed", alert.get("observed_count", "—"))
            threshold = alert.get("threshold", "—")
            start = _timestamp(alert.get("window_start", "—"))
            end = _timestamp(alert.get("window_end", "—"))
            alerts.add_row(
                Text(severity, style=severity_styles.get(severity, "white")),
                Text(str(alert.get("rule_id", "UNKNOWN"))),
                Text(str(alert.get("source", "—"))),
                Text(f"{_plain(observed)} / {_plain(threshold)}"),
                Text(f"{start} → {end}"),
            )
    else:
        alerts.add_row("—", "No alerts", "—", "—", "—")
    console.print(alerts)

    incidents = Table(title="Correlated incidents", show_lines=True)
    incidents.add_column("Incident")
    incidents.add_column("Source")
    incidents.add_column("Alerts", justify="right")
    incidents.add_column("Rules")
    if report["correlated_incidents"]:
        for incident in report["correlated_incidents"]:
            rules = incident.get("correlated_rules", [])
            incidents.add_row(
                Text(str(incident.get("incident_id", "—"))),
                Text(str(incident.get("source", "—"))),
                Text(_plain(incident.get("alert_count", "—"))),
                Text(", ".join(str(rule) for rule in rules) if isinstance(rules, list) else _plain(rules)),
            )
    else:
        incidents.add_row("—", "No correlated incidents", "0", "—")
    console.print(incidents)

    for index, alert in enumerate(report["alerts"], 1):
        evidence = alert.get("evidence", {})
        evidence_lines = []
        if isinstance(evidence, dict):
            evidence_lines = [f"{key}: {_plain(value)}" for key, value in sorted(evidence.items())]
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
        console.print(Panel(Text("\n".join(details)), title=Text(title),
                            border_style=severity_styles.get(severity, "white")))


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Display a SENTINEL JSON report in a Rich terminal dashboard."
    )
    parser.add_argument(
        "--input", default="-",
        help="JSON report path, or '-' to read JSON from stdin (default: stdin)",
    )
    args = parser.parse_args(argv)
    try:
        report = load_report(args.input)
        render_dashboard(report)
    except (OSError, ValueError, RuntimeError) as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
