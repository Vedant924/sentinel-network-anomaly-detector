# SENTINEL Event Schema — Current Detector Input

This document distinguishes the **current detector input** from a proposed future packet-event format. The current detector consumes JSONL records with a numeric Unix timestamp in seconds.

## Current supported input

Format: JSON Lines (JSONL), one JSON object per line.

```json
{"timestamp": 1000.0, "src_ip": "192.0.2.10", "dst_ip": "198.51.100.20", "dst_port": 443}
```

### Fields used by the current detector

| Field | Required | Current expectation |
|---|---|---|
| `timestamp` | Yes | Numeric Unix time in seconds; values for one source are ordered and compared within a sliding time window |
| `src_ip` | Yes | Non-empty source address or source identifier string |
| `dst_port` | Yes | Integer destination port from 1 through 65535 |
| `dst_ip` | No for this rule | Destination address string when available |

The current rule groups events by `src_ip` and counts distinct `dst_port` values in a configurable time window. It emits a `MANY_DESTINATION_PORTS` alert when the count is **greater than** the configured threshold.

The detector does not currently validate or use `protocol`, `src_port`, `packet_length`, or `tcp_flags` for this rule. Extra fields may be included, but they do not affect the current detection result.

## Example synthetic test event set

Each line is a separate JSON object:

```jsonl
{"timestamp": 1000.0, "src_ip": "192.0.2.10", "dst_ip": "198.51.100.20", "dst_port": 80}
{"timestamp": 1001.0, "src_ip": "192.0.2.10", "dst_ip": "198.51.100.20", "dst_port": 443}
```

These are example values, not evidence of live network traffic. Use enough events from the same source with distinct destination ports inside the configured window to exercise the alert rule.

## Proposed future packet-event format (not yet the current detector contract)

A future packet-capture adapter could normalize packet metadata into a richer event format such as:

```json
{
  "schema_version": 1,
  "event_type": "packet",
  "timestamp": "2026-10-14T12:00:00.000Z",
  "protocol": "TCP",
  "src_ip": "192.0.2.10",
  "dst_ip": "198.51.100.20",
  "src_port": 51514,
  "dst_port": 443,
  "packet_length": 60,
  "tcp_flags": ["SYN"]
}
```

The IP addresses above are reserved documentation ranges. **This richer format is a design proposal only:** its ISO 8601 timestamp is not accepted by the current detector, which expects numeric seconds. Do not feed this proposed format directly into the current detector without an adapter or a deliberate schema change with tests.

## Validation and safety requirements

- Reject malformed JSON and non-object JSONL lines with a clear line number.
- Validate required fields and numeric ranges before detection.
- Bound uploaded input size and line length when adding a web/API upload feature.
- Do not invent missing values or treat malformed events as confirmed benign traffic.
- Do not include packet payload bytes in event records.
- Treat alerts as indicators for investigation, not proof of an intrusion.

## Current alert output

The current detector returns fields including `rule`, `source`, `unique_destination_ports`, `threshold`, `window_seconds`, `severity`, `reason`, and `timestamp`. Fields such as `alert_id`, `rule_id`, `observed`, and a structured uncertainty note may be added in a future reviewed change.
