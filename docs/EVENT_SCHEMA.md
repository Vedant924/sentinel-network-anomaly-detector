# SENTINEL Event Schema — Phase 1 and Phase 2

SENTINEL reads JSON Lines (JSONL): one event object per non-empty line. Timestamps are finite numeric seconds. The core connection fields remain required for compatibility with Phase 1.

## Required fields

| Field | Type | Meaning |
|---|---|---|
| `timestamp` | number | Event time in seconds |
| `src_ip` | string | Valid IPv4 or IPv6 source |
| `dst_port` | integer | Destination port, 1–65535 |

## Optional Phase 2 fields

| Field | Type | Used by |
|---|---|---|
| `dst_ip` | IP string | Distinct destination host rule |
| `connection_status` or `status` | string | Failed connection rule |
| `bytes_transferred` or `bytes` | non-negative integer | Traffic-volume rule |
| `dns_query` or `query_name` | non-empty string | DNS burst and suspicious-name rules |
| `protocol` | string | Descriptive metadata only; not currently used for detection |

For failed connections, the detector recognizes `failed`, `failure`, `timeout`, `timed_out`, `refused`, `reset`, `rejected`, and `error`. Other values, including `success`, are not counted as failures.

Traffic volume currently uses the explicit per-event byte count. It does not infer bytes from packet length or multiply by packet count. DNS analysis uses query-name length, label length, character entropy, and query frequency; it does not inspect DNS payloads or response codes.

## Detection rules

| Rule ID | What it detects | Default threshold/window |
|---|---|---|
| `MANY_DESTINATION_PORTS` | Many distinct destination ports from one source | >10 ports / 10s |
| `HIGH_EVENT_RATE` | High event count from one source | >20 events / 10s |
| `REPEATED_FAILED_CONNECTIONS` | Repeated failed connection attempts | >10 failures / 60s |
| `HIGH_TRAFFIC_VOLUME` | High sum of transferred bytes | >1,000,000 bytes / 10s |
| `DNS_QUERY_BURST` | High DNS query count | >50 queries / 60s |
| `SUSPICIOUS_DNS_QUERY` | Long or unusually structured query name | 80 characters or heuristic label/entropy condition |
| `MANY_DESTINATION_HOSTS` | Many distinct destination IPs | >20 hosts / 30s |

Thresholds are exceeded, not merely met. Each rule produces a structured evidence-rich alert. Rule thresholds are configurable in the Python functions and CLI where exposed.

## Correlation and deduplication

`deduplicate_alerts` removes exact repeated alert IDs. Detection rules suppress repeated alerts while a continuous threshold breach remains active, and can alert again after the condition clears.

`correlate_alerts` groups two or more alerts from the same source when adjacent alert timestamps are within the configured correlation gap. Correlation is a grouping aid, not proof that alerts share one root cause. The CLI enables it with `--correlate`.

## Important limitations

- The rules are deterministic heuristics, not machine-learning classifications or proof of an attack.
- Severity is currently a fixed prototype value and is not calibrated to risk.
- The DNS rule does not perform threat-intelligence lookups or confirm DNS tunnelling.
- Traffic volume is based on supplied event byte counts; accuracy depends on the upstream event source.
- The current event contract still requires `dst_port` even for DNS/connection events.
- Sample datasets use synthetic events and documentation-only IP ranges. No live traffic is included.

See [data/datasets/README.md](../data/datasets/README.md) for the synthetic scenarios and expected detections.
