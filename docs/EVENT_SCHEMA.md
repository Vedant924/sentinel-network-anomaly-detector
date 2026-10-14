# SENTINEL Event Schema — Draft v1

The event producer and detector must agree on this language-independent contract before implementation. Format: JSON Lines (JSONL), one JSON object per line. This is a draft and can change through a reviewed pull request.

## Example packet event

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

The IPs in this example are reserved documentation addresses, not real captured traffic.

## Required fields
- `schema_version`: integer, initially `1`.
- `event_type`: initially `packet`.
- `timestamp`: UTC ISO 8601 timestamp.
- `protocol`: normalized label such as `TCP`, `UDP`, `ICMP`, or `OTHER`.
- `packet_length`: non-negative integer.

## Address and transport fields
- `src_ip`, `dst_ip`: parsed address strings when available.
- `src_port`, `dst_port`: integers from 0 to 65535 when a transport header is available; otherwise omit or set to `null`.
- `tcp_flags`: normalized TCP flag labels when available.

## Validation
- Reject or safely skip malformed JSON and unsupported schema versions.
- Validate IP addresses and numeric ranges.
- Do not invent values for truncated or unsupported packets.
- Bound input line length and memory use.
- Do not include payload bytes in events.

## Alert fields
The detector alert model should include `alert_id`, `timestamp`, `rule_id`, `severity`, `summary`, `window_seconds`, `threshold`, `observed`, and an uncertainty/limitations note. Finalize the exact alert schema alongside the first tested detector rule.
