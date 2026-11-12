# SENTINEL structured alert contract

Every network alert preserves legacy fields and adds a stable fingerprint ID, machine-readable rule ID, category, first/last seen timestamps, detection window bounds, observed value, configured threshold, structured evidence, severity rationale, human-review recommendation, uncertainty note, and a suspicious-pattern classification.

The current port rule evidence is the number and a bounded sample of distinct destination ports in the active window. The event-rate rule evidence is the event count and derived events-per-second value. Optional fields such as protocol are not presented as evidence because the current rules do not inspect them.

Both current rules use HIGH severity as a fixed prototype policy. It is not calibrated and does not indicate a confirmed incident or probability. The alert ID is a deterministic fingerprint, not a permanent database key.

## Dataset fixtures

- `normal_traffic.jsonl`: ordinary repeated connections; expected no alerts.
- `port_scan.jsonl`: synthetic source contacts many destination ports; expected port alert.
- `high_event_rate.jsonl`: synthetic event burst to one port; expected rate alert.
- `mixed_scenarios.jsonl`: combines ordinary and suspicious patterns; expected both rules.

All fixtures use RFC 5737 documentation IP ranges and are synthetic. No live network traffic is included.
