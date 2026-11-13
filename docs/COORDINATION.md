# SENTINEL Coordination

This document records current ownership boundaries, shared contracts, and handoff rules for the SENTINEL project. Update it through a pull request so all contributors can review changes.

## Working rules

- Keep changes within the agreed file ownership below. Ask the owner before changing another contributor's files.
- Shared contracts are changed only through a reviewed pull request.
- Do not report a test as passing unless it was actually executed; identify the environment and command.
- Distinguish **RAN** (executed and observed), **READ** (source inspected without execution), and **ASSUMED** (not yet verified).
- Do not describe heuristic alerts as confirmed attacks or incidents.
- Do not merge stacked pull requests out of order.

## File ownership

| Owner | Files / areas | Scope |
|---|---|---|
| Claude | `src/detector.py`, `src/run_detector.py`, their tests, `c/`, evaluation script | Detection rules, event validation, CLI, C sniffer, and evaluation |
| ChatGPT | PCAP replay module, Rich terminal dashboard, dashboard/triage/Nebius UI wiring, CI workflow, README, dependency declarations | Input adapters, terminal presentation, integration wiring, project documentation and CI |
| Shared (PR review required) | `docs/COORDINATION.md`, `docs/EVENT_SCHEMA.md`, `docs/ALERT_SCHEMA.md` | Team agreements and public data contracts |

Ownership does not grant permission to silently change another owner's implementation. Coordinate cross-boundary changes first.

## Event contract

The current event schema is defined in [EVENT_SCHEMA.md](EVENT_SCHEMA.md). Each JSONL line is one event object.

Required fields:
- `timestamp`: finite numeric seconds
- `src_ip`: valid IPv4 or IPv6 address
- `dst_port`: integer from 1 through 65535

Optional fields:
- `dst_ip`
- `bytes_transferred` or `bytes`
- `connection_status` or `status`
- `dns_query` or `query_name`
- `protocol` (descriptive metadata only; not currently used for detection)

Do not add required fields without a reviewed change to the shared event schema and coordinated detector/replay updates.

### PCAP replay decisions

The planned offline PCAP adapter will emit **flow-level events**, not one event per packet. Packet-level events would make `HIGH_EVENT_RATE` count packets and could trigger on ordinary high-throughput downloads. The adapter must document its flow key, directionality, idle timeout, aggregation behavior, and timestamp choice. Events must be emitted in timestamp order.

- Emit `dst_port` only when a supported transport packet has a real destination port.
- Skip ICMP and other packets without a destination port under the current required-field contract. Do not invent a port. Revisit only through a shared schema PR if ICMP support is needed.
- Emit `protocol` as metadata.
- Do not infer `connection_status` from a SYN or any isolated packet. Only populate it if a defensible connection outcome can be established.
- Do not emit `tcp_flags` until that optional field is added to the shared event schema.
- Do not equate packet count with connection count or packet length with application payload bytes. If packet/flow byte accounting is exported, document exactly what is measured.

## Alert and incident contracts

The current alert contract is documented in [ALERT_SCHEMA.md](ALERT_SCHEMA.md). The runner's JSON report currently exposes these top-level keys:

- `tool`
- `events_analyzed`
- `unique_sources`
- `alert_count`
- `correlated_incident_count`
- `severity_counts`
- `alerts`
- `correlated_incidents`

Dashboard integration rules:
- Consume the runner's JSON output; do not import detector internals.
- Render `evidence` as generic key-value data because its keys vary by rule.
- Use `rule_id` as the rule identifier; `rule` is currently a duplicate display field.
- Treat `observed_count` as a compatibility/duplicate field where present; the port rule uses `unique_destination_ports` in evidence.
- Timestamps are numeric seconds. Do not assume they are ISO-8601 or convert them to calendar dates without an explicit time-origin contract.
- `severity_counts` contains only levels that occurred and is an empty object when there are no alerts.
- Support `LOW`, `MEDIUM`, and `HIGH`, as well as unknown future severity strings.
- Treat alerts and correlated incidents as investigation signals, not proof of malicious activity.

The JSON interface and severity policy are expected to evolve. Keep the dashboard tolerant of missing optional fields and unknown values.

## Current implementation queue

Claude's planned detector work (subject to its own review and PRs):
1. `--skip-invalid` mode
2. Severity calibration
3. CLI threshold fix
4. DNS alert aggregation
5. Validate-once performance improvement
6. SYN detection rule (after the shared event schema is updated for optional `tcp_flags`)
7. Evaluation script

ChatGPT's integration work:
1. Offline PCAP replay using the decisions above
2. Rich terminal dashboard consuming the runner's JSON report
3. Triage/Nebius integration in the UI
4. CI and README/dependency maintenance

## Stacked pull requests

The current detector/security stack is intended to be integrated bottom-up:

1. PR #6 — guardrails hardening
2. PR #7 — structured alerts and datasets (currently based on #6)
3. PR #8 — Phase 2 detection engine (currently based on #7)

After each retarget or merge, re-check the relevant GitHub Actions run for the new PR head/base state. Do not assume an earlier green run proves a later commit or retarget is green. Merge only in dependency order, and report each result.

## Change and handoff checklist

Before a cross-owner change:
- Identify the affected contract and owner.
- Propose the exact schema/API change.
- Add or update regression tests in the owning area.
- Update this document and the relevant schema document through a PR.
- State what was **RAN**, **READ**, and **ASSUMED** in the handoff.
