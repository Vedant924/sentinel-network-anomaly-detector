# Curated SENTINEL datasets

All fixtures are synthetic, not live captures. IPs use RFC 5737 documentation ranges.

## Phase 1 fixtures

| File | Scenario | Expected behavior |
|---|---|---|
| `normal_traffic.jsonl` | Ordinary repeated connections | No alerts |
| `port_scan.jsonl` | One source contacts many destination ports | `MANY_DESTINATION_PORTS` |
| `high_event_rate.jsonl` | One source generates many events to one port | `HIGH_EVENT_RATE` |
| `mixed_scenarios.jsonl` | Normal traffic plus Phase 1 anomalies | Both Phase 1 rules |

## Phase 2 fixtures

| File | Scenario | Expected behavior |
|---|---|---|
| `failed_connections.jsonl` | Repeated refused/time-out attempts | `REPEATED_FAILED_CONNECTIONS` |
| `high_traffic_volume.jsonl` | Large byte transfer in a short window | `HIGH_TRAFFIC_VOLUME` |
| `dns_anomalies.jsonl` | DNS query burst and long query name | `DNS_QUERY_BURST`, `SUSPICIOUS_DNS_QUERY` |
| `many_destination_hosts.jsonl` | One source contacts many distinct IPs | `MANY_DESTINATION_HOSTS` |
| `phase2_mixed_scenarios.jsonl` | Combined Phase 2 scenarios | All five Phase 2 rule IDs |

## Run the scenarios

```bash
python -m src.run_detector --input data/datasets/normal_traffic.jsonl --rule all
python -m src.run_detector --input data/datasets/failed_connections.jsonl --rule failed
python -m src.run_detector --input data/datasets/high_traffic_volume.jsonl --rule volume
python -m src.run_detector --input data/datasets/dns_anomalies.jsonl --rule dns
python -m src.run_detector --input data/datasets/many_destination_hosts.jsonl --rule hosts
python -m src.run_detector --input data/datasets/phase2_mixed_scenarios.jsonl --rule all --correlate --format json
```

The Phase 2 fixtures include only fields supported by the current event contract. Descriptive protocol labels are not used as detection evidence. Dataset labels describe test intent, not guaranteed real-world classification.

Regression tests assert the expected rule outcomes. Alerts remain heuristic investigation signals, not proof of malicious activity.
