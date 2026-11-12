# Curated SENTINEL datasets

All fixtures are synthetic, not live captures. IPs use RFC 5737 documentation ranges.

| File | Scenario | Expected behavior at default thresholds |
|---|---|---|
| `normal_traffic.jsonl` | Ordinary repeated connections across hosts | No alerts |
| `port_scan.jsonl` | One source contacts many destination ports | `MANY_DESTINATION_PORTS` |
| `high_event_rate.jsonl` | One source generates many events to one port | `HIGH_EVENT_RATE` |
| `mixed_scenarios.jsonl` | Normal activity plus both suspicious patterns | Both rules |

Run:
```bash
python -m src.run_detector --input data/datasets/normal_traffic.jsonl --rule all
python -m src.run_detector --input data/datasets/port_scan.jsonl --rule all
python -m src.run_detector --input data/datasets/high_event_rate.jsonl --rule all
python -m src.run_detector --input data/datasets/mixed_scenarios.jsonl --rule all --format json
```

The fixtures contain only supported event fields plus descriptive protocol labels. The current rules do not inspect protocol, destination IP, or payloads. Dataset labels describe test intent, not guaranteed real-world classification.
