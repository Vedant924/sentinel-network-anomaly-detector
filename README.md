# SENTINEL
## Network Anomaly Detection and AI-Assisted Incident Analysis

SENTINEL is a defensive cybersecurity project designed to analyze authorized network events, detect unusual patterns using explainable rules, and eventually use AI to summarize incident evidence.

## Current status

The first Python MVP is in progress. It currently includes one explainable detection rule:

- **MANY_DESTINATION_PORTS:** flags a source IP when it contacts more than the configured number of distinct destination ports within a time window.

The starter event data is synthetic. This version does not capture live traffic and does not include AI or a dashboard yet.

## Project structure

- `src/detector.py` — detection rule
- `tests/test_detector.py` — automated tests
- `data/sample_events.jsonl` — synthetic example events
- `docs/` — project planning and design notes

## Run the tests

Use Python 3 from the repository's root directory:

```bash
python -m unittest discover -v
```

## Event format

Each event is one JSON object per line. The detector currently uses these fields:

```json
{"timestamp": 1000, "src_ip": "192.168.1.10", "dst_ip": "192.168.1.1", "dst_port": 443}
```

- `timestamp`: numeric time in seconds
- `src_ip`: source IP address
- `dst_port`: destination port number

## Planned next steps

1. Read JSONL events from the sample data file.
2. Connect event reading to the detector and print clear alerts.
3. Add and test another detection rule only after this one works reliably.
4. Consider approved PCAP input, performance measurement, AI-assisted explanations, and a simple interface in later phases.

## Safety

Test with synthetic data, approved packet captures, or networks you are authorized to monitor. Never commit API keys, private captures, or sensitive logs.

## Team

Three contributors. See [the language-agnostic project blueprint](docs/PROJECT_BLUEPRINT.md) for proposed workstreams.
