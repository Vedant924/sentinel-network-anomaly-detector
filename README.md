# SENTINEL
## Network Anomaly Detection and AI-Assisted Incident Analysis

SENTINEL is a defensive cybersecurity project that analyzes authorized network events and detects unusual patterns using explainable rules. AI-assisted incident summaries are a possible future extension, not part of the current MVP.

## Current MVP

- Reads synthetic network events from a JSON Lines (JSONL) file.
- Detects a source contacting too many distinct destination ports within a configurable time window.
- Prints a readable alert with the rule, source, port count, threshold window, and reason.
- Includes automated tests for the detector, input loader, and command-line runner.

**Limitations:** This version does not capture live network traffic, does not use AI, and does not include a graphical dashboard. An alert is a signal for investigation, not proof that an intrusion occurred.

## Project structure

- `src/detector.py` — explainable detection rule
- `src/run_detector.py` — JSONL loader and command-line entry point
- `tests/test_detector.py` — detection-rule tests
- `tests/test_runner.py` — event-loader and command-line tests
- `data/sample_events.jsonl` — synthetic example events
- `TEAM_CONTRIBUTION_PLAN.md` — task split and contribution record template

## Run SENTINEL

Run these commands from the repository root with Python 3 installed:

```bash
python -m src.run_detector
```

Use a different input file or detection settings:

```bash
python -m src.run_detector --input data/sample_events.jsonl --window 10 --threshold 10
```

The default input is `data/sample_events.jsonl`. Each non-empty line must contain one JSON object.

## Run the tests

From the repository root:

```bash
python -m unittest discover -v
```

A valid test run should report individual tests and a final test count. If it says `Ran 0 tests`, tests were not discovered and that is not a passing result.

## Event format

Each event is one JSON object per line:

```json
{"timestamp": 1000, "src_ip": "192.168.1.10", "dst_ip": "192.168.1.1", "dst_port": 443}
```

- `timestamp`: numeric time in seconds
- `src_ip`: source IP address
- `dst_port`: destination port number

## Next steps

1. Run the MVP and verify the tests on a clean checkout.
2. Add more detection rules only with clear tests and explanations.
3. Consider approved PCAP input, performance measurements, AI-assisted explanations, and a simple interface in later phases.

## Safety

Use synthetic data, approved packet captures, or networks you are authorized to monitor. Never commit API keys, private captures, or sensitive logs.

## Team

Use [TEAM_CONTRIBUTION_PLAN.md](TEAM_CONTRIBUTION_PLAN.md) to assign tasks and record contributions accurately. Do not claim a contribution until the work has been completed.
