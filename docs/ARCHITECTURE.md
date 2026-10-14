# SENTINEL Architecture

## Planned data flow

Synthetic events / authorized PCAP replay → C packet parser → versioned JSONL events → Python ingestion and rolling windows → explainable detection rules → alerts and dashboard → optional Nebius-hosted NVIDIA model for an AI-assisted incident summary.

## Components

### C event producer
- Begin with synthetic input or approved PCAP replay.
- Parse packet metadata and emit one JSON object per line.
- Handle malformed and truncated input safely.
- Avoid collecting payload contents unless there is a documented, authorized need.

### Python detector
- Validate incoming events.
- Maintain bounded rolling windows and counters.
- Generate alerts with a rule ID, time window, observed evidence, threshold, and severity rationale.
- Treat suspicious patterns as indicators, not proof of malicious activity.

### AI incident analyst
- Summarize structured alert evidence in plain language.
- Validate model output and label it as AI-generated.
- Never execute commands or automatically change network settings.
- Keep deterministic detection working when the AI service is unavailable.

### Dashboard
Show traffic statistics, alert timeline, evidence behind each rule, and incident summaries. Build a simple working view before adding visual polish.

## Build order
1. Agree on the event schema and create synthetic fixtures.
2. Implement the Python detector and tests.
3. Implement the C event producer/replay.
4. Connect both components with integration tests.
5. Add the dashboard.
6. Integrate Nebius/NVIDIA after verifying current service and hackathon requirements.

## Decisions to confirm
- Development OS and packet-capture library.
- PCAP replay approach.
- Dashboard framework.
- Model/API configuration.
- Detection thresholds, evaluated with test fixtures rather than guessed performance claims.
