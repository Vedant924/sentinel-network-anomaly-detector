
# SENTINEL
## Real-Time Network Anomaly Detection and AI-Assisted Incident Analysis

SENTINEL is a defensive cybersecurity project designed to analyze authorized network traffic, detect unusual patterns using explainable rules, and use AI to help summarize incident evidence.

### Planned technologies
- **Python (initial MVP):** Event ingestion, explainable anomaly detection, tests, AI integration, and a simple interface
- **JSON Lines (JSONL):** Language-independent contract between event input and analytics
- **C++ (optional later component):** Packet parsing/high-throughput event generation only if the MVP demonstrates a need
- **NVIDIA AI via Nebius:** AI-assisted incident analysis
- **Dashboard/CLI:** Traffic statistics, alerts, and incident summaries

### Project status
Currently in the initial setup and planning stage. Features will be documented as they are implemented and tested.

### Safety
We will test using synthetic data, approved packet captures, or networks we are authorized to monitor. API keys, private captures, and sensitive logs must never be committed.

### Team
Three contributors. See [the language-agnostic project blueprint](docs/PROJECT_BLUEPRINT.md) for proposed workstreams.

