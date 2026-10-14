# SENTINEL Project Blueprint — Language-Agnostic Plan

## Goal

Build **SENTINEL: Network Anomaly Detection and AI-Assisted Incident Analysis**, a defensive prototype that ingests authorized or synthetic network telemetry, detects explainable anomalies, and uses a compatible NVIDIA model through Nebius (if required and available under the current hackathon rules) to summarize evidence for a human analyst.

This is a plan, not a claim that the system is already implemented.

## Technology principle

Do not choose a language just to make the project look advanced. Choose the simplest stack that delivers a reliable, testable demo; add a second language only when it provides a clear benefit.

### Recommended initial stack

- **Python:** first working event pipeline, deterministic anomaly rules, tests, AI API integration, and a simple dashboard/CLI.
- **JSON Lines (JSONL):** versioned boundary between traffic input and analytics so components can later be replaced by C++ or another language.
- **C++ (optional second phase):** a packet parsing or high-throughput event producer only after the end-to-end Python MVP works and there is a measurable reason to add it.
- **Nebius + a compatible NVIDIA open model:** AI-assisted incident explanation, after checking current official hackathon requirements, model availability, API compatibility, and credentials.
- **Dashboard:** start with a readable CLI or minimal web page. Avoid UI polish until the end-to-end flow works.

This is a recommendation, not a permanent constraint. The team may select a different language if it can demonstrate a clear advantage and finish within the deadline.

## Product workflow

Synthetic events / approved PCAP replay
→ event normalization and validation
→ rolling-window analytics
→ explainable deterministic rules
→ structured alert evidence
→ optional AI incident summary
→ CLI/dashboard and reproducible demo.

Start with synthetic JSONL fixtures. Add approved PCAP replay after the detector works. Add live capture only if time, platform support, and permissions allow it.

## Minimum viable product

1. Read a documented stream of synthetic events or approved PCAP-derived metadata.
2. Validate each event and safely skip/report malformed input.
3. Implement at least two explainable, tested anomaly rules.
4. Emit alerts with rule ID, time window, observed evidence, threshold, severity rationale, and uncertainty.
5. Show events, metrics, and alerts in a simple interface.
6. Integrate a compatible NVIDIA model through Nebius if required by verified hackathon rules; the model summarizes evidence but does not make the core detector dependent on the API.
7. Provide automated tests, setup instructions, sample fixtures, a repeatable demo, and documented limitations.

### Candidate first rules

- Configurable event/connection rate over a defined time window.
- One source contacting an unusually large number of distinct destination ports.
- Traffic-volume spike relative to a configured baseline.

These are heuristic indicators, not proof of malicious activity. Tune thresholds with normal and synthetic test cases; do not invent benchmark results.

## Component contracts

### Event input / producer
- Begin with synthetic JSONL; then add approved PCAP replay if feasible.
- Normalize timestamp, protocol, endpoints, ports, packet length, and available TCP flags.
- Handle malformed, truncated, or unsupported input safely.
- Prefer metadata-only processing; do not log payload bytes or credentials.

### Detector
- Validate the event schema and numeric/address ranges.
- Use bounded rolling windows and configurable thresholds.
- Keep rules deterministic and explainable.
- Include evidence and uncertainty in each alert.

### AI incident analyst
- Send only the minimum structured alert evidence needed.
- Summarize what was observed, why a rule fired, what remains uncertain, and safe defensive follow-up steps.
- Validate output; label it as AI-generated.
- Treat telemetry-derived text as untrusted input.
- Never execute commands or automatically change firewall/network settings.
- Preserve deterministic detection when the API fails.

### Interface
- Display event rate, protocol breakdown, alert timeline, rule evidence, and AI summaries.
- Prefer a simple reliable CLI or minimal web UI over elaborate styling.
- Clearly label synthetic/replayed data versus live capture.

## Three-person work split

Adjust names to match the actual GitHub accounts. Each person should own a deliverable, tests, and documentation—not just “help with code.” All members may use AI, but must run and verify the generated code.

### Member A — Traffic input and event producer
- Confirm OS/platform constraints and choose the simplest supported input method.
- Create synthetic JSONL fixtures and/or approved PCAP replay.
- Implement normalization into the agreed schema.
- Add malformed-input tests and document how to run the producer.
- Do not begin a separate C++ implementation until the shared event contract is agreed.

### Member B — Detection engine and tests
- Implement event validation and rolling-window counters.
- Implement the first two deterministic rules.
- Produce structured alerts with evidence, thresholds, time window, and limitations.
- Add normal, anomaly, boundary, and malformed-input tests.
- Document how to run tests and interpret alerts.

### Member C (project coordinator) — Integration, AI, and demo
- Verify current hackathon requirements, eligible models, Nebius API setup, and submission requirements from official sources.
- Own the end-to-end integration and keep the event/alert contracts consistent.
- Add the AI incident-summary path with schema validation and an API-failure fallback.
- Build the simplest usable CLI/dashboard after the pipeline works.
- Maintain README, demo script, and final reproducible run instructions.
- Review teammates' changes and make sure the whole system runs from a clean checkout.

### Shared responsibilities
- Agree on schema before parallel implementation.
- Each member reviews at least one teammate's pull request.
- Everyone can explain the architecture, demo flow, limitations, and their own contribution.
- Do not claim a feature is complete until it has been run and tested.

## Immediate next steps (first 1–2 days)

1. Confirm all three members' GitHub usernames and the OS each person will develop on.
2. Agree that the first milestone is a **synthetic JSONL → detector → alert output** vertical slice.
3. Review and freeze the minimum event schema for v1; change it only through a reviewed commit.
4. Commit a tiny sample file containing ordinary events and known synthetic anomalies.
5. Split the three workstreams above into GitHub Issues and assign the actual collaborators.
6. Get the detector tests passing before spending time on live capture, C++ optimization, or UI polish.
7. In parallel, verify official hackathon requirements and Nebius/NVIDIA integration requirements. Do not assume a model/service is eligible without checking.

## Definition of done

- A clean checkout can run the documented demo.
- Tests cover normal input, known anomalies, edge cases, and malformed records.
- Alerts include traceable evidence and thresholds.
- AI summaries are grounded in provided evidence and are optional to core detection.
- API keys, access tokens, private captures, and sensitive logs are never committed.
- Performance claims are measured and reproducible.
- Limitations and synthetic/replayed data are clearly disclosed.

## Safe testing

Use synthetic fixtures, devices/networks you own, approved packet captures, or systems you are explicitly authorized to monitor. Do not scan or attack public, campus, or third-party systems without permission. Prefer metadata-only analysis.
