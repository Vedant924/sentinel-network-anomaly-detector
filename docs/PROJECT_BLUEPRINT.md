# SENTINEL Project Blueprint

## Goal
Build a reproducible defensive network-anomaly analysis prototype using:
1. C-based packet metadata parsing or PCAP replay.
2. Python explainable anomaly detection.
3. Optional AI-assisted incident summaries using a compatible NVIDIA model through Nebius.
4. A simple dashboard and repeatable demo.

These are goals, not claims that the features are already implemented.

## Minimum viable product
- Ingest synthetic events or events from an approved PCAP replay.
- Validate the JSONL event format.
- Implement at least two tested, explainable anomaly rules.
- Show the evidence and threshold behind each alert.
- Keep core detection working when the AI service is unavailable.
- Include tests, setup instructions, and a repeatable demo.

Possible initial rules:
- Event/connection rate above a configurable threshold in a defined time window.
- One source contacting an unusually large number of distinct destination ports.
- A sudden traffic-volume change against a configured baseline.

Tune thresholds using normal and synthetic test cases. Alerts describe patterns and are not proof of malicious intent.

## AI feature
The AI analyst can summarize structured alert evidence, explain why a rule fired, describe uncertainty, and suggest safe defensive investigation steps. It must not invent telemetry or execute commands.

Before relying on the hackathon for project scope, verify its current official requirements, deadline, eligible models/services, API details, and submission format.

## Suggested three-person split
Adjust this to the team's skills and confirm responsibilities together.

- **C/event producer:** parsing or replay, JSONL output, malformed-input handling, tests.
- **Python detector:** event validation, rolling windows, rules, alert contract, tests.
- **Integration/demo:** dashboard, synthetic fixtures, AI integration, end-to-end demo, documentation.

Agree on the event schema before implementing producer and consumer in parallel.

## Git collaboration
- Use a separate branch for each task.
- Open a pull request before merging into `main`.
- Keep commits small and descriptive.
- Review each other's work and ensure every contributor can explain the code.
- Never commit API keys, access tokens, private captures, or sensitive logs.

## Safe testing
Use synthetic fixtures, your own devices, approved PCAPs, or networks you are explicitly authorized to monitor. Do not scan or attack public, campus, or third-party systems without permission. Prefer metadata-only analysis.

## Definition of done
- Tests cover ordinary, edge-case, and malformed input.
- Output follows the agreed schema.
- Setup and usage are documented.
- Limitations are stated honestly.
- The author understands the implementation.
