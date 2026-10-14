# SENTINEL Architecture

## Planned data flow

Synthetic JSONL / approved PCAP replay → language-independent event normalization → versioned JSONL events → rolling-window analytics → explainable detection rules → structured alerts → optional Nebius-hosted NVIDIA model for an AI-assisted incident summary → CLI or minimal dashboard.

The first end-to-end MVP should prioritize the simplest reliable implementation. Python is the recommended starting point for event replay, analytics, tests, AI integration, and the initial interface. A C++ producer/parser may be added later if it provides a demonstrated capability or performance benefit. The JSONL contract allows components to use different languages.

## Components

### Traffic input and event producer
- Begin with synthetic JSONL events; add approved PCAP replay if feasible.
- Normalize packet metadata into the agreed event schema.
- Handle malformed, truncated, and unsupported input safely.
- Avoid collecting payload contents unless there is a documented, authorized need.
- Clearly distinguish synthetic/replayed data from live capture.

### Detector and analytics
- Validate incoming events.
- Maintain bounded rolling windows and counters.
- Generate alerts with a rule ID, time window, observed evidence, threshold, severity rationale, and uncertainty.
- Treat suspicious patterns as indicators, not proof of malicious activity.

### AI incident analyst
- Summarize structured alert evidence in plain language.
- Validate model output and label it as AI-generated.
- Never execute commands or automatically change network settings.
- Keep deterministic detection working when the AI service is unavailable.
- Integrate only after current Nebius/NVIDIA and hackathon requirements have been verified.

### CLI/dashboard
Show event rates, protocol breakdown, alert timeline, evidence behind each rule, and incident summaries. Build a simple working view before adding visual polish.

## Build order

1. Agree on the event schema and add synthetic fixtures.
2. Build an end-to-end synthetic JSONL → detector → alert-output path.
3. Add tests for normal events, known anomalies, boundaries, and malformed input.
4. Add approved PCAP replay if feasible.
5. Integrate a compatible NVIDIA model through Nebius if required and available under verified rules.
6. Add a simple CLI/dashboard and reproducible demo.
7. Consider a C++ component only if it adds clear value and the time budget permits.

## Decisions to confirm

- Development OS for each member.
- Event schema v1 and fixture format.
- Whether PCAP replay is feasible on the team's machines.
- CLI versus minimal web interface.
- Current hackathon rules, model/API configuration, and submission requirements.
- Detection thresholds, evaluated with test fixtures rather than guessed performance claims.
