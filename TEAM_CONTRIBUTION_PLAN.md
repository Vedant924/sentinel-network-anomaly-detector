# SENTINEL AI Guard — Team Contribution Plan

This document splits the project into independently reviewable contributions. Each teammate should make changes on their own branch and open a pull request. Do not commit directly to `main`.

## Current project status

The local working version has a rule-based prompt-injection detector, a deterministic tool policy, a Nebius-compatible model client, a pipeline, and a reported 59-test suite (58 passed, 1 skipped). Confirm that the latest local code has actually been pushed to GitHub before assigning work that depends on it; the public repository may still contain an earlier version.

**Important:** the current demo tools are simulations. Do not add real shell execution, file writes, or database execution as part of these tasks.

## Work split for a three-person team

### Team lead — integration and security review
- Own the pipeline and deterministic policy.
- Review every pull request and run the full test suite before merging.
- Keep model output advisory only; it must never override a deterministic block.
- Keep API keys out of source control and screenshots.

### Teammate A — UI and demo experience
**Branch:** `feature/demo-ui`

Build a small, beginner-friendly interface that:
- accepts a prompt and an optional proposed tool call;
- shows the prompt-injection verdict, risk level, matched rule and explanation;
- shows tool-policy verdict separately from model status;
- clearly labels model modes as **LIVE**, **MOCK**, or **UNAVAILABLE**;
- displays simulated tool output as simulated, never as a real action;
- shows a clear blocked state for unsafe requests.

Do not edit `src/guardrails/injection_guard.py`, `src/guardrails/tool_policy.py`, or `src/guardrails/pipeline.py` without coordinating with the lead. Add UI tests or a manual test checklist.

**Acceptance criteria**
- The UI starts from documented commands.
- A benign prompt and a blocked injection prompt can be demonstrated.
- A safe demo tool produces only mock output.
- An unsafe tool is blocked even if the model explanation says it is safe.
- Missing API key is visibly identified as mock/offline mode.

### Teammate B — documentation and reproducible demo
**Branch:** `docs/setup-and-demo`

Improve documentation without changing security behavior:
- document Python setup and the exact test command;
- write a 3–5 minute demo script with benign, injection, and unsafe-tool examples;
- add a troubleshooting section for missing API keys, model errors, and test failures;
- document the architecture and limitations, including regex limitations and simulated tools;
- provide a safe `.env.example` containing placeholders only (never a real key).

**Acceptance criteria**
- A new teammate can clone the repository, install only documented dependencies, run tests, and understand mock versus live mode.
- No secrets or personal machine paths appear in docs.
- Commands are tested on the author's environment.

### Team lead / shared follow-up — test quality and model configuration
After the first two contributions are reviewed:
- add focused regression tests for any UI-to-pipeline integration;
- validate `max_depth` as a positive integer at the public pipeline boundary;
- verify the configured Nebius model identifier and API request format against current provider documentation before claiming live integration;
- keep all network tests mocked by default.

## Required pull-request workflow

1. Sync the latest `main` branch.
2. Create your own branch using the names above.
3. Make one focused change at a time.
4. Run the tests and include the exact command and result in the pull request.
5. Open a pull request into `main`; do not merge your own PR without review.
6. The lead checks the diff, test results, secrets, and whether security decisions can be overridden.
7. Merge only after review and a passing test suite.

## Local test command

From the repository root:

```powershell
python -m unittest discover -s tests -v
```

A symlink test may be skipped on Windows when the environment does not permit symlink creation. Record the actual result; do not claim tests passed unless they were run.

## GitHub task tracking

Create one GitHub Issue for each task and assign an owner. Each issue should state:
- the goal;
- files the contributor may edit;
- acceptance criteria;
- how to test;
- the pull request that closes the issue.

## Security boundaries — non-negotiable

- Never commit API keys, tokens, passwords, or real user data.
- Never make the model the final authority on tool permission.
- Never add real shell, database, filesystem-write, or arbitrary network execution to the MVP.
- Do not silently label mock output as live AI output.
- Preserve the original network anomaly detector and its tests.
- Keep pull requests small and explain every security-sensitive change.
