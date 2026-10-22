# SENTINEL Team Contribution Plan

This plan splits the remaining MVP work into independent, reviewable tasks. Replace the role labels with the contributors' GitHub usernames before presenting this as a record of completed work.

## Workstreams

| Workstream | Owner | Deliverable | Acceptance check |
|---|---|---|---|
| Detection logic | Project lead | Maintain `src/detector.py` and edge-case tests | Unit tests pass; rule and threshold are explained |
| Event input and demo | Contributor 2 | Review `src/run_detector.py`, sample JSONL, and CLI behaviour | A clean checkout can run the sample and show an alert |
| Test quality and documentation | Contributor 3 | Add test cases, improve README, and verify setup steps | Tests run from repository root; docs match actual behaviour |

## Team workflow

1. Each contributor takes one workstream and creates a small branch or pull request.
2. Keep changes focused; do not edit the same file simultaneously without coordinating.
3. Run `python -m unittest discover -v` from the repository root before opening a pull request.
4. In the pull request description, state what changed, how it was tested, and any known limitations.
5. The project lead reviews and merges only after the acceptance check is met.

## Contribution record

Fill this in honestly as work is completed. Do not claim a task or contribution before it has happened.

| Contributor GitHub username | Task completed | Evidence (PR/commit) |
|---|---|---|
| Vedant924 | Project coordination and integration | Add commit or PR link |
| Contributor 2 | To be assigned | Add after completion |
| Contributor 3 | To be assigned | Add after completion |

## Current scope and limitations

The current MVP uses synthetic JSONL events and explainable rule-based detection. It does not capture live network traffic, establish that an event is malicious, or include AI-assisted incident analysis. Alerts are leads for review, not proof of an intrusion.
