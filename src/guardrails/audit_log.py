"""Small, privacy-conscious audit records for guardrail decisions."""

from datetime import datetime, timezone
from typing import Any, Dict, Optional


def build_audit_event(
    stage: str,
    decision: str,
    rule_triggered: Optional[str],
    risk_level: str,
    reason: str,
    tool_name: Optional[str] = None,
) -> Dict[str, Any]:
    """Create a structured event without copying prompts or tool arguments."""
    if not stage or not decision or not risk_level or not reason:
        raise ValueError("stage, decision, risk_level, and reason are required")

    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "stage": stage,
        "decision": decision,
        "risk_level": risk_level,
        "rule_triggered": rule_triggered,
        "tool_name": tool_name,
        "reason": reason,
    }


def build_audit_trail(
    prompt_verdict: Dict[str, Any],
    tool_verdict: Optional[Dict[str, Any]] = None,
    tool_name: Optional[str] = None,
) -> list:
    """Summarize final deterministic decisions; never log raw prompt/arguments."""
    events = [
        build_audit_event(
            stage="prompt_injection",
            decision="ALLOW" if prompt_verdict.get("allowed") else "BLOCK",
            rule_triggered=prompt_verdict.get("rule_triggered"),
            risk_level=prompt_verdict.get("risk_level", "HIGH"),
            reason=prompt_verdict.get("reason", "No reason supplied."),
        )
    ]
    if tool_verdict is not None:
        events.append(
            build_audit_event(
                stage="tool_policy",
                decision=(
                    "ALLOW" if tool_verdict.get("allowed") else
                    "APPROVAL_REQUIRED" if tool_verdict.get("rule_triggered") == "HUMAN_APPROVAL_REQUIRED" else
                    "BLOCK"
                ),
                rule_triggered=tool_verdict.get("rule_triggered"),
                risk_level=tool_verdict.get("risk_level", "HIGH"),
                reason=tool_verdict.get("reason", "No reason supplied."),
                tool_name=tool_name,
            )
        )
    return events
