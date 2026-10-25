"""AI-Assisted Incident Triage Bridge connecting Network Detection to AI Guardrails."""

from typing import Any, Dict, List, Optional

from src.guardrails.nebius_client import NebiusClient
from src.guardrails.pipeline import run_guardrail_pipeline


def format_triage_prompt(alert: Dict[str, Any]) -> str:
    """Construct an explainable security investigation prompt from a network alert."""
    if not isinstance(alert, dict):
        raise ValueError("Alert must be a dictionary")

    rule = alert.get("rule", "UNKNOWN_RULE")
    source = alert.get("source", "UNKNOWN_SOURCE")
    severity = alert.get("severity", "MEDIUM")
    reason = alert.get("reason", "No details provided.")

    return (
        f"Security Alert Analysis: Rule '{rule}' fired for source IP '{source}' with severity '{severity}'. "
        f"Observed evidence: {reason} "
        f"Please provide an incident summary, potential risk assessment, and recommended containment steps."
    )


def triage_network_alert(
    alert: Dict[str, Any],
    nebius_client: Optional[NebiusClient] = None,
    propose_investigation_tool: bool = False,
) -> Dict[str, Any]:
    """Pass a network alert into the AI Guardrail pipeline for safe AI-assisted incident analysis.

    Enforces that:
    1. The generated prompt passes prompt-injection checks.
    2. Any proposed investigation tool call passes deterministic policy firewalls.
    3. AI incident narrative remains advisory and deterministic safety is preserved.

    Returns:
        Structured triage record containing incident metadata, AI explanation,
        guardrail verdicts, and an audit trail.
    """
    if not isinstance(alert, dict):
        raise ValueError("alert must be a dictionary")

    prompt = format_triage_prompt(alert)

    proposed_tool = None
    if propose_investigation_tool:
        rule_name = str(alert.get("rule", "network_anomaly")).lower()
        proposed_tool = {
            "name": "search_docs",
            "arguments": {"query": f"incident response runbook for {rule_name}"},
        }

    pipeline_result = run_guardrail_pipeline(
        prompt=prompt,
        proposed_tool=proposed_tool,
        nebius_client=nebius_client,
    )

    incident_id = f"INC-{int(alert.get('timestamp', 0))}-{alert.get('source', 'unknown')}"

    ai_analysis = pipeline_result.get("ai_analysis")
    ai_summary = ai_analysis.get("explanation") if isinstance(ai_analysis, dict) else None

    return {
        "incident_id": incident_id,
        "alert": alert,
        "triage_status": "TRIAGED" if pipeline_result["overall_status"] == "ALLOWED" else "BLOCKED",
        "ai_summary": ai_summary,
        "guardrail_verdict": pipeline_result,
        "audit_trail": pipeline_result.get("audit_trail", []),
    }


def triage_incident_batch(
    alerts: List[Dict[str, Any]],
    nebius_client: Optional[NebiusClient] = None,
) -> List[Dict[str, Any]]:
    """Triage a list of network alerts through the guardrail pipeline."""
    if not isinstance(alerts, list):
        raise ValueError("alerts must be a list")
    return [
        triage_network_alert(alert, nebius_client=nebius_client)
        for alert in alerts
    ]
