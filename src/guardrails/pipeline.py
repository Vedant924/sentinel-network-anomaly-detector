"""End-to-end AI Guardrail pipeline uniting deterministic guards and NVIDIA model analysis."""

from typing import Any, Dict, Optional

from src.guardrails.injection_guard import detect_prompt_injection
from src.guardrails.audit_log import build_audit_trail
from src.guardrails.nebius_client import NebiusClient
from src.guardrails.tool_policy import evaluate_tool_call, simulate_tool_call


def run_guardrail_pipeline(
    prompt: str,
    proposed_tool: Optional[Dict[str, Any]] = None,
    nebius_client: Optional[NebiusClient] = None,
    allowed_dir: str = "data",
    max_depth: int = 20,
    human_approved: bool = False,
) -> Dict[str, Any]:
    """Execute end-to-end security pipeline for user prompt and optional tool call.

    Execution Flow:
    1. Pre-flight deterministic prompt-injection detection (authoritative).
       - If blocked: immediate short-circuit return. Zero model API calls, zero tool calls.
    2. Advisory analysis via Nebius Token Factory (NVIDIA model or offline mock).
       - Model output is advisory narrative ONLY. It NEVER overrides a security block.
    3. Tool policy firewall (if proposed_tool is provided).
       - Validates tool name, argument types, dangerous patterns, and path containment.
       - If blocked: overall status set to BLOCKED. If allowed: safe simulation executes.
    4. Consolidated structured audit record returned.

    Args:
        prompt: User input string.
        proposed_tool: Optional dict with {"name": str, "arguments": dict}.
        nebius_client: Optional configured NebiusClient instance.
        allowed_dir: Permitted sandbox directory for file read tools.
        max_depth: Maximum permitted nesting depth for arguments (default: 20).
        human_approved: Explicit approval signal supplied by a trusted caller/UI, never by model output.

    Returns:
        dict containing:
            - overall_status (str): "ALLOWED" or "BLOCKED".
            - model_status (str): "MODEL_OK", "MODEL_MOCK", "MODEL_UNAVAILABLE", or "MODEL_SKIPPED".
            - prompt_injection (dict): Stage 1 injection verdict.
            - ai_analysis (dict | None): Stage 2 model or mock narrative analysis.
            - tool_evaluation (dict | None): Stage 3 tool policy verdict (if tool proposed).
            - simulated_tool_result (dict | None): Stage 3 simulated execution result.
    """
    client = nebius_client or NebiusClient()

    # Step 0: Input validation for prompt
    if not isinstance(prompt, str) or not prompt.strip():
        reason_msg = (
            "Prompt must be a non-empty string."
            if isinstance(prompt, str)
            else f"Prompt must be a string, got {type(prompt).__name__}."
        )
        return {
            "overall_status": "BLOCKED",
            "model_status": "MODEL_SKIPPED",
            "prompt_injection": {
                "allowed": False,
                "risk_level": "HIGH",
                "rule_triggered": "INVALID_INPUT",
                "reason": reason_msg,
                "matched_patterns": [],
            },
            "ai_analysis": None,
            "tool_evaluation": None,
            "simulated_tool_result": None,
            "audit_trail": build_audit_trail({
                "allowed": False,
                "risk_level": "HIGH",
                "rule_triggered": "INVALID_INPUT",
                "reason": reason_msg,
            }),
        }

    # Step 1: Deterministic prompt injection check (authoritative)
    try:
        injection_verdict = detect_prompt_injection(prompt)
    except ValueError as val_err:
        return {
            "overall_status": "BLOCKED",
            "model_status": "MODEL_SKIPPED",
            "prompt_injection": {
                "allowed": False,
                "risk_level": "HIGH",
                "rule_triggered": "INVALID_INPUT",
                "reason": str(val_err),
                "matched_patterns": [],
            },
            "ai_analysis": None,
            "tool_evaluation": None,
            "simulated_tool_result": None,
            "audit_trail": build_audit_trail({
                "allowed": False,
                "risk_level": "HIGH",
                "rule_triggered": "INVALID_INPUT",
                "reason": str(val_err),
            }),
        }

    # Short-circuit on injection detection: do not call model API, do not evaluate tools
    if not injection_verdict["allowed"]:
        return {
            "overall_status": "BLOCKED",
            "model_status": "MODEL_SKIPPED",
            "prompt_injection": injection_verdict,
            "ai_analysis": None,
            "tool_evaluation": None,
            "simulated_tool_result": None,
            "audit_trail": build_audit_trail(injection_verdict),
        }

    # Step 2: Advisory NVIDIA Model Analysis via Nebius Token Factory
    try:
        ai_analysis = client.analyze_incident(prompt)
        if not isinstance(ai_analysis, dict):
            ai_analysis = {
                "status": "MODEL_UNAVAILABLE",
                "success": False,
                "is_mock": False,
                "model": getattr(client, "model", "unknown"),
                "explanation": (
                    "[FALLBACK] Model client returned malformed non-dictionary result. "
                    "Deterministic guardrails remain authoritative."
                ),
                "error": "INVALID_CLIENT_RESPONSE",
            }
    except Exception:
        ai_analysis = {
            "status": "MODEL_UNAVAILABLE",
            "success": False,
            "is_mock": False,
            "model": getattr(client, "model", "unknown"),
            "explanation": (
                "[FALLBACK] Model client raised an unexpected exception during analysis. "
                "Deterministic guardrails remain authoritative."
            ),
            "error": "CLIENT_EXCEPTION",
        }

    model_status = ai_analysis.get("status", "MODEL_UNAVAILABLE")

    # Step 3: Tool policy evaluation (if tool proposed)
    tool_verdict = None
    simulated_result = None
    overall_status = "ALLOWED"

    if proposed_tool is not None:
        if not isinstance(proposed_tool, dict):
            overall_status = "BLOCKED"
            tool_verdict = {
                "allowed": False,
                "risk_level": "HIGH",
                "rule_triggered": "INVALID_TOOL_SPECIFICATION",
                "reason": "proposed_tool must be a dictionary with 'name' and 'arguments'.",
            }
        else:
            t_name = proposed_tool.get("name")
            t_args = proposed_tool.get("arguments", {})

            if not isinstance(t_name, str) or not t_name.strip() or not isinstance(t_args, dict):
                overall_status = "BLOCKED"
                tool_verdict = {
                    "allowed": False,
                    "risk_level": "HIGH",
                    "rule_triggered": "INVALID_TOOL_SPECIFICATION",
                    "reason": "Tool 'name' must be a non-empty string and 'arguments' must be a dictionary.",
                }
            elif proposed_tool.get("requires_approval") is True and not human_approved:
                overall_status = "APPROVAL_REQUIRED"
                tool_verdict = {
                    "allowed": False,
                    "risk_level": "HIGH",
                    "rule_triggered": "HUMAN_APPROVAL_REQUIRED",
                    "reason": "This tool call requires explicit human approval before it can proceed.",
                }
                simulated_result = {
                    "status": "APPROVAL_REQUIRED",
                    "tool": t_name.strip(),
                    "simulated_output": None,
                    "policy_verdict": tool_verdict,
                }
            else:
                try:
                    simulated_result = simulate_tool_call(
                        t_name,
                        t_args,
                        allowed_dir=allowed_dir,
                        max_depth=max_depth,
                    )
                    if (
                        not isinstance(simulated_result, dict)
                        or "policy_verdict" not in simulated_result
                    ):
                        raise ValueError("Tool simulation returned malformed result structure.")
                    tool_verdict = simulated_result["policy_verdict"]
                    if not isinstance(tool_verdict, dict) or not tool_verdict.get("allowed", False):
                        overall_status = "BLOCKED"
                except Exception:
                    overall_status = "BLOCKED"
                    tool_verdict = {
                        "allowed": False,
                        "risk_level": "HIGH",
                        "rule_triggered": "TOOL_SIMULATION_ERROR",
                        "reason": "An unexpected error occurred during tool policy simulation.",
                    }
                    simulated_result = {
                        "status": "ERROR",
                        "policy_verdict": tool_verdict,
                        "result": None,
                        "error": "TOOL_SIMULATION_ERROR",
                    }

    return {
        "overall_status": overall_status,
        "model_status": model_status,
        "prompt_injection": injection_verdict,
        "ai_analysis": ai_analysis,
        "tool_evaluation": tool_verdict,
        "simulated_tool_result": simulated_result,
        "audit_trail": build_audit_trail(
            injection_verdict,
            tool_verdict,
            proposed_tool.get("name") if isinstance(proposed_tool, dict) else None,
        ),
    }
