"""AI Guardrail module for prompt injection detection and policy enforcement."""

from src.guardrails.injection_guard import detect_prompt_injection

__all__ = ["detect_prompt_injection"]
