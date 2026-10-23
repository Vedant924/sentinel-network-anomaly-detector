"""Deterministic prompt-injection and jailbreak detector for AI Guardrail."""

import re
import unicodedata
from typing import Any, Dict, List, Optional, Tuple

# Rule definition: (Rule ID, Risk Level, Pattern Description, Compiled Regex)
INJECTION_RULES: List[Tuple[str, str, str, re.Pattern]] = [
    (
        "INSTRUCTION_OVERRIDE",
        "CRITICAL",
        "Attempt to override, bypass, or discard prior system instructions",
        re.compile(
            r"\b(?:ignore|disregard|forget|bypass|override|drop|cancel)\b[\s,:;—\-\.]+"
            r"(?:(?:all|any)\s+(?:of\s+)?(?:the\s+)?|(?:the|your)\s+)?"
            r"(?:previous|prior|above|system|earlier)\s+"
            r"(?:instructions|prompts|rules|commands|context|directives)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "INSTRUCTION_OVERRIDE",
        "CRITICAL",
        "Direct instruction or system prompt override directive",
        re.compile(
            r"\b(?:system\s+prompt\s+override|override\s+system\s+prompt)\b|"
            r"\b(?:reset|clear)\s+(?:all\s+(?:of\s+)?(?:the\s+)?)?"
            r"(?:system\s+instructions|system\s+rules|safety\s+constraints)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "SYSTEM_PROMPT_EXFILTRATION",
        "HIGH",
        "Attempt to exfiltrate or reveal internal system prompt instructions",
        re.compile(
            r"\b(?:show|reveal|display|output|print|repeat|leak|dump|give\s+me|tell\s+me)\s+"
            r"(?:me\s+)?(?:the\s+|your\s+)?(?:initial|original|secret|hidden|internal|exact)?\s*"
            r"(?:system\s+prompt|system\s+instructions|developer\s+instructions|system\s+message|base\s+instructions)\b|"
            r"\b(?:what\s+is|what\s+are|can\s+i\s+(?:see|view)|can\s+you\s+(?:share|provide|tell\s+me|show\s+me|reveal))\s+"
            r"(?:me\s+)?(?:the\s+|your\s+)(?:initial|original|secret|hidden|internal|exact)?\s*"
            r"(?:system\s+prompt|system\s+instructions|developer\s+instructions|system\s+message|base\s+instructions)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "SYSTEM_PROMPT_EXFILTRATION",
        "HIGH",
        "Directive to repeat all prior conversation or system text verbatim",
        re.compile(
            r"\b(?:repeat|output|print)\s+(?:the\s+text\s+above|everything\s+above|all\s+prior\s+text)\s+"
            r"(?:verbatim|word\s+for\s+word|completely)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "ROLEPLAY_JAILBREAK",
        "CRITICAL",
        "Attempt to engage an unrestricted persona or disable safety guidelines",
        re.compile(
            r"\b(?:you\s+are\s+now|act\s+as|pretend\s+to\s+be)\s+"
            r"(?:an?\s+)?(?:DAN|do\s+anything\s+now|jailbroken|unrestricted|uncensored|evil\s+twin|an?\s+ai\s+without\s+rules)\b|"
            r"\b(?:disable|turn\s+off|bypass|suspend)\s+(?:all\s+)?"
            r"(?:safety|guardrails?|content\s+filters?|ethical\s+guidelines?|safety\s+protocols?)\b|"
            r"\bdeveloper\s+mode\s+(?:is\s+now\s+)?enabled\b",
            re.IGNORECASE,
        ),
    ),
    (
        "DELIMITER_INJECTION",
        "HIGH",
        "Attempt to inject raw chat envelope tokens or fake system message headers",
        re.compile(
            r"(?:<\|im_start\|>\s*(?:system|assistant|user|admin)|<\|im_end\|>|<\|system\|>|"
            r"<\|start_header_id\|>\s*(?:system|assistant|user|admin)?\s*<\|end_header_id\|>|"
            r"<\|start_header_id\|>|<\|end_header_id\|>|<\|eot_id\|>|"
            r"<start_of_turn>\s*(?:model|user)?|<end_of_turn>|"
            r"\[INST\]\s*<<SYS>>|<<SYS>>|\[/INST\])|"
            r"(?:(?:\r?\n|^)###\s*(?:System|Developer|Admin|Root)\s*:)",
            re.IGNORECASE,
        ),
    ),
]


def detect_prompt_injection(prompt: str) -> Dict[str, Any]:
    """Inspect a user prompt and return a structured verdict on prompt-injection risks.

    Applies Unicode NFKC normalization and zero-width/invisible character filtering
    to mitigate obfuscation attempts (e.g. zero-width spaces or fullwidth Latin forms).
    Note: NFKC does not bridge cross-script homoglyphs (e.g. Cyrillic lookalikes), which
    remain an explicit boundary for regex heuristics without a dedicated script map.

    Args:
        prompt: The raw user prompt string to inspect.

    Returns:
        dict containing:
            - allowed (bool): True if prompt passes safety checks, False if blocked.
            - risk_level (str): "NONE", "HIGH", or "CRITICAL".
            - rule_triggered (Optional[str]): Rule ID that triggered, or None if clean.
            - reason (str): Human-readable explanation of the verdict.
            - matched_patterns (List[str]): Snippets of text that triggered the rule.

    Raises:
        ValueError: If prompt is not a non-empty string.
    """
    if not isinstance(prompt, str):
        raise ValueError("Prompt must be a string")
    if not prompt.strip():
        raise ValueError("Prompt must be a non-empty string")

    # SEC-03: Normalize Unicode to NFKC (decomposes fullwidth characters, ligature forms, etc.)
    normalized = unicodedata.normalize("NFKC", prompt)

    # SEC-03: Strip invisible formatting controls (ZWSP \u200B, ZWNJ \u200C, ZWJ \u200D,
    # BOM \uFEFF, Word Joiner \u2060, Soft Hyphen \u00AD, Directional Marks \u200E-\u200F, \u202A-\u202E)
    # 1. Stripped variant: counters intra-word fragmentation (e.g. "I\u200Bgnore" -> "Ignore")
    cleaned_stripped = re.sub(
        r"[\u200B-\u200D\uFEFF\u2060\u00AD\u200E\u200F\u202A-\u202E]", "", normalized
    )
    # 2. Spaced variant: counters invisible space substitution (e.g. "Ignore\u200Ball" -> "Ignore all")
    cleaned_spaced = re.sub(
        r"[\u200B-\u200D\uFEFF\u2060\u00AD\u200E\u200F\u202A-\u202E]", " ", normalized
    )

    candidate_texts = [cleaned_stripped, cleaned_spaced, normalized, prompt]

    for rule_id, risk_level, description, pattern in INJECTION_RULES:
        for candidate in candidate_texts:
            matches = pattern.findall(candidate)
            if matches:
                matched_snippets = [
                    match if isinstance(match, str) else match[0] for match in matches
                ]
                return {
                    "allowed": False,
                    "risk_level": risk_level,
                    "rule_triggered": rule_id,
                    "reason": f"Blocked by guardrail rule '{rule_id}': {description}.",
                    "matched_patterns": matched_snippets,
                }

    return {
        "allowed": True,
        "risk_level": "NONE",
        "rule_triggered": None,
        "reason": "Prompt passed all deterministic safety checks.",
        "matched_patterns": [],
    }
