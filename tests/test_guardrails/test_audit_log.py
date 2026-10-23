"""Tests for privacy-conscious guardrail audit records."""

import unittest

from src.guardrails.audit_log import build_audit_event, build_audit_trail


class TestAuditLog(unittest.TestCase):
    def test_audit_event_has_structured_decision_fields(self):
        event = build_audit_event(
            stage="tool_policy",
            decision="BLOCK",
            rule_triggered="UNKNOWN_TOOL",
            risk_level="HIGH",
            reason="Tool is not allowlisted.",
            tool_name="run_shell",
        )
        self.assertEqual(event["decision"], "BLOCK")
        self.assertEqual(event["rule_triggered"], "UNKNOWN_TOOL")
        self.assertTrue(event["timestamp"].endswith("+00:00"))

    def test_audit_trail_records_prompt_and_tool_decisions_without_arguments(self):
        trail = build_audit_trail(
            {"allowed": True, "risk_level": "NONE", "rule_triggered": None, "reason": "Prompt passed."},
            {"allowed": False, "risk_level": "CRITICAL", "rule_triggered": "PATH_TRAVERSAL", "reason": "Unsafe path."},
            "read_demo_file",
        )
        self.assertEqual([event["decision"] for event in trail], ["ALLOW", "BLOCK"])
        self.assertEqual(trail[1]["tool_name"], "read_demo_file")
        self.assertNotIn("arguments", str(trail))
        self.assertNotIn("Ignore all previous instructions", str(trail))

    def test_required_fields_are_validated(self):
        with self.assertRaises(ValueError):
            build_audit_event("", "BLOCK", None, "HIGH", "reason")


if __name__ == "__main__":
    unittest.main()
