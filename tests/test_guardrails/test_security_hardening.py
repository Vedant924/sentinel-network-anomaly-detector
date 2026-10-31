"""Regression tests for hardened file access and read-only SQL policy."""

import os
import tempfile
import unittest

from src.guardrails.tool_policy import (
    _validate_read_only_sql,
    evaluate_tool_call,
    open_sandboxed_file,
)


class TestReadOnlySQLHardening(unittest.TestCase):
    def test_safe_selects_and_ctes_remain_allowed(self):
        safe_queries = [
            "SELECT id, src_ip FROM events WHERE id = 10;",
            "WITH recent AS (SELECT * FROM events WHERE timestamp > 1000) SELECT * FROM recent;",
            "SELECT 'DROP TABLE users' AS note;",
            "SELECT 'UPDATE users SET role = admin' AS note",
            "/* report query */ SELECT count(*) FROM events",
        ]
        for sql in safe_queries:
            with self.subTest(sql=sql):
                self.assertIsNone(_validate_read_only_sql(sql))
                verdict = evaluate_tool_call("query_demo_database", {"sql": sql})
                self.assertTrue(verdict["allowed"], verdict)

    def test_multiple_statements_are_rejected(self):
        attacks = [
            "SELECT 1; DROP TABLE events;",
            "SELECT 1; SELECT 2;",
            "SELECT 1; -- comment\nWITH x AS (SELECT 1) SELECT * FROM x;",
        ]
        for sql in attacks:
            with self.subTest(sql=sql):
                verdict = evaluate_tool_call("query_demo_database", {"sql": sql})
                self.assertFalse(verdict["allowed"])
                self.assertIn(
                    verdict["rule_triggered"],
                    {"MULTIPLE_SQL_STATEMENTS", "SQL_INJECTION"},
                )

    def test_mutating_and_privileged_sql_are_rejected(self):
        attacks = [
            "PRAGMA user_version;",
            "SELECT * FROM users FOR UPDATE;",
            "WITH x AS (SELECT 1) UPDATE users SET role = 'admin';",
            "SELECT * FROM events INTO OUTFILE '/tmp/events.csv';",
            "ATTACH DATABASE '/tmp/other.db' AS other;",
        ]
        for sql in attacks:
            with self.subTest(sql=sql):
                verdict = evaluate_tool_call("query_demo_database", {"sql": sql})
                self.assertFalse(verdict["allowed"])

    def test_injection_patterns_are_still_rejected(self):
        attacks = [
            "SELECT * FROM users WHERE name = '' OR '1'='1';",
            "SELECT id FROM events UNION ALL SELECT password FROM users;",
            "SELECT * FROM events; -- comment",
        ]
        for sql in attacks:
            with self.subTest(sql=sql):
                verdict = evaluate_tool_call("query_demo_database", {"sql": sql})
                self.assertFalse(verdict["allowed"])
                self.assertEqual(verdict["rule_triggered"], "SQL_INJECTION")

    def test_malformed_quotes_and_comments_fail_closed(self):
        for sql in ["SELECT 'unfinished", "SELECT 1 /* unfinished"]:
            with self.subTest(sql=sql):
                verdict = evaluate_tool_call("query_demo_database", {"sql": sql})
                self.assertFalse(verdict["allowed"])
                self.assertEqual(verdict["rule_triggered"], "INVALID_SQL")


class TestSandboxedFileOpening(unittest.TestCase):
    def test_opens_regular_file_inside_sandbox(self):
        with tempfile.TemporaryDirectory() as root:
            expected = b"demo data\n"
            with open(os.path.join(root, "sample.txt"), "wb") as file:
                file.write(expected)

            with open_sandboxed_file("sample.txt", allowed_dir=root) as file:
                self.assertEqual(file.read(), expected)

    def test_rejects_traversal_and_absolute_paths(self):
        with tempfile.TemporaryDirectory() as root:
            for path in ("../outside.txt", "/etc/passwd", r"..\outside.txt", "folder/../x"):
                with self.subTest(path=path):
                    with self.assertRaises((ValueError, PermissionError)):
                        open_sandboxed_file(path, allowed_dir=root)

    def test_rejects_symlink_even_when_target_is_inside_sandbox(self):
        with tempfile.TemporaryDirectory() as root:
            target = os.path.join(root, "target.txt")
            link = os.path.join(root, "link.txt")
            with open(target, "wb") as file:
                file.write(b"secret")
            try:
                os.symlink(target, link)
            except (OSError, NotImplementedError):
                self.skipTest("Symlink creation is unavailable in this environment.")

            with self.assertRaises((OSError, PermissionError)):
                open_sandboxed_file("link.txt", allowed_dir=root)

    def test_rejects_directories_as_files(self):
        with tempfile.TemporaryDirectory() as root:
            os.mkdir(os.path.join(root, "folder"))
            with self.assertRaises((OSError, PermissionError, IsADirectoryError)):
                open_sandboxed_file("folder", allowed_dir=root)


if __name__ == "__main__":
    unittest.main()
