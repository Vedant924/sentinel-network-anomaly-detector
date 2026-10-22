import json
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path

from src.run_detector import load_events, main


class TestEventLoader(unittest.TestCase):
    def test_loads_jsonl_and_ignores_blank_lines(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.jsonl"
            path.write_text(
                '{"timestamp": 1, "src_ip": "192.0.2.1", "dst_port": 80}\n\n',
                encoding="utf-8",
            )
            self.assertEqual(
                load_events(path),
                [{"timestamp": 1, "src_ip": "192.0.2.1", "dst_port": 80}],
            )

    def test_reports_invalid_json_line_number(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.jsonl"
            path.write_text('{"timestamp": 1}\nnot-json\n', encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "line 2"):
                load_events(path)

    def test_rejects_non_object_json(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.jsonl"
            path.write_text(json.dumps([1, 2, 3]) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "JSON object"):
                load_events(path)


class TestDetectorCommand(unittest.TestCase):
    def test_normal_file_runs_without_alert(self):
        output = StringIO()
        normal_path = Path("data/normal_events.jsonl")
        with redirect_stdout(output):
            result = main(["--input", str(normal_path)])
        self.assertEqual(result, 0)
        self.assertIn("SENTINEL analyzed 5 event(s).", output.getvalue())
        self.assertIn("No anomalies detected.", output.getvalue())

    def test_sample_file_runs_and_prints_alert(self):
        output = StringIO()
        sample_path = Path("data/sample_events.jsonl")
        with redirect_stdout(output):
            result = main(["--input", str(sample_path)])
        self.assertEqual(result, 0)
        self.assertIn("SENTINEL analyzed", output.getvalue())
        self.assertIn("MANY_DESTINATION_PORTS", output.getvalue())


if __name__ == "__main__":
    unittest.main()
