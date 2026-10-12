import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from endpoint_lab.cli import main
from endpoint_lab.io import read_local
from endpoint_lab.limits import InputError, Limits
from endpoint_lab.scenarios import get_case


class CliTests(unittest.TestCase):
    def test_analysis_report(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "synthetic.json"
            path.write_text(json.dumps(get_case("incident-chain")["events"]))
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                self.assertEqual(main(["analyze", str(path)]), 1)
            report = json.loads(stdout.getvalue())
            self.assertEqual(report["alert_count"], 5)
            self.assertNotIn(directory, stdout.getvalue())

    def test_validation_cli(self):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            self.assertEqual(main(["validate"]), 0)
        self.assertEqual(json.loads(stdout.getvalue())["tuned"]["passed_cases"], 18)

    def test_no_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "input.json"
            path.write_text("[]")
            output = Path(directory) / "report.json"
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(main(["analyze", str(path), "--output", str(path)]), 2)
                self.assertEqual(main(["analyze", str(path), "--output", str(output)]), 0)
                self.assertEqual(main(["analyze", str(path), "--output", str(output)]), 2)
            self.assertEqual(path.read_text(), "[]")

    def test_bad_inputs_and_policy_conflict(self):
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(main(["analyze", "missing.xml"]), 2)
            self.assertEqual(main(["analyze", "missing.xml", "--policy", "x", "--tuned"]), 2)

    def test_directory_and_limit_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(InputError):
                read_local(Path(directory))
            path = Path(directory) / "large"
            path.write_bytes(b"abcd")
            with self.assertRaises(InputError):
                read_local(path, Limits(file_bytes=3))

    def test_symlink_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "input"
            path.write_bytes(b"[]")
            link = Path(directory) / "link"
            try:
                link.symlink_to(path)
            except OSError:
                self.skipTest("Windows symlink permission unavailable")
            with self.assertRaises(InputError):
                read_local(link)
