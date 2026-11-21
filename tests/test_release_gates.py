"""Exercise gate failure modes independently of the Go tests under test."""

import contextlib
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import release_gates as gates


def passing_events():
    return [{"Package": "dhcpv4-served/" + gates.package_path(package), "Test": name, "Action": "pass"}
            for checks in gates.GATES.values() for package, name in checks]


class GateResultsTests(unittest.TestCase):
    def test_all_contracts_must_run_and_pass(self):
        result = gates.evaluate(passing_events(), 0)
        self.assertTrue(result["passed"])
        self.assertEqual(len(result["gates"]), 7)

    def test_zero_exit_with_no_or_missing_tests_is_failure(self):
        for events in ([], passing_events()[1:]):
            with self.subTest(events=events):
                self.assertFalse(gates.evaluate(events, 0)["passed"])

    def test_each_gate_fails_for_a_failed_skipped_or_missing_test(self):
        for gate, checks in gates.GATES.items():
            package, name = checks[0]
            for action in ("fail", "skip", "output"):
                events = passing_events()
                for event in events:
                    if event["Package"].endswith("/" + package) and event["Test"] == name:
                        event["Action"] = action
                with self.subTest(gate=gate, action=action):
                    result = gates.evaluate(events, 0)
                    self.assertFalse(result["passed"])
                    self.assertFalse(result["gates"][gate]["passed"])

    def test_failed_or_skipped_child_cannot_hide_behind_parent_pass(self):
        for action in ("skip", "fail"):
            child = {"Package": "dhcpv4-served/internal/server", "Test": "TestGateDurableACK/failed_commit", "Action": action}
            result = gates.evaluate([child] + passing_events(), 0)
            self.assertFalse(result["passed"])
            self.assertFalse(result["gates"]["durable-ack"]["passed"])

    def test_pass_from_wrong_package_does_not_satisfy_gate(self):
        events = passing_events()
        events[0]["Package"] = "unrelated/package"
        self.assertFalse(gates.evaluate(events, 0)["passed"])

    def test_build_or_process_failure_is_failure_even_with_passing_events(self):
        self.assertFalse(gates.evaluate(passing_events(), 1)["passed"])

    def test_command_result_and_failure_reports(self):
        success = "\n".join(json.dumps(event) for event in passing_events())
        for name, stdout, code, expected in (("passing", success, 0, 0),
                                              ("empty_success", "", 0, 1),
                                              ("build_failure", "", 1, 1),
                                              ("invalid_output", "not JSON", 0, 1)):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                process = subprocess.CompletedProcess([], code, stdout, "")
                with patch.object(gates, "ROOT", root), patch.object(gates, "revision", return_value={}):
                    with patch.object(gates.subprocess, "run", return_value=process):
                        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                            self.assertEqual(gates.main(), expected)
                report = json.loads((root / "work/release-gates.json").read_text())
                self.assertEqual(report["passed"], expected == 0)

    def test_missing_tool_or_timeout_replaces_previous_evidence(self):
        for error in (FileNotFoundError("go missing"), subprocess.TimeoutExpired("go", 300)):
            with self.subTest(error=error), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / "work").mkdir()
                log = root / "work/release-gates.go.jsonl"
                log.write_text("old successful evidence")
                with patch.object(gates, "ROOT", root), patch.object(gates, "revision", return_value={}):
                    with patch.object(gates.subprocess, "run", side_effect=error):
                        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                            self.assertEqual(gates.main(), 1)
                self.assertEqual(log.read_text(), "")
                self.assertFalse(json.loads((root / "work/release-gates.json").read_text())["passed"])


if __name__ == "__main__":
    unittest.main()
