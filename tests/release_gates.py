"""Run the experimental worker's executable contracts; no PR metadata needed."""

import json
import os
from pathlib import Path
import re
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
GATES = {
    "bounded-events": [("cmd/dhcpv4-served", "TestWorkerFloodEvents"),
                       ("cmd/dhcpv4-served", "TestWorkerWithBlockedOrBrokenOutput"),
                       ("events", "TestLocalDeliveryFaults")],
    "durable-ack": [("server", "TestGateDurableACK")],
    "ownership": [("server", "TestGateSelectingOwnership"), ("server", "TestGateReleaseDeclineOwnership")],
    "restart-reservations": [("lease", "TestGateRestartReservations")],
    "input-validation": [("config", "TestLoad"), ("config", "TestValidateLink"),
                         ("config", "TestValidateMultiple"), ("protocol", "TestMalformedOptions"),
                         ("protocol", "TestConcatenation"),
                         ("server", "TestRelayFieldsDoNotReserveAddress")],
    "socket-and-link": [("activation", "TestRejectActivation"), ("transport", "TestMetadata"),
                        ("transport", "TestMonitorRejectsReplacementAndLostEvents")],
    "snapshot-integrity": [("store", "TestLockSurvivesSnapshotReplacementAndExit"),
                           ("store", "TestLockRejectsUnsafePaths"), ("store", "TestSnapshotRecoveryAndIdentity")],
}


def package_path(package):
    return package if package.startswith("cmd/") else "internal/" + package


def evaluate(events, exit_code):
    """A zero process exit is insufficient: every named test must actually pass."""
    results = {}
    for gate, checks in GATES.items():
        outcomes = {}
        for package, name in checks:
            relevant = [e for e in events if e.get("Package") == "dhcpv4-served/" + package_path(package)
                        and (e.get("Test") == name or e.get("Test", "").startswith(name + "/"))]
            actions = {e.get("Action") for e in relevant}
            terminal = [e.get("Action") for e in relevant if e.get("Test") == name
                        and e.get("Action") in {"pass", "fail", "skip"}]
            status = ("fail" if "fail" in actions else "skip" if "skip" in actions
                      else "pass" if terminal == ["pass"] else "missing")
            outcomes[package + "/" + name] = status
        results[gate] = {"passed": all(s == "pass" for s in outcomes.values()), "tests": outcomes}
    return {"passed": exit_code == 0 and all(r["passed"] for r in results.values()), "gates": results}


def revision():
    try:
        sha = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True, stderr=subprocess.DEVNULL).strip()
        dirty = bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT, text=True, stderr=subprocess.DEVNULL))
        return {"commit": sha, "dirty": dirty}
    except (OSError, subprocess.CalledProcessError):
        return {"commit": None, "dirty": None}


def main():
    checks = [item for group in GATES.values() for item in group]
    names = "^(" + "|".join(sorted({re.escape(name) for _, name in checks})) + ")$"
    command = ["go", "test", "-json", "-count=1", "-timeout=60s", "-run", names]
    command += sorted({"./" + package_path(package) for package, _ in checks})
    output = ROOT / "work"
    output.mkdir(exist_ok=True)
    (output / "release-gates.go.jsonl").write_text("")
    report = {"schema": 1, "scope": "experimental-contracts", "source": revision(), "command": command}
    try:
        process = subprocess.run(command, cwd=ROOT, text=True, capture_output=True,
                                 timeout=300, env={**os.environ, "CGO_ENABLED": "0"})
        (output / "release-gates.go.jsonl").write_text(process.stdout)
        events = [json.loads(line) for line in process.stdout.splitlines() if line.strip()]
        if not all(isinstance(event, dict) for event in events):
            raise ValueError("invalid Go test event")
        report.update(evaluate(events, process.returncode))
        report["exit_code"] = process.returncode
        if process.stderr:
            print(process.stderr, file=sys.stderr)
        if not report["passed"]:
            for event in events:
                if event.get("Output"):
                    print(event["Output"], end="", file=sys.stderr)
    except (OSError, ValueError, subprocess.TimeoutExpired) as error:
        report.update(evaluate([], 1))
        report["error"] = str(error)
    (output / "release-gates.json").write_text(json.dumps(report, indent=2) + "\n")
    for gate, result in report["gates"].items():
        print(f"{gate}: {'PASS' if result['passed'] else 'FAIL'}")
        for name, status in result["tests"].items():
            if status != "pass":
                print(f"  {name}: {status}")
    if "error" in report:
        print(report["error"], file=sys.stderr)
    print("Evidence: work/release-gates.json and work/release-gates.go.jsonl")
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
