import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]

# Model pinned verifier diagnostics. Live signing/root integration remains a
# separate candidate-release requirement.
FAKE = '''#!/usr/bin/env python3
import os, sys
from pathlib import Path
args = sys.argv[1:]
tool = Path(sys.argv[0]).name
negative = "modified" if any("modified-binary" in a for a in args) else "identity" if any(a.endswith("-wrong") for a in args) else "positive"
calls = Path(os.environ["CALLS"])
with calls.open("a") as f:
    f.write(tool + ":" + negative + "\\n")
target = tool + ":" + negative
if target == os.environ.get("FAIL_AT") or (os.environ.get("FAIL_CONTROL") and negative == "positive" and len(calls.read_text().splitlines()) > 1):
    print(os.environ.get("ERROR", "temporary network/credential service failure"))
    sys.exit(int(os.environ.get("STATUS", "1")))
if negative == "positive":
    sys.exit(0)
if negative == "modified":
    print("Error: failed to verify signature: could not verify message: invalid signature when validating ASN.1 encoded signature")
else:
    identity = args[args.index("--certificate-identity") + 1]
    print(f'Error: failed to verify certificate identity: no matching CertificateIdentity found, last error: expected SAN value "{identity}", got "{identity[:-6]}"')
sys.exit(1)
'''


class VerificationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.assets, bins, self.evidence = [self.root / p for p in ("assets", "bin", "evidence")]
        self.assets.mkdir()
        bins.mkdir()
        (self.assets / "dhcpv4-served-linux-amd64").write_bytes(b"binary")
        executable = bins / "cosign"
        executable.write_text(FAKE)
        executable.chmod(0o755)
        self.env = dict(os.environ, PATH=str(bins) + os.pathsep + os.environ["PATH"],
                        GITHUB_REF_NAME="v1.2.3", GITHUB_SHA="a" * 40, CALLS=str(self.root / "calls"))

    def run_gate(self, **env):
        (self.root / "calls").unlink(missing_ok=True)
        return subprocess.run([str(ROOT / "scripts/test_release_verification.sh"),
                               str(self.assets), str(self.evidence)],
                              env=dict(self.env, **env), capture_output=True, text=True)

    def test_requires_recognized_rejections_and_positive_controls(self):
        result = self.run_gate()
        self.assertEqual(result.returncode, 0, result.stderr)
        results = list(self.evidence.glob("*.result.json"))
        self.assertEqual(len(results), 5)
        self.assertTrue(all(json.loads(p.read_text())["accepted"] for p in results))
        self.assertEqual((self.root / "calls").read_text().splitlines(), [
            "cosign:positive", "cosign:modified", "cosign:positive", "cosign:identity", "cosign:positive"])
        self.assertFalse((self.evidence / "modified-binary").exists())

    def test_operational_errors_cannot_satisfy_any_negative(self):
        for target in ("cosign:modified", "cosign:identity"):
            for status in ("1", "2", "42", "124", "137"):
                with self.subTest(target=target, status=status):
                    result = self.run_gate(FAIL_AT=target, STATUS=status)
                    self.assertNotEqual(result.returncode, 0)
                    name = target.replace("cosign:", "cosign-").replace("-identity", "-wrong-identity")
                    recorded = json.loads((self.evidence / (name + ".result.json")).read_text())
                    self.assertFalse(recorded["accepted"])
                    self.assertTrue((self.evidence / "policy.txt").exists())
                    self.assertFalse((self.evidence / "modified-binary").exists())

    def test_zero_exit_does_not_satisfy_negative(self):
        self.assertNotEqual(self.run_gate(FAIL_AT="cosign:modified", STATUS="0").returncode, 0)

    def test_positive_and_after_negative_controls_must_pass(self):
        for env in ({"FAIL_AT": "cosign:positive"}, {"FAIL_CONTROL": "1"}):
            with self.subTest(env=env):
                self.assertNotEqual(self.run_gate(**env).returncode, 0)
                if "FAIL_CONTROL" in env:
                    self.assertEqual((self.root / "calls").read_text().splitlines(),
                                     ["cosign:positive", "cosign:modified", "cosign:positive"])

    def test_rejection_text_with_abnormal_status_does_not_count(self):
        result = self.run_gate(
            FAIL_AT="cosign:modified", STATUS="42",
            ERROR="Error: failed to verify signature: could not verify message: invalid signature when validating ASN.1 encoded signature")
        self.assertNotEqual(result.returncode, 0)

    def test_wrong_cosign_rejection_reason_does_not_count(self):
        self.assertNotEqual(self.run_gate(
            FAIL_AT="cosign:identity",
            ERROR="Error: failed to verify signature: could not verify message: invalid signature when validating ASN.1 encoded signature").returncode, 0)


if __name__ == "__main__":
    unittest.main()
