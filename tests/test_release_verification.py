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
asset = Path(args[-1]).name
negative = "positive"
if tool == "gh":
    signer_sha = os.environ["PROVENANCE_SIGNER_SHA"]
    signer = args[args.index("--signer-workflow") + 1]
    digest = args[args.index("--signer-digest") + 1]
    workflow = "ruohonej/dhcpv4-served/.github/workflows/release-build.yml"
    if signer == f"{workflow}-wrong@{signer_sha}":
        negative = "identity"
    elif signer != f"{workflow}@{signer_sha}":
        sys.exit("unexpected signer workflow")
    elif digest != signer_sha:
        negative = "wrong-signer-digest"
elif args[args.index("--certificate-identity") + 1].endswith("-wrong"):
    negative = "identity"
if asset == "modified-binary":
    negative = "modified"
label = negative
if tool == "gh" and negative == "positive" and asset != "dhcpv4-served-linux-amd64":
    label = asset
target = tool + ":" + label
calls = Path(os.environ["CALLS"])
with calls.open("a") as f:
    f.write(target + "\\n")
if target == os.environ.get("FAIL_AT") or (os.environ.get("FAIL_CONTROL") and negative == "positive" and len(calls.read_text().splitlines()) > 1):
    print(os.environ.get("ERROR", "temporary network/credential service failure"))
    sys.exit(int(os.environ.get("STATUS", "1")))
if negative == "positive":
    sys.exit(0)
if tool == "gh":
    marker = "✗ Sigstore verification failed"
    diagnostic = 'Error: verifying with issuer "sigstore.dev"'
    if negative == "wrong-signer-digest":
        marker = "✗ Policy verification failed"
        diagnostic = f"Error: expected BuildSignerDigest to be {digest}, got {signer_sha}"
    if os.environ.get("GH_FORCE_TTY"):
        if not os.environ.get("NO_COLOR"):
            marker = "\\x1b[31m" + marker + "\\x1b[0m"
        print(marker)
    print(diagnostic)
elif negative == "modified":
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
        self.deb = "dhcpv4-served_1.2.3_linux_amd64.deb"
        asset_names = ("dhcpv4-served-linux-amd64", self.deb, "checksums.txt")
        for name in asset_names:
            (self.assets / name).write_bytes(name.encode())
        self.manifest = self.assets / "release-manifest.json"
        self.manifest.write_text(json.dumps({"artifacts": [{"name": name} for name in asset_names]}))
        for name in ("gh", "cosign"):
            executable = bins / name
            executable.write_text(FAKE)
            executable.chmod(0o755)
        self.env = dict(os.environ, PATH=str(bins) + os.pathsep + os.environ["PATH"], GH_FORCE_TTY="", NO_COLOR="",
                        GITHUB_REF_NAME="v1.2.3", GITHUB_SHA="a" * 40, PROVENANCE_SIGNER_SHA="b" * 40,
                        CALLS=str(self.root / "calls"))

    def run_gate(self, **env):
        (self.root / "calls").unlink(missing_ok=True)
        return subprocess.run([str(ROOT / "scripts/test_release_verification.sh"),
                               str(self.assets), str(self.evidence)],
                              env=dict(self.env, **env), capture_output=True, text=True)

    def test_requires_recognized_rejections_and_positive_controls(self):
        result = self.run_gate()
        self.assertEqual(result.returncode, 0, result.stderr)
        results = list(self.evidence.glob("*.result.json"))
        self.assertEqual(len(results), 15)
        self.assertTrue(all(json.loads(p.read_text())["accepted"] for p in results))
        self.assertEqual((self.root / "calls").read_text().splitlines(), [
            "cosign:positive", "cosign:modified", "cosign:positive", "cosign:identity", "cosign:positive",
            "gh:positive", "gh:modified", "gh:positive", "gh:identity", "gh:positive",
            "gh:wrong-signer-digest", "gh:positive",
            f"gh:{self.deb}", "gh:checksums.txt", f"gh:{self.manifest.name}"])
        self.assertFalse((self.evidence / "modified-binary").exists())

    def test_each_artifact_requires_provenance(self):
        for name in (self.deb, "checksums.txt", self.manifest.name):
            with self.subTest(name=name):
                result = self.run_gate(FAIL_AT=f"gh:{name}", ERROR="No provenance for artifact")
                self.assertNotEqual(result.returncode, 0)
                record = self.evidence / f"provenance-artifact-{name}.result.json"
                self.assertFalse(json.loads(record.read_text())["accepted"])

    def test_manifest_must_be_readable(self):
        self.manifest.unlink()
        self.assertNotEqual(self.run_gate().returncode, 0)

    def test_operational_errors_cannot_satisfy_any_negative(self):
        for target in ("cosign:modified", "cosign:identity", "gh:modified", "gh:identity", "gh:wrong-signer-digest"):
            for status in ("1", "2", "42", "124", "137"):
                with self.subTest(target=target, status=status):
                    result = self.run_gate(FAIL_AT=target, STATUS=status)
                    self.assertNotEqual(result.returncode, 0)
                    name = target.replace("gh:", "provenance-").replace("cosign:", "cosign-").replace("-identity", "-wrong-identity")
                    recorded = json.loads((self.evidence / (name + ".result.json")).read_text())
                    self.assertFalse(recorded["accepted"])
                    self.assertTrue((self.evidence / "policy.txt").exists())
                    self.assertFalse((self.evidence / "modified-binary").exists())

    def test_zero_exit_does_not_satisfy_negative(self):
        self.assertNotEqual(self.run_gate(FAIL_AT="cosign:modified", STATUS="0").returncode, 0)

    def test_positive_and_after_negative_controls_must_pass(self):
        for env in ({"FAIL_AT": "cosign:positive"}, {"FAIL_AT": "gh:positive"}, {"FAIL_CONTROL": "1"}):
            with self.subTest(env=env):
                self.assertNotEqual(self.run_gate(**env).returncode, 0)
                if "FAIL_CONTROL" in env:
                    self.assertEqual((self.root / "calls").read_text().splitlines(),
                                     ["cosign:positive", "cosign:modified", "cosign:positive"])

    def test_rejection_text_with_abnormal_status_does_not_count(self):
        for target, error in (
            ("cosign:modified", "Error: failed to verify signature: could not verify message: invalid signature when validating ASN.1 encoded signature"),
            ("gh:modified", '✗ Sigstore verification failed\nError: verifying with issuer "sigstore.dev"'),
        ):
            with self.subTest(target=target):
                self.assertNotEqual(self.run_gate(FAIL_AT=target, STATUS="42", ERROR=error).returncode, 0)

    def test_wrong_cosign_rejection_reason_does_not_count(self):
        self.assertNotEqual(self.run_gate(
            FAIL_AT="cosign:identity",
            ERROR="Error: failed to verify signature: could not verify message: invalid signature when validating ASN.1 encoded signature").returncode, 0)

    def test_generic_or_incomplete_verification_messages_do_not_count(self):
        for error in ("verification failed", "✗ Sigstore verification failed",
                      'Error: verifying with issuer "sigstore.dev"',
                      '✗ Sigstore verification failed\nError: failed to get trusted root',
                      '✗ Sigstore verification failed\nError: verifying with issuer "unknown"',
                      '✗ Sigstore verification failed\nError: verifying with issuer "GitHub, Inc."'):
            with self.subTest(error=error):
                self.assertNotEqual(self.run_gate(FAIL_AT="gh:modified", ERROR=error).returncode, 0)


if __name__ == "__main__":
    unittest.main()
