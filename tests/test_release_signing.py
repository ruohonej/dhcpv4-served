import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class ReleaseSigningTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.assets = self.root / "assets"
        self.assets.mkdir()
        (self.assets / "binary").write_bytes(b"payload")
        (self.assets / "binary.cdx.json").write_text("{}")
        self.env = dict(os.environ, GITHUB_REF_NAME="v1.2.3", GITHUB_SHA="a" * 40)

    def test_manifest_binds_staged_files_and_source(self):
        subprocess.run(["python3", str(ROOT / "scripts/create_release_manifest.py"), str(self.assets)], env=self.env, check=True)
        manifest = json.loads((self.assets / "release-manifest.json").read_text())
        self.assertEqual(manifest["source_sha"], "a" * 40)
        self.assertEqual(manifest["version"], "v1.2.3")
        self.assertEqual({entry["name"]: entry["sha256"] for entry in manifest["artifacts"]}, {
            "binary": hashlib.sha256(b"payload").hexdigest(),
            "binary.cdx.json": hashlib.sha256(b"{}").hexdigest(),
        })
        result = subprocess.run(["python3", str(ROOT / "scripts/create_release_manifest.py"), str(self.assets)], env=self.env, capture_output=True)
        self.assertNotEqual(result.returncode, 0)

    def fake_cosign(self):
        bin_dir = self.root / "bin"
        bin_dir.mkdir()
        cosign = bin_dir / "cosign"
        cosign.write_text('''#!/usr/bin/env python3
import os, pathlib, sys
args = sys.argv[1:]
with open(os.environ["TEST_LOG"], "a") as log:
    log.write(" ".join(args) + "\\n")
if args[0] == "sign-blob":
    pathlib.Path(args[args.index("--bundle") + 1]).write_text("bundle")
elif os.environ.get("TEST_FAIL_VERIFY"):
    sys.exit(1)
''')
        cosign.chmod(0o755)
        self.env.update(PATH=str(bin_dir) + os.pathsep + self.env["PATH"], TEST_LOG=str(self.root / "calls"))

    def test_signs_each_file_and_checks_exact_identity(self):
        self.fake_cosign()
        subprocess.run([str(ROOT / "scripts/sign_release_assets.sh"), str(self.assets)], env=self.env, check=True)
        calls = (self.root / "calls").read_text().splitlines()
        self.assertEqual(len(calls), 4)
        self.assertEqual(sum(line.startswith("sign-blob ") for line in calls), 2)
        for line in calls:
            if line.startswith("verify-blob "):
                self.assertIn("--certificate-oidc-issuer https://token.actions.githubusercontent.com", line)
                self.assertIn("--certificate-identity https://github.com/ruohonej/dhcpv4-served/.github/workflows/release.yml@refs/tags/v1.2.3", line)
        self.assertTrue((self.assets / "binary.sigstore.json").is_file())
        result = subprocess.run([str(ROOT / "scripts/sign_release_assets.sh"), str(self.assets)], env=self.env, capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(len((self.root / "calls").read_text().splitlines()), 4)

    def test_verification_failure_stops_signing(self):
        self.fake_cosign()
        self.env["TEST_FAIL_VERIFY"] = "1"
        result = subprocess.run([str(ROOT / "scripts/sign_release_assets.sh"), str(self.assets)], env=self.env, capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(len((self.root / "calls").read_text().splitlines()), 2)


if __name__ == "__main__":
    unittest.main()
