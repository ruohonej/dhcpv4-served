import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
REPO = "ruohonej/dhcpv4-served"
SOURCE_SHA = "a" * 40

FAKE_GH = '''#!/usr/bin/env python3
import json
import os
import sys

with open(os.environ["GH_CALLS"], "a") as calls:
    calls.write(json.dumps(sys.argv[1:]) + "\\n")
if sys.argv[1] == "api":
    print(os.environ["REMOTE_SHA"])
    sys.exit(int(os.environ["API_STATUS"]))
'''


class PublishReleaseTests(unittest.TestCase):
    def setUp(self):
        workspace = tempfile.TemporaryDirectory()
        self.addCleanup(workspace.cleanup)
        self.workspace = Path(workspace.name)
        assets = self.workspace / "release-assets"
        assets.mkdir()
        (assets / "dhcpv4-served-linux-amd64").touch()
        gh = self.workspace / "gh"
        gh.write_text(FAKE_GH)
        gh.chmod(0o755)
        self.calls = self.workspace / "calls.jsonl"

    def publish(self, tag, remote_sha=SOURCE_SHA, api_status=0):
        self.calls.unlink(missing_ok=True)
        env = dict(os.environ, PATH=str(self.workspace) + os.pathsep + os.environ["PATH"],
                   GITHUB_REPOSITORY=REPO, GITHUB_REF_NAME=tag, GITHUB_SHA=SOURCE_SHA,
                   REMOTE_SHA=remote_sha, API_STATUS=str(api_status), GH_CALLS=str(self.calls))
        result = subprocess.run([str(ROOT / "scripts/publish_release.sh")],
                                cwd=self.workspace, env=env, capture_output=True, text=True)
        calls = [json.loads(line) for line in self.calls.read_text().splitlines()]
        self.assertEqual(calls[0], ["api", f"repos/{REPO}/commits/tags/{tag}", "--jq", ".sha"])
        return result, calls[1:]

    def test_version_tags_publish_with_correct_prerelease_status(self):
        for tag, flags in (("v1.2.3", []), ("v1.2.3-rc.1", ["--prerelease"])):
            with self.subTest(tag=tag):
                result, calls = self.publish(tag)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(calls, [["release", "create", tag, "release-assets/dhcpv4-served-linux-amd64",
                                          "--repo", REPO, "--verify-tag", "--generate-notes", *flags]])

    def test_tag_resolution_failure_or_mismatch_prevents_publication(self):
        for remote_sha, api_status in (("b" * 40, 0), ("", 0), ("", 1), (SOURCE_SHA, 1)):
            with self.subTest(remote_sha=remote_sha, api_status=api_status):
                result, calls = self.publish("v1.2.3", remote_sha, api_status)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(calls, [])


if __name__ == "__main__":
    unittest.main()
