import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("policy", Path(__file__).resolve().parents[1] / "scripts/check_release_policy.py")
policy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(policy)


class ReleasePolicyTests(unittest.TestCase):
    public_tag_push = {
        "GITHUB_REPOSITORY": "ruohonej/dhcpv4-served",
        "GITHUB_EVENT_NAME": "push",
        "GITHUB_REF": "refs/tags/v1.2.3-rc.1",
        "GITHUB_WORKFLOW_REF": "ruohonej/dhcpv4-served/.github/workflows/release.yml@refs/tags/v1.2.3-rc.1",
        "REPOSITORY_VISIBILITY": "public",
        "REF_PROTECTED": "true",
    }

    def test_only_protected_version_pushes_in_canonical_repository_pass(self):
        env = self.public_tag_push
        policy.check(env)
        for key, value in (("GITHUB_REPOSITORY", "attacker/dhcpv4-served"), ("GITHUB_EVENT_NAME", "pull_request"), ("GITHUB_REF", "refs/heads/main"), ("GITHUB_REF", "refs/tags/vanything"), ("REF_PROTECTED", "false")):
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                policy.check(dict(env, **{key: value}))

    def test_only_canonical_release_workflow_can_call_builder(self):
        for workflow in ("other.yml@refs/tags/v1.2.3-rc.1", "release.yml@refs/heads/main"):
            with self.subTest(workflow=workflow), self.assertRaisesRegex(ValueError, "canonical caller workflow"):
                policy.check(dict(self.public_tag_push, GITHUB_WORKFLOW_REF=f"ruohonej/dhcpv4-served/.github/workflows/{workflow}"))

    def test_private_or_unknown_repository_visibility_is_rejected(self):
        for status in ("private", "internal", "false", ""):
            with self.subTest(status=status), self.assertRaisesRegex(ValueError, "to be public"):
                policy.check(dict(self.public_tag_push, REPOSITORY_VISIBILITY=status))

        env = self.public_tag_push.copy()
        del env["REPOSITORY_VISIBILITY"]
        with self.assertRaisesRegex(ValueError, "to be public"):
            policy.check(env)

    def test_tag_policy_uses_fetched_history_without_network_credentials(self):
        with tempfile.TemporaryDirectory() as directory:
            def git(*args):
                return subprocess.check_output(["git", "-c", "user.name=Release Test",
                    "-c", "user.email=release@example.invalid", *args], cwd=directory,
                    stderr=subprocess.DEVNULL, text=True).strip()
            git("init", "--object-format=sha1")
            git("commit", "--allow-empty", "-m", "reviewed")
            reviewed = git("rev-parse", "HEAD")
            git("update-ref", "refs/remotes/origin/main", reviewed)
            # Any attempt to fetch again would fail: only the authenticated
            # checkout's local history is available to the policy step.
            git("remote", "add", "origin", "http://127.0.0.1:1/private-repo")
            env = dict(os.environ, **self.public_tag_push,
                       GITHUB_SHA=reviewed, GIT_TERMINAL_PROMPT="0")
            command = ["python3", str(Path(policy.__file__).resolve())]
            subprocess.run(command, cwd=directory, env=env, check=True, capture_output=True)
            git("commit", "--allow-empty", "-m", "not on reviewed main")
            env["GITHUB_SHA"] = git("rev-parse", "HEAD")
            result = subprocess.run(command, cwd=directory, env=env, capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            env["GITHUB_SHA"] = "--help"
            result = subprocess.run(command, cwd=directory, env=env, capture_output=True)
            self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
