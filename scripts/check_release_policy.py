#!/usr/bin/env python3
"""Fail closed before a tag-triggered release acquires publishing permissions."""
import os
import re
import subprocess


def check(env):
    if env.get("GITHUB_REPOSITORY") != "ruohonej/dhcpv4-served":
        raise ValueError("release repository is not authorized")
    if env.get("GITHUB_EVENT_NAME") != "push":
        raise ValueError("release requires a push event")
    ref = env.get("GITHUB_REF", "")
    # Stable and prerelease SemVer tags, without build metadata.
    if not re.fullmatch(r"refs/tags/v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?", ref):
        raise ValueError("release requires a version tag")
    if env.get("REF_PROTECTED") != "true":
        raise ValueError("release tag is not covered by an active protection rule")


def check_main_history(env, cwd=None):
    source = env.get("GITHUB_SHA", "")
    if not re.fullmatch(r"[0-9a-f]{40}", source):
        raise ValueError("release requires a full source SHA")
    # checkout fetch-depth: 0 already fetched all branches using its scoped
    # credential. Do not refetch after persist-credentials: false removed it.
    subprocess.run(["git", "merge-base", "--is-ancestor", source,
                    "refs/remotes/origin/main"], cwd=cwd, check=True)


if __name__ == "__main__":
    check(os.environ)
    check_main_history(os.environ)
