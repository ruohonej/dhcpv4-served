#!/usr/bin/env python3
"""Record digests of the staged release outputs before attestation and signing."""
import hashlib
import json
import os
from pathlib import Path
import re
import sys


def main():
    assets = Path(sys.argv[1] if len(sys.argv) > 1 else "release-assets")
    version = os.environ["GITHUB_REF_NAME"]
    source = os.environ["GITHUB_SHA"]
    if not version.startswith("v") or not re.fullmatch(r"[0-9a-f]{40}", source):
        raise ValueError("expected a version tag and a full source SHA")
    files = sorted(assets.iterdir())
    if not files or any(not item.is_file() or item.is_symlink() for item in files):
        raise ValueError("expected only regular staged files")
    if (assets / "release-manifest.json").exists():
        raise ValueError("manifest already exists")
    entries = [{"name": file.name, "sha256": hashlib.sha256(file.read_bytes()).hexdigest()}
               for file in files]
    (assets / "release-manifest.json").write_text(json.dumps({
        "version": version, "source_sha": source, "artifacts": entries,
    }, indent=2) + "\n")


if __name__ == "__main__":
    main()
