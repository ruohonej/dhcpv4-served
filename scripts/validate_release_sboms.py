#!/usr/bin/env python3
"""Check binary SBOM coverage and bind each inventory to its release binary."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys


# This replacement is pinned in go.mod and documented in NOTICE.
VARLINK_VERSION = "v2.0.0-20260611234345-b30f18e21e83"
REVIEWED_REPLACEMENT = (("github.com/varlink/go/v2", VARLINK_VERSION),
                        ("github.com/noxiouz/go/v2", VARLINK_VERSION))


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def validate(binary, sbom, build_info):
    lines = build_info.splitlines()
    if not lines or ": " not in lines[0]:
        raise ValueError("missing Go build information")
    toolchain = lines[0].rsplit(": ", 1)[1]
    if not toolchain.startswith("go1."):
        raise ValueError("unrecognised Go toolchain")
    components = {(c.get("name"), c.get("version")) for c in sbom.get("components", [])}
    if ("stdlib", toolchain) not in components:
        raise ValueError("SBOM missing Go standard library version " + toolchain)
    for index, line in enumerate(lines[1:], start=1):
        fields = line.split()
        if fields[:1] == ["=>"]:
            original = lines[index - 1].split()
            module = tuple(fields[1:3])
            if original[:1] != ["dep"] or (tuple(original[1:3]), module) != REVIEWED_REPLACEMENT:
                raise ValueError("module replacements need explicit SBOM review")
        elif fields[:1] == ["dep"]:
            if index + 1 < len(lines) and lines[index + 1].split()[:1] == ["=>"]:
                continue
            module = tuple(fields[1:3])
        else:
            continue
        if module not in components:
            raise ValueError("SBOM missing embedded module: " + line.strip())
    if sbom.get("bomFormat") != "CycloneDX":
        raise ValueError("not a CycloneDX SBOM")
    subject = sbom.get("metadata", {}).get("component", {})
    if subject.get("version") != "sha256:" + digest(binary):
        raise ValueError("SBOM subject digest does not match binary")
    return toolchain


def main():
    assets = Path(sys.argv[1] if len(sys.argv) > 1 else "release-assets")
    version = os.environ["GITHUB_REF_NAME"]
    source = os.environ["GITHUB_SHA"]
    entries = []
    for arch in ("amd64",):
        binary = assets / ("dhcpv4-served-linux-" + arch)
        sbom_path = assets / (binary.name + ".cdx.json")
        sbom = json.loads(sbom_path.read_text())
        info = subprocess.check_output(["go", "version", "-m", str(binary)], text=True)
        toolchain = validate(binary, sbom, info)
        entries.append({"binary": binary.name, "binary_sha256": digest(binary),
                        "sbom": sbom_path.name, "sbom_sha256": digest(sbom_path),
                        "go_toolchain": toolchain})
    (assets / "sbom-bindings.json").write_text(json.dumps({
        "version": version, "source_sha": source, "inventories": entries,
    }, indent=2) + "\n")


if __name__ == "__main__":
    main()
