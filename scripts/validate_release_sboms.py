#!/usr/bin/env python3
"""Check binary SBOM coverage and bind each inventory to its release binary."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys


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
    for line in lines[1:]:
        fields = line.split()
        if fields and fields[0] == "=>":
            raise ValueError("module replacements need explicit SBOM review")
        if fields and fields[0] == "dep":
            if len(fields) < 3 or (fields[1], fields[2]) not in components:
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
