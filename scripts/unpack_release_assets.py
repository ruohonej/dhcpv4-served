#!/usr/bin/env python3
"""Copy the expected release files from the build artifact into a new directory."""
from pathlib import Path
import re
import shutil
import sys
from zipfile import ZipFile


def unpack(incoming, assets):
    archives = list(incoming.iterdir())
    if len(archives) != 1 or not archives[0].is_file():
        raise ValueError("expected one downloaded build artifact")

    required = {
        "checksums.txt",
        "dhcpv4-served-linux-amd64",
        "dhcpv4-served-linux-amd64.cdx.json",
        "dhcpv4-srvctl-linux-amd64",
        "dhcpv4-srvctl-linux-amd64.cdx.json",
        "sbom-bindings.json",
    }
    package_name = r"dhcpv4-served_[0-9A-Za-z._~+-]+"
    with ZipFile(archives[0]) as archive:
        members = archive.infolist()
        names = {member.filename for member in members}
        packages = names - required
        if (len(members) != len(required) + 2 or len(names) != len(members)
                or not required.issubset(names)
                or sum(re.fullmatch(package_name + r"\.deb", name) is not None for name in packages) != 1
                or sum(re.fullmatch(package_name + r"\.tar\.gz", name) is not None for name in packages) != 1):
            raise ValueError("build artifact has unexpected release files")

        assets.mkdir()
        for member in members:
            with archive.open(member) as source, (assets / member.filename).open("xb") as destination:
                shutil.copyfileobj(source, destination)


if __name__ == "__main__":
    unpack(Path(sys.argv[1]), Path(sys.argv[2]))
