"""Check the production DEB's payload and control archive before installation."""
import hashlib
from io import BytesIO
import json
from pathlib import Path
import subprocess
import sys
import tarfile


PAYLOAD = {
    'usr/libexec/dhcpv4-served': 0o755,
    'usr/lib/systemd/system/dhcpv4-served@.service': 0o644,
    'usr/lib/systemd/system/dhcpv4-served@.socket': 0o644,
    'usr/share/doc/dhcpv4-served/LICENSE': 0o644,
    'usr/share/doc/dhcpv4-served/NOTICE': 0o644,
}
CONTROL = {'control': 0o644, 'md5sums': 0o644}


def archive(package, option, expected):
    expected_dirs = {str(parent) for name in expected for parent in Path(name).parents}
    entries = {}
    data = subprocess.check_output(['dpkg-deb', option, package])
    with tarfile.open(fileobj=BytesIO(data)) as tar:
        for entry in tar:
            name = entry.name.removeprefix('./')
            if entry.isdir() and name in expected_dirs and entry.mode == 0o755 and entry.uid == entry.gid == 0:
                continue
            if (not entry.isfile() or name in entries or expected.get(name) != entry.mode
                    or entry.uid != 0 or entry.gid != 0):
                raise ValueError(f'Unexpected {option} entry: {entry.name} ({entry.mode:o})')
            entries[name] = f'{entry.mode:04o}'
    if expected.keys() != entries.keys():
        raise ValueError(f'Missing {option} entries: {sorted(expected.keys() - entries.keys())}')
    return entries


def inspect(package):
    metadata = subprocess.check_output(['dpkg-deb', '-f', package], text=True)
    relationships = {'pre-depends', 'depends', 'recommends', 'suggests'}
    for line in metadata.splitlines():
        if line.split(':', 1)[0].lower() in relationships:
            raise ValueError(f'Unexpected package relationship: {line}')
    return {
        'sha256': hashlib.sha256(package.read_bytes()).hexdigest(),
        'metadata': metadata,
        'payload': archive(package, '--fsys-tarfile', PAYLOAD),
        'control': archive(package, '--ctrl-tarfile', CONTROL),
    }


if __name__ == '__main__':
    try:
        print(json.dumps(inspect(Path(sys.argv[1])), indent=2))
    except ValueError as error:
        raise SystemExit(str(error))
