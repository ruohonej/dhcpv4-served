#!/usr/bin/env bash
# Stage exactly the outputs that will be attested and published.
set -euo pipefail
shopt -s nullglob

dist=${1:-dist}
out=${2:-release-assets}
[ ! -e "$out" ] || { echo "Output already exists: $out" >&2; exit 1; }
archives=("$dist"/*.tar.gz)
debs=("$dist"/*.deb)
binaries=("$dist"/*_linux_amd64*/dhcpv4-served)
[ "${#archives[@]}" -eq 1 ] && [ "${#debs[@]}" -eq 1 ] && [ "${#binaries[@]}" -eq 1 ] && [ -f "${binaries[0]}" ] && [ -f "$dist/checksums.txt" ] || {
  echo 'Expected one archive, DEB, linux/amd64 binary and checksums' >&2; exit 1;
}
utilities=("$dist"/*_linux_amd64*/dhcpv4-srvctl)
[ "${#utilities[@]}" -eq 1 ] && [ -f "${utilities[0]}" ] || { echo "Expected srvctl binary" >&2; exit 1; }
mkdir -p "$out"
cp "${archives[0]}" "${debs[0]}" "$dist/checksums.txt" "$out/"
cp "${binaries[0]}" "$out/dhcpv4-served-linux-amd64"
cp "${utilities[0]}" "$out/dhcpv4-srvctl-linux-amd64"
