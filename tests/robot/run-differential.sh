#!/bin/bash
# Run inside a fresh mapped user and network namespace.
set -euo pipefail

[[ $(id -u) == 0 && $(ip -o link show | cut -d: -f2) == ' lo' ]] || {
    echo 'Expected a fresh mapped user and network namespace' >&2
    exit 1
}
export DHCP_STARTUP_ROOT_HARNESS=1
PYTHONPATH=tests/robot work/venv/bin/python -c \
    'from harness.fixtures import namespace_check; namespace_check(require_writable_proc=True)'
# A preconfigured private, root-owned /tmp can also satisfy the worker's
# trusted configuration path check.
if [[ $(stat -c '%u:%a' /tmp) != '0:755' ]]; then
    mount --make-rprivate /
    mount -t tmpfs -o mode=0755,nosuid,nodev tmpfs /tmp
fi

mkdir -p -m 755 work/differential
output=$(mktemp -d work/differential/run-XXXXXX)
if [[ ${SUDO_UID:-} =~ ^[0-9]+$ && ${SUDO_GID:-} =~ ^[0-9]+$ ]]; then
    return_artifacts() {
        local status=$?
        if ! chown -hR -- "+$SUDO_UID:+$SUDO_GID" "$output" && [[ $status == 0 ]]; then
            status=1
        fi
        exit "$status"
    }
    trap return_artifacts EXIT
fi
echo "Differential test artifacts: $output"
dnsmasq --version > "$output/dnsmasq-version.txt"

status=0
for server in go dnsmasq; do
    bash tests/robot/namespace-robot.sh work/dhcpv4-served --include differential \
        --outputdir "$output/$server/robot" \
        --variable "BACKEND:differential-$server" \
        --variable "FIXTURE_OUTPUT:$output/$server" \
        tests/robot/suites/lease_delivery.robot || status=1
done
if [[ $status == 0 ]]; then
    diff -ru "$output/go/comparison" "$output/dnsmasq/comparison" | tee "$output/comparison.diff" || status=1
fi
exit "$status"
