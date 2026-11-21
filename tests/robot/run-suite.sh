#!/bin/bash
# Runs inside the dedicated namespace created by tests/acceptance.
set -euo pipefail
suite=${1:?expected a Robot suite}
output=${2:?expected an output directory}
[[ $(id -u) == 0 && $(xargs </proc/self/uid_map) == '0 0 65536' ]] || {
    echo 'Expected the dedicated mapped user namespace' >&2; exit 1;
}
shift 2
# Each host-launched run owns a fresh directory. Return root-created captures
# and logs to the caller, including on a failed Robot run.
if [[ $output == */work/acceptance/*/run-* && ${SUDO_UID:-} =~ ^[0-9]+$ && ${SUDO_GID:-} =~ ^[0-9]+$ ]]; then
    trap 'chown -hR -- "$SUDO_UID:$SUDO_GID" "$output"' EXIT
fi
if [[ $suite == fuzz ]]; then
    bash tests/robot/run-fuzz.sh --output "$output" "$@"
    exit
fi
mount --make-rprivate /
mount -t tmpfs -o mode=0755,nosuid,nodev tmpfs /tmp
export DHCP_STARTUP_ROOT_HARNESS=1
bash tests/robot/namespace-robot.sh work/dhcpv4-served --outputdir "$output" \
    --variable "FIXTURE_OUTPUT:${1:-$output/fixtures}" "tests/robot/suites/$suite.robot"
