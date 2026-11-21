#!/bin/bash
# Run inside the dedicated mapped user and network namespace used by CI.
set -euo pipefail
[[ $(id -u) == 0 && $(cat /proc/self/uid_map | xargs) == '0 0 65536' ]] || {
    echo 'Expected the dedicated mapped user namespace' >&2; exit 1;
}
worker=work/dhcpv4-served
output=work/fuzz-dhcp
replay=tests/robot/data/fuzz-replay.json
examples=4
packet_replay=
run_replay=0
run_generated=0
run_packet_replay=0
if [[ $# == 0 ]]; then
    run_replay=1
    run_generated=1
fi
while [[ $# -gt 0 ]]; do
    if [[ $# -lt 2 ]]; then
        echo "Missing value for $1" >&2
        exit 2
    fi
    case "$1" in
        --worker) worker=$2 ;;
        --output) output=$2 ;;
        --replay) replay=$2; run_replay=1 ;;
        --examples) examples=$2; run_generated=1 ;;
        --packet-replay) packet_replay=$2; run_packet_replay=1 ;;
        *) echo "Unknown argument: $1" >&2; exit 2 ;;
    esac
    shift 2
done
if [[ $run_replay == 0 && $run_generated == 0 && $run_packet_replay == 0 ]]; then
    run_replay=1
    run_generated=1
fi
mount --make-rprivate /
mount -t tmpfs -o mode=0755,nosuid,nodev tmpfs /tmp
export DHCP_STARTUP_ROOT_HARNESS=1
selection=()
if [[ $run_replay == 1 ]]; then
    selection+=(--test 'Replay DHCP sequence')
fi
if [[ $run_generated == 1 ]]; then
    selection+=(--test 'Generate DHCP sequences' --test 'Fuzz DHCP packet fields')
fi
if [[ $run_packet_replay == 1 ]]; then
    selection+=(--test 'Replay DHCP packet sequence')
fi
# Keep reports from different test selections in separate directories.
result_dir="$output/robot"
if [[ $run_replay == 1 && $run_generated == 0 ]]; then
    result_dir="$output/robot-replay"
elif [[ $run_generated == 1 && $run_replay == 0 ]]; then
    result_dir="$output/robot-generated"
fi
if [[ $run_packet_replay == 1 ]]; then
    if [[ $run_replay == 0 && $run_generated == 0 ]]; then
        result_dir="$output/robot-packet-replay"
    else
        result_dir+="-with-packet-replay"
    fi
fi
exec bash tests/robot/namespace-robot.sh "$worker" --outputdir "$result_dir" \
    --variable "FUZZ_OUTPUT:$output" \
    --variable "REPLAY:$replay" --variable "EXAMPLES:$examples" \
    --variable "PACKET_REPLAY:$packet_replay" \
    "${selection[@]}" tests/robot/suites/fuzz_and_replay.robot
