#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/../.."
if [[ $EUID != 0 ]]; then
    echo 'Run with sudo on a disposable systemd host (not inside Docker).' >&2
    exit 1
fi
[[ $(ps -p 1 -o comm=) == systemd ]] || { echo 'Host PID 1 must be systemd.' >&2; exit 1; }
[[ $(stat -fc %T /sys/fs/cgroup) == cgroup2fs ]] || { echo 'cgroup v2 is required.' >&2; exit 1; }
load_env=DHCPV4_SERVED_LOAD=0
require_apparmor=${DHCPV4_SERVED_REQUIRE_APPARMOR:-0}
[[ $require_apparmor == 0 || $require_apparmor == 1 ]] || { echo 'Invalid AppArmor test setting.' >&2; exit 1; }
security_mount=()
if [[ $require_apparmor == 1 ]]; then
    [[ $(cat /sys/module/apparmor/parameters/enabled) == Y ]] || { echo 'AppArmor must be enabled.' >&2; exit 1; }
    grep -Fx 'dhcpv4-served (enforce)' /sys/kernel/security/apparmor/profiles
    # Guest systemd detects AppArmor via the host's module parameter. Expose
    # securityfs for diagnostics too; both mounts remain read-only.
    security_mount=(--bind-ro=/sys/module --bind-ro=/sys/kernel/security)
fi
runtime=12min
if [[ ${1:-} == --load && $# == 1 ]]; then
    load_env=DHCPV4_SERVED_LOAD=1
    runtime=30min
elif [[ $# != 0 ]]; then
    echo 'Usage: tests/systemd/run.sh [--load]' >&2
    exit 2
fi
image=$(realpath work/images/dhcp-test)
[[ -f $image/etc/dhcpv4-served-test-image ]] || { echo 'Build the test image first.' >&2; exit 1; }
# Each invocation has fresh evidence; an old successful result cannot mask failure.
output=$(mktemp -d "$PWD/work/nspawn-XXXXXXXX")
guest=$(mktemp -d "$PWD/work/guest-XXXXXXXX")
unit="dhcpv4-served-test-${output##*-}"
cleanup() {
    systemctl stop "$unit-fresh.service" "$unit-armed.service" \
        "$unit-disabled.service" "$unit-reboot.service" >/dev/null 2>&1 || true
    rm -rf --one-file-system -- "$guest"
    # sudo-created evidence must be readable by the runner's artifact uploader.
    chown -R "${SUDO_UID:-0}:${SUDO_GID:-0}" "$output"
}
trap cleanup EXIT
echo "Evidence: $output"
uname -a > "$output/host.txt"
systemd-nspawn --version >> "$output/host.txt"
packages=/opt/dhcpv4-served-tests/packages
cp "$image$packages/candidate.json" "$output/package-manifest.json"

prepare_root() {
    local root=$1 package=$2
    {
        if chroot "$root" dpkg-query -W dhcpv4-served >/dev/null 2>&1; then
            echo 'Expected a clean package database before provisioning dhcpv4-served.' >&2
            return 1
        fi
        sha256sum "$root$packages/$package"
        systemd-nspawn --quiet --register=no --settings=no --private-network \
            --private-users=no --directory="$root" /usr/bin/dpkg --install "$packages/$package"
    } > "$output/$package-install.log" 2>&1
    [[ $(chroot "$root" dpkg-query -W -f='${db:Status-Status}' dhcpv4-served) == installed ]]
    local path
    for path in /usr/libexec/dhcpv4-served /usr/lib/systemd/system/dhcpv4-served@.service \
        /usr/lib/systemd/system/dhcpv4-served@.socket; do
        [[ $(chroot "$root" dpkg-query -S "$path") == "dhcpv4-served: $path" ]]
    done
    [[ ! -e $root/etc/systemd/system/dhcpv4-served@.service && ! -e $root/etc/systemd/system/dhcpv4-served@.socket ]]
}

# Clone both update roots before any guest boots or writes a lease. With an
# older DEB the candidate is installed only in the separate fresh-install root.
cp --archive --reflink=auto "$image" "$guest/fresh"
prepare_root "$guest/fresh" candidate.deb
if [[ -f $image$packages/previous.deb ]]; then
    cp --archive --reflink=auto "$image" "$guest/armed"
    prepare_root "$guest/armed" previous.deb
else
    cp --archive --reflink=auto "$guest/fresh" "$guest/armed"
fi
cp --archive --reflink=auto "$guest/armed" "$guest/disabled"

boot() {
    local phase=$1 root=$2 selection=$3 robot_output=$4 limit=$5 required_test=$6
    printf '%s\n' "$load_env" "DHCPV4_SERVED_REQUIRE_APPARMOR=$require_apparmor" \
        "DHCPV4_SERVED_ROBOT_SELECTION=\"$selection\"" \
        "DHCPV4_SERVED_ROBOT_OUTPUT=/test-output/$robot_output" \
        > "$root/opt/dhcpv4-served-tests/robot.env"
    # Grant BPF to guest systemd for SocketBindDeny; the worker has no capabilities.
    systemd-run --unit="$unit-$phase" --wait --pipe --collect \
        --property=Delegate=yes --property=KillMode=mixed \
        --property=RuntimeMaxSec="$limit" --property=TimeoutStopSec=30s \
        systemd-nspawn --quiet --boot --keep-unit --register=no --settings=no \
        --machine="$unit" --directory="$root" \
        --private-users=no --private-network \
        --capability=CAP_BPF,CAP_PERFMON \
        "${security_mount[@]}" \
        --bind="$output:/test-output" 2>&1 | tee "$output/nspawn-$phase.log"

    # A clean poweroff cannot turn a missing or failed Robot result into a pass.
    "$PWD/work/venv/bin/rebot" --output NONE --log NONE \
        --report "$output/$robot_output/report.html" "$output/$robot_output/output.xml"
    python3 tests/systemd/check-robot-result.py "$output/$robot_output/output.xml" "$required_test"
}

boot fresh "$guest/fresh" '--include install-fresh' fresh-robot 4min \
    'The installed package only serves after explicit configuration and enablement'
boot armed "$guest/armed" '--include install-armed' armed-robot 4min \
    'Updating an armed socket leaves the worker dormant'
boot disabled "$guest/disabled" '--include install-disabled' disabled-robot 4min \
    'Updating a disabled socket leaves it disarmed'
boot reboot "$guest/disabled" '--exclude install-setup' robot "$runtime" \
    'A previously disabled installation stays disarmed after reboot'
if [[ $load_env == DHCPV4_SERVED_LOAD=1 ]]; then
    # Rebot accepts skipped cases. Explicit opt-in requires complete load evidence.
    python3 - "$output/load/load.json" <<'PY'
import json
import sys
from pathlib import Path
report = json.loads(Path(sys.argv[1]).read_text())
if report.get('status') != 'pass':
    raise SystemExit('Requested load acceptance did not pass: ' + str(report.get('status')))
PY
fi
