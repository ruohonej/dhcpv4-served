#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/../.."

# Stage the DEBs in a clean Ubuntu image. run.sh installs them only in
# disposable copies for the fresh-install and update tests.
if [[ $# -lt 1 || $# -gt 2 || ! -f $1 || ( $# == 2 && ! -f $2 ) ]]; then
    echo "Usage: $0 candidate.deb [previous.deb]" >&2
    exit 1
fi
package=$(realpath "$1")
[[ $(dpkg-deb -f "$package" Package) == dhcpv4-served ]] || { echo "Expected a dhcpv4-served DEB" >&2; exit 1; }
[[ $(dpkg-deb -f "$package" Architecture) == "$(dpkg --print-architecture)" ]] || { echo "DEB architecture does not match the host" >&2; exit 1; }
if [[ $# == 2 ]]; then
    previous=$(realpath "$2")
    if [[ $(dpkg-deb -f "$previous" Package) != dhcpv4-served ||
          $(dpkg-deb -f "$previous" Architecture) != "$(dpkg --print-architecture)" ]] ||
        ! dpkg --compare-versions "$(dpkg-deb -f "$previous" Version)" lt "$(dpkg-deb -f "$package" Version)"; then
        echo 'Expected a lower-version dhcpv4-served DEB for the candidate architecture.' >&2
        exit 1
    fi
fi
mkosi_bin=$(command -v mkosi)
if [[ $("$mkosi_bin" --version) != 'mkosi 25.3' ]]; then
    echo 'Install mkosi v25.3 in a Python virtual environment; see the development and tests section in README.md.' >&2
    exit 1
fi
stage=work/image-root
rm -rf -- "$stage"
mkdir -p "$stage/etc/systemd/system/multi-user.target.wants" \
    "$stage/etc/systemd/system-preset" "$stage/opt/dhcpv4-served-tests/packages" "$stage/test-output"
# Presets run again on first boot, so disable the resolver and its sockets in
# the image policy. The DNS test starts them explicitly in its disposable guest.
printf 'disable systemd-resolved.service\ndisable systemd-resolved-varlink.socket\ndisable systemd-resolved-monitor.socket\n' \
    > "$stage/etc/systemd/system-preset/00-dhcpv4-served-test.preset"
cp tests/systemd/dhcpv4-served-test.service "$stage/etc/systemd/system/"
ln -sfn ../dhcpv4-served-test.service \
    "$stage/etc/systemd/system/multi-user.target.wants/dhcpv4-served-test.service"
# Client networkd is launched explicitly in its client namespace; do not let
# the distribution instance configure links or share its runtime state.
ln -sfn /dev/null "$stage/etc/systemd/system/systemd-networkd.service"
ln -sfn /dev/null "$stage/etc/systemd/system/systemd-networkd.socket"
ln -sfn /dev/null "$stage/etc/systemd/system/systemd-networkd-varlink.socket"
ln -sfn /dev/null "$stage/etc/systemd/system/systemd-networkd-resolve-hook.socket"
guest_tests="$stage/opt/dhcpv4-served-tests"
cp tests/check-platform.py "$guest_tests/"
for group in suites resources keywords harness data; do
    mkdir -p "$guest_tests/$group"
    cp tests/robot/"$group"/*.* "$guest_tests/$group/"
done
packages="$stage/opt/dhcpv4-served-tests/packages"
python3 tests/systemd/inspect-deb.py "$package" > "$packages/candidate.json"
install -m 0644 "$package" "$packages/candidate.deb"
if [[ $# == 2 ]]; then
    install -m 0644 "$previous" "$packages/previous.deb"
fi
# Robot is pure Python: stage the same requirement used by the host libraries,
# without a guest pip installation or a separate integration runner.
python3 -m pip install --no-compile --no-deps --upgrade \
    --target "$stage/opt/dhcpv4-served-tests" -r tests/robot/requirements.txt
printf 'Disposable dhcpv4-served acceptance image\n' > "$stage/etc/dhcpv4-served-test-image"
sudo "$mkosi_bin" --force build
