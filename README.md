# dhcpv4-served

[![CI](https://github.com/ruohonej/dhcpv4-served/actions/workflows/ci.yml/badge.svg)](https://github.com/ruohonej/dhcpv4-served/actions/workflows/ci.yml)
[![Latest release](https://img.shields.io/github/v/release/ruohonej/dhcpv4-served)](https://github.com/ruohonej/dhcpv4-served/releases/latest)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

An experimental, socket-activated DHCPv4 server for an isolated Linux lab. Each instance serves one directly connected Ethernet or VLAN interface from its own address pool. It can grant and renew leases across worker restarts. Use it on lab links only. Full client lifecycle interoperability and availability under hostile traffic are still unqualified.

## Run one instance

This walkthrough uses a disposable Ubuntu 26.04 amd64 host, systemd 259+, and Linux 6.18+ with Landlock ABI 7 enabled. The shipped service requires successful all-thread Landlock enforcement. Use an isolated interface named `lan10`, already up with exactly one IPv4 address, `192.168.10.1/24`. Reserve the pool `192.168.10.100–200` for this server. The example advertises the host as both router and DNS server. Adjust or remove those settings if the lab host does not provide those services. [Example YAML](examples/lan10.yaml)

From the repository root, build and install a local snapshot using Go and GoReleaser v2.13.3. CI uses Go 1.27.x. The package installs the binary and two unit templates. The operator supplies the interface configuration and chooses when to arm the socket.

```sh
goreleaser release --snapshot --clean
sudo dpkg -i dist/*_linux_amd64.deb
/usr/libexec/dhcpv4-served --version
```

Validate and install the configuration on the fresh host. The worker must be able to read the YAML. It checks that the file and ancestor directories are root-owned, have no group or other write permission, and contain no symlinks. For subsequent changes, disarm the instance first and replace the file by atomic rename in its protected directory.

```sh
/usr/libexec/dhcpv4-served validate examples/lan10.yaml
sudo install -d -o root -g root -m 0755 /etc/dhcpv4-served
sudo install -o root -g root -m 0644 examples/lan10.yaml /etc/dhcpv4-served/lan10.yaml
sudo systemctl daemon-reload
sudo systemctl start dhcpv4-served@lan10.socket
systemctl is-active dhcpv4-served@lan10.socket
```

Request a lease from a DHCP client on that link. The first datagram starts the worker. Check that the client receives an address in the configured pool and that the journal contains a `worker.ready` event for `lan10`. If the socket is active but the client gets no reply, check the worker's journal for `startup.rejected` or `state.failed` and its `reason` field.

```sh
systemctl is-active dhcpv4-served@lan10.service
sudo journalctl -b -u dhcpv4-served@lan10.service -o cat
```

Repeated startup failures can leave the socket in `service-start-limit-hit`. After repairing the cause, clear the failure counters and rearm the affected socket. Reload systemd first if you changed a unit or drop-in. Check that a client can acquire a lease on that link.

```sh
sudo systemctl reset-failed dhcpv4-served@lan10.service dhcpv4-served@lan10.socket
sudo systemctl restart dhcpv4-served@lan10.socket
```

For persistent activation, use `sudo systemctl enable --now dhcpv4-served@lan10.socket`. To stop serving, including across reboot, disarm the socket and stop the worker. Verify that both report `inactive`. Preserve the state directory during maintenance.

```sh
sudo systemctl disable --now dhcpv4-served@lan10.socket
sudo systemctl stop dhcpv4-served@lan10.service
systemctl is-active dhcpv4-served@lan10.socket dhcpv4-served@lan10.service
```

For a published DEB, verify the package and signed manifest before installation. Select the expected tag and source revision independently and obtain Cosign v3 from a trusted distribution. With `tag` set to the expected tag and `deb` to the exact downloaded filename, run these commands in the download directory. Compare the verified manifest's `version`, `source_sha`, and artifact digest with the expected release and local file. [Release workflow](.github/workflows/release.yml)

```sh
(
  set -eu
  identity="https://github.com/ruohonej/dhcpv4-served/.github/workflows/release.yml@refs/tags/${tag:?set tag}"
  for asset in "${deb:?set deb}" release-manifest.json; do
    cosign verify-blob --bundle "$asset.sigstore.json" \
      --certificate-oidc-issuer https://token.actions.githubusercontent.com \
      --certificate-identity "$identity" "$asset"
  done
  sha256sum "$deb"
  cat release-manifest.json
)
```

## Default configuration

On an isolated link already up with exactly one IPv4 address, start `dhcpv4-served@INTERFACE.socket` without creating `/etc/dhcpv4-served/INTERFACE.yaml` to serve the subnet's usable addresses, excluding the host. The host is advertised as the router, so it must be configured to forward client traffic. The worker snapshots usable IPv4 DNS servers from systemd-resolved over Varlink, excluding route-only and strict DNS-over-TLS scopes, and omits DNS when unavailable. These settings do not configure the link, routing or DNS services.

The default pool includes addresses assigned statically by other means and the worker does not probe for conflicts. Use this mode only on an isolated link where the whole pool is available to this server. For exclusions or different settings, provide a trusted YAML file as above. An invalid or unreadable file stops startup. Changes to the link or pool can make existing lease state incompatible; follow the [recovery rules](TechnicalSpecification.md#persistence-and-recovery). [Default settings](TechnicalSpecification.md#configuration-and-startup)

## Development and tests

Build the worker and install the Python test dependencies into the repository virtual environment.

```sh
mkdir -p work
CGO_ENABLED=0 go build -o work/dhcpv4-served ./cmd/dhcpv4-served
work/dhcpv4-served validate examples/lan10.yaml examples/lan20.yaml
python3 -m venv work/venv
work/venv/bin/pip install -r tests/robot/requirements.txt
tests/check
```

`tests/check` runs Go unit tests, Python fixture and release-tool regressions, a Robot dry run, and the [executable contract checks](tests/release_gates.py). To run one group, use `tests/check go`, `fixtures`, `release`, `scenarios`, or `contracts`. CI also runs the race detector, native Go fuzzing, golangci-lint v2.15.0, and security scans. Add a regression test for behavior changes and describe what you verified in the PR.

Use `tests/acceptance run PROFILE` or `tests/check acceptance run PROFILE` for live scenarios. The runner invokes sudo when needed. The namespace profiles require a disposable Linux host with iproute2, setpriv, and support for mapped user and network namespaces.

| Profile | What runs | Evidence under `work/` |
| --- | --- | --- |
| `dhcp` | Packet delivery, lease recovery, and link isolation | `acceptance/dhcp/run-*` |
| `startup` | Startup rejection through a synthetic launcher | `acceptance/startup/run-*` |
| `clients` | Acquisition with dhclient, dhcpcd, and systemd-networkd (install all three) | `acceptance/clients/run-*` |
| `fuzz` | Recorded and generated DHCP sequences and packet cases | `acceptance/fuzz/run-*` |
| `differential` | OFFER isolation and broadcast ACK on dhcpv4-served and dnsmasq | `differential/run-*` |
| `package` | Fresh install, update, reboot, shipped units, packets, and real clients | `nspawn-*` |
| `load` | Package acceptance including measured load and renewal budgets | `nspawn-*` |

Read a behavior in [the Robot suites](tests/robot/suites). Shared Robot settings live in `resources/`, Python keyword libraries in `keywords/`, drivers and assertions in `harness/`, harness unit tests in `regression/`, and replay inputs in `data/`. A test template expresses one rule with named examples for each port, client, or startup condition. The Given/When/Then keywords call Python drivers such as [the namespace driver](tests/robot/harness/namespace_driver.py). Both DHCP servers use [the same reply assertions](tests/robot/harness/reply_checks.py). [Package scenarios](tests/robot/suites/package_lifecycle.robot) use a snapshot from before the update to check journal activity, configuration, and lease state afterward.

For `package` and `load`, use a disposable Ubuntu 26.04 amd64 systemd host with root, cgroup v2/BPF, namespaces, and strict Landlock support. Install systemd-nspawn and mkosi v25.3 as in [CI](.github/workflows/ci.yml). Build the snapshot DEB, then run the following with the virtual environment on `PATH`. With one DEB the update cases exercise a reinstall. CI currently uses one DEB and exercises a reinstall. Once an earlier release is available, supply its DEB as a second argument to test an upgrade from a lower version. The test records both package versions in `update-versions.json`.

```sh
tests/systemd/build.sh dist/*_linux_amd64.deb
tests/acceptance run package
```

For packet decisions, state compatibility, and restart rules, see the [technical specification](TechnicalSpecification.md). For trust assumptions and deployment limits, see the [threat model](ThreatModel.md).

The fuzz profile accepts `--examples N`, `--replay PATH`, and `--packet-replay PATH`. Both entry points resolve replay paths from the invoking directory and save the supplied inputs under `inputs/` in the run’s evidence directory. Each failing case saves replay JSON, packet captures, and worker logs under the printed run directory. For example, use `tests/acceptance run fuzz --replay "$run/stateful-generated/sequence.json"` with `run` set to that directory.

### DHCPv4 comparison with dnsmasq

CI runs the comparison on pull requests. To run it locally, install `dnsmasq-base` and run `tests/acceptance run differential` on the namespace test host.

The runner exercises the existing OFFER isolation and broadcast ACK cases on both links, with fresh state for each server and case. It checks the transaction, granted lease, broadcast destination, subnet mask, lease duration, and configured DHCP options. Either server can choose any eligible address. Option order and padding are ignored, and dnsmasq may omit the echoed client identifier. Reports, per-link captures, server configs and logs, dnsmasq version, and the normalized comparison are saved under `work/differential/run-*`. When run with `sudo`, the runner returns ownership of each run directory to the invoking user.
