"""systemd backend for the shared Robot DHCP and real-client libraries.

Topology, packet I/O, assertions and client commands are shared with the fast
backend. Only the service lifecycle and inspection belong to this backend.
"""
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time

from harness.namespace_driver import FastBackend
from harness import fixtures as probe
from harness import real_client_fixture as clients

HERE = Path(__file__).resolve().parents[1]
LINKS = ('lan10', 'lan20')
# Reviewed enabled-unit baseline for the disposable image in mkosi.conf.
# Review changes to this set alongside changes to the image or its packages.
BASELINE_ENABLED_SERVICES = frozenset({
    'getty@.service', 'dhcpv4-served-test.service',
    # Enabled at runtime by systemd's container/boot generators.
    'console-getty.service', 'systemd-remount-fs.service',
    'systemd-confext.service', 'systemd-network-generator.service',
    'systemd-networkd-wait-online.service', 'systemd-pstore.service',
    'systemd-sysext.service', 'systemd-tpm2-clear.service',
    'systemd-pcrlock-file-system.service', 'systemd-pcrlock-firmware-code.service',
    'systemd-pcrlock-firmware-config.service', 'systemd-pcrlock-machine-id.service',
    'systemd-pcrlock-make-policy.service', 'systemd-pcrlock-secureboot-authority.service',
    'systemd-pcrlock-secureboot-policy.service',
})


def run(*args, check=True, timeout=30):
    result = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    if check and result.returncode:
        raise RuntimeError(f'{args!r} exited {result.returncode}:\n{result.stdout}\n{result.stderr}')
    return result


def ctl(*args, check=True):
    return run('systemctl', *args, check=check).stdout.strip()


def prop(unit, key):
    return ctl('show', unit, '--property=' + key, '--value')


def journal_cursor():
    run('journalctl', '--sync')
    entry = json.loads(run('journalctl', '-b', '--no-pager', '--lines=1', '--output=json').stdout)
    cursor = entry.get('__CURSOR')
    assert isinstance(cursor, str) and cursor, 'Journal cursor is missing'
    return cursor


def configuration_rejections(service, cursor, previous_invocations):
    output = run('journalctl', '-b', '--no-pager', '-u', service,
                 '--after-cursor=' + cursor, '--output=json').stdout
    entries = [json.loads(line) for line in output.splitlines() if line.strip()]
    invocations = {entry['_SYSTEMD_INVOCATION_ID'] for entry in entries
                   if entry.get('_SYSTEMD_INVOCATION_ID')
                   and entry['_SYSTEMD_INVOCATION_ID'] not in previous_invocations
                   and any(event.get('event_id') == 'startup.rejected' and event.get('reason') in
                           ('config', 'config_file', 'config_directory')
                           for event in probe.worker_events(entry.get('MESSAGE', '')))}
    assert invocations, 'No fresh worker invocation rejected the configuration'
    return invocations


def wait(predicate, message, timeout=10):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.1)
    raise AssertionError(message)


def listener_inventory():
    """Return listening TCP and bound UDP endpoints with their socket inodes."""
    result = set()
    for protocol in ('tcp', 'tcp6', 'udp', 'udp6'):
        lines = Path('/proc/net', protocol).read_text().splitlines()[1:]
        for line in lines:
            fields = line.split()
            if ((protocol.startswith('tcp') and fields[3] == '0A')
                    or (protocol.startswith('udp') and int(fields[1].split(':')[1], 16) != 0)):
                result.add((protocol, fields[1], fields[9]))
    return result


def enabled_services():
    output = ctl('list-unit-files', '--type=service', '--state=enabled,enabled-runtime',
                 '--no-legend', '--no-pager')
    return {line.split()[0] for line in output.splitlines() if line.strip()}


class SystemdProcess:
    """The small process interface used by the existing DHCP scenario keywords."""
    def __init__(self, link):
        self.unit = f'dhcpv4-served@{link}.service'

    @property
    def pid(self):
        return int(prop(self.unit, 'MainPID'))

    def poll(self):
        if prop(self.unit, 'ActiveState') in ('active', 'activating', 'deactivating'):
            return None
        return int(prop(self.unit, 'ExecMainStatus'))

    def wait(self, timeout=5):
        wait(lambda: self.poll() is not None, f'{self.unit} did not stop', timeout)
        return self.poll()

    def terminate(self):
        ctl('stop', self.unit)

    def kill(self):
        ctl('kill', '--signal=SIGKILL', self.unit, check=False)


class SystemdBackend(FastBackend):
    prepared = False
    exchange_timeout = 2

    def check_environment(self):
        if (os.geteuid() != 0 or not Path('/etc/dhcpv4-served-test-image').is_file()
                or run('systemd-detect-virt', '--container', check=False).stdout.strip() != 'systemd-nspawn'
                or Path('/proc/1/comm').read_text().strip() != 'systemd'):
            raise RuntimeError('Only run inside the booted dhcpv4-served nspawn test image')
        self.environment_checked = True
        if not SystemdBackend.prepared:
            report = json.loads(run(sys.executable, str(HERE / 'check-platform.py')).stdout)
            report['landlock_enforcement_tested'] = False
            report['scope'] = 'Production strict-profile systemd integration; worker startup enforces all-thread policy'
            Path('/test-output/platform.json').write_text(json.dumps(report, indent=2))
            version = re.match(r'systemd (\d+)', report['systemd'])
            if not version or int(version[1]) < 259:
                raise RuntimeError('Guest systemd 259+ is required')
            if report.get('landlock_abi') is None or report['landlock_abi'] < 7:
                raise RuntimeError('Production strict-profile acceptance requires enabled Landlock ABI 7+')
            run('systemd-analyze', 'verify', '--man=no', 'dhcpv4-served@lan10.socket', 'dhcpv4-served@lan10.service')
            SystemdBackend.prepared = True

    def create(self, *, configure=True):
        super().create()
        if configure:
            config = Path('/etc/dhcpv4-served')
            config.mkdir(mode=0o755, exist_ok=True)
            for link in LINKS:
                (config / f'{link}.yaml').write_text(probe.pool_configuration(link[3:]))
        ctl('reset-failed')

    def clear_configuration(self):
        # Only real-client tests require an absent config. Installation tests
        # use configure=False to preserve configuration across reboots.
        for link in LINKS:
            (Path('/etc/dhcpv4-served') / f'{link}.yaml').unlink(missing_ok=True)

    def start(self):
        self.check_dormant()
        ctl('start', *(f'dhcpv4-served@{link}.socket' for link in LINKS))
        self.workers = {link: SystemdProcess(link) for link in LINKS}
        self.check_dormant()

    def check_dormant(self):
        for link in LINKS:
            assert prop(f'dhcpv4-served@{link}.service', 'MainPID') == '0', f'{link} activated without traffic'

    def check_listener_lifecycle(self):
        socket_unit = 'dhcpv4-served@lan10.socket'
        service = 'dhcpv4-served@lan10.service'
        for link in LINKS:
            assert prop(f'dhcpv4-served@{link}.socket', 'ActiveState') == 'inactive'
            assert ctl('is-enabled', f'dhcpv4-served@{link}.socket', check=False) == 'disabled'
        before = listener_inventory()
        baseline_services = enabled_services()
        evidence = {'before': sorted(before), 'enabled_services_before': sorted(baseline_services)}
        try:
            assert not before, f'Unexpected initial TCP/UDP endpoints: {sorted(before)}'
            assert baseline_services == BASELINE_ENABLED_SERVICES, {
                'unexpected': sorted(baseline_services - BASELINE_ENABLED_SERVICES),
                'missing': sorted(BASELINE_ENABLED_SERVICES - baseline_services),
            }
            ctl('enable', '--now', socket_unit)
            armed = listener_inventory()
            added = armed - before
            assert before <= armed, (before, armed)
            assert len(added) == 1, added
            protocol, address, _ = next(iter(added))
            assert (protocol, address) == ('udp', '00000000:0043'), added
            assert prop(socket_unit, 'BindToDevice') == 'lan10'
            assert prop('dhcpv4-served@lan20.socket', 'ActiveState') == 'inactive'
            assert prop(service, 'ActiveState') == 'inactive'
            evidence['armed'] = sorted(armed)
            evidence['enabled_services_armed'] = sorted(enabled_services())
            assert evidence['enabled_services_armed'] == sorted(baseline_services)
            ctl('disable', '--now', socket_unit)
            ctl('stop', service)
            after = listener_inventory()
            evidence['after'] = sorted(after)
            evidence['enabled_services_after'] = sorted(enabled_services())
            assert after == before, (before, after)
            assert evidence['enabled_services_after'] == sorted(baseline_services)
            assert prop(socket_unit, 'ActiveState') == 'inactive'
            assert prop(service, 'ActiveState') == 'inactive'
            assert ctl('is-enabled', socket_unit, check=False) == 'disabled'
        finally:
            (self.output / 'listener-inventory.json').write_text(json.dumps(evidence, indent=2))
            ctl('disable', '--now', socket_unit, check=False)
            ctl('stop', service, check=False)

    def commit_lease(self, link):
        super().commit_lease(link)
        snapshot = self.snapshot(link)
        assert any(b['address'] == f'192.168.{link[3:]}.100' and b['state'] == 'leased'
                   and b['hardware'] == clients.MAC for b in snapshot['bindings']), snapshot

    def snapshot(self, link):
        snapshot = json.loads(Path(f'/var/lib/dhcpv4-served-{link}/leases.json').read_text())
        (self.output / f'{link}-leases.json').write_text(json.dumps(snapshot, indent=2))
        return snapshot

    def restart(self):
        for process in self.workers.values():
            before = prop(process.unit, 'InvocationID')
            ctl('restart', process.unit)
            assert prop(process.unit, 'InvocationID') != before
        for link in LINKS:
            assert prop(f'dhcpv4-served@{link}.socket', 'ActiveState') == 'active'

    def stop_worker(self, link):
        process = self.workers[link]
        self.stopped_invocation = prop(process.unit, 'InvocationID')
        process.terminate()
        assert process.pid == 0
        assert prop(f'dhcpv4-served@{link}.socket', 'ActiveState') == 'active'

    def check_reactivated(self, link):
        process = self.workers[link]
        assert prop(process.unit, 'ActiveState') == 'active'
        assert prop(process.unit, 'InvocationID') != self.stopped_invocation

    def check_privileges(self):
        for link in LINKS:
            self.exchange(link, probe.request())
            self.check_reply(link)
        super().check_privileges()
        uids = []
        for link, process in self.workers.items():
            uid = int(next(line.split()[1] for line in Path(f'/proc/{process.pid}/status').read_text().splitlines()
                           if line.startswith('Uid:')))
            uids.append(uid)
            assert prop(process.unit, 'DynamicUser') == 'yes'
            apparmor = Path('/sys/module/apparmor/parameters/enabled')
            if apparmor.is_file() and apparmor.read_text().strip() == 'Y':
                label = Path(f'/proc/{process.pid}/attr/current').read_text().strip()
                assert label == 'dhcpv4-served (enforce)', label
            assert prop(process.unit, 'ProtectProc') == 'invisible'
            assert prop(process.unit, 'ProcSubset') == 'pid'
            state = Path(f'/proc/{process.pid}/root/var/lib/dhcpv4-served-{link}')
            assert state.stat().st_uid == uid and state.stat().st_mode & 0o777 == 0o700
            assert os.readlink(f'/proc/{process.pid}/ns/mnt') != os.readlink('/proc/self/ns/mnt')
        assert len(set(uids)) == 2, 'Instances must have distinct dynamic users'

    def start_invalid(self, reason):
        if reason == 'pool outside the subnet':
            Path('/etc/dhcpv4-served/lan10.yaml').write_text(probe.pool_configuration('20'))
            self.expected_diagnostic = 'config_link'
        elif reason == 'ambiguous server addresses':
            probe.ip('address', 'add', '192.168.10.2/24', 'dev', 'lan10')
            self.expected_diagnostic = 'link_addresses'
        else:
            raise ValueError('Malformed descriptors/capabilities use the fast backend in startup_rejection.robot')
        self.start()
        self.last_worker = self.workers['lan10']
        self.exchange('lan10', probe.request())

    def check_rejected(self):
        self.last_worker.wait(timeout=5)
        self.invalid_log = self.output / 'invalid.log'
        self.invalid_log.write_text(run('journalctl', '-b', '--no-pager', '-u', self.last_worker.unit).stdout)
        super().check_rejected()

    def check_control_failure(self, failure):
        """Inject one startup protection failure; never weaken the peer unit."""
        settings = {
            'Landlock unavailable': ('SystemCallFilter=~landlock_create_ruleset', 'abi_missing'),
            'Landlock enforcement denied': ('SystemCallFilter=~landlock_restrict_self', 'protection'),
        }
        if failure == 'state access denied':
            # Masking StateDirectory with InaccessiblePaths breaks systemd's
            # id-mapped mount setup before exec (226/NAMESPACE). Instead pass a
            # separate root-owned 0700 directory: namespace setup succeeds, and
            # the actual DynamicUser worker encounters DAC denial on open.
            self.denied_state = tempfile.TemporaryDirectory(prefix='dhcpv4-served-denied-', dir='/run')
            original = Path('/usr/lib/systemd/system/dhcpv4-served@.service').read_text()
            command = next(line for line in original.splitlines() if line.startswith('ExecStart='))
            expected = '--state-dir /var/lib/private/dhcpv4-served-%i'
            assert expected in command, 'Production state-dir command changed'
            setting = 'ExecStart=\n' + command.replace(expected, '--state-dir ' + self.denied_state.name)
            diagnostic = 'permission'
        else:
            setting, diagnostic = settings[failure]
        self.start()
        self.commit_lease('lan20')
        self.assign_client_address('lan20')
        peer_invocation = prop('dhcpv4-served@lan20.service', 'InvocationID')
        self.healthy_peer_invocation = peer_invocation
        peer_before = self.snapshot('lan20')
        override = Path('/run/systemd/system/dhcpv4-served@lan10.service.d/37-fault.conf')
        override.parent.mkdir(parents=True, exist_ok=True)
        override.write_text('[Service]\n' + setting + '\n')
        ctl('daemon-reload')
        self.last_worker = self.workers['lan10']
        self.expected_diagnostic = diagnostic
        self.failure_since = str(time.time())
        ctl('start', self.last_worker.unit, check=False)
        self.last_worker.wait(timeout=5)
        # Worker failure alone does not explicitly stop the already armed socket.
        # Traffic below can cause manager retries/start limits; record that too.
        socket_before = prop('dhcpv4-served@lan10.socket', 'ActiveState')
        assert socket_before == 'active', socket_before
        self.exchange('lan10', probe.request())
        assert self.replies == [], f'Failed protection produced DHCP replies: {self.replies!r}'
        self.invalid_log = self.output / 'control-failure.log'
        self.invalid_log.write_text(run('journalctl', '-b', '--no-pager', '-u', self.last_worker.unit,
                                        '--since=@' + self.failure_since).stdout)
        FastBackend.check_rejected(self)
        assert all(e.get('event_id') != 'worker.ready' for e in probe.worker_events(self.invalid_log.read_text())), \
            'Failed protection reached readiness'
        assert prop('dhcpv4-served@lan20.service', 'InvocationID') == peer_invocation, 'Peer restarted'
        assert prop('dhcpv4-served@lan20.service', 'ActiveState') == 'active', 'Peer exited'
        assert self.snapshot('lan20') == peer_before, 'Fault altered peer lease state'
        self.send_unicast_renewal('lan20')
        self.check_unicast_ack('lan20')
        (self.output / 'control-failure.json').write_text(json.dumps({
            'fault': failure, 'setting': setting, 'failed_worker_status': self.last_worker.poll(),
            'socket_after_worker_failure': socket_before,
            'socket_after_traffic': prop('dhcpv4-served@lan10.socket', 'ActiveState'),
            'peer_invocation': peer_invocation, 'peer_survived_and_renewed': True,
            'no_reply_and_no_readiness': True,
        }, indent=2))

    def repair_control_failure(self):
        service, socket = 'dhcpv4-served@lan10.service', 'dhcpv4-served@lan10.socket'
        # Clear the rate limit while the failed units are still loaded. Stop
        # the socket to discard any datagrams queued under the broken setup.
        ctl('reset-failed', service, socket)
        ctl('stop', socket, service)
        Path('/run/systemd/system/dhcpv4-served@lan10.service.d/37-fault.conf').unlink()
        ctl('daemon-reload')
        ctl('start', socket)
        assert prop(socket, 'ActiveState') == 'active'
        assert prop(service, 'MainPID') == '0', 'Repaired worker activated before traffic'

    def check_control_recovery(self):
        self.commit_lease('lan10')
        recovered = prop('dhcpv4-served@lan10.service', 'InvocationID')
        assert recovered and prop('dhcpv4-served@lan10.service', 'ActiveState') == 'active'
        self.send_unicast_renewal('lan20')
        self.check_unicast_ack('lan20')
        peer = prop('dhcpv4-served@lan20.service', 'InvocationID')
        assert peer == self.healthy_peer_invocation, 'Repair restarted the healthy peer'
        (self.output / 'control-recovery.json').write_text(json.dumps({
            'recovered_invocation': recovered, 'peer_invocation': peer,
        }, indent=2))

    def check_default_configuration(self):
        Path('/etc/dhcpv4-served/lan10.yaml').unlink()
        # Start the real resolver and configure a general-purpose link and a
        # route-only link. No external DNS server needs to be contacted.
        dns_servers = ['192.0.2.53', '198.51.100.53']
        split_dns = '203.0.113.53'
        ctl('start', 'systemd-resolved.service')
        try:
            run('resolvectl', 'dns', 'lan10', *dns_servers)
            run('resolvectl', 'default-route', 'lan10', 'yes')
            run('resolvectl', 'dns', 'lan20', split_dns)
            run('resolvectl', 'domain', 'lan20', '~internal.example')
            run('resolvectl', 'default-route', 'lan20', 'no')
            self.start()
            self.exchange('lan10', probe.request())
            assert len(self.replies) == 1, self.replies
            offer = self.replies[0]
            assert offer['yiaddr'] == '192.168.10.2', offer
            assert offer['router'] == ['192.168.10.1'], offer
            assert offer['dns'] is not None and all(addr in offer['dns'] for addr in dns_servers), offer
            assert split_dns not in offer['dns'], offer
            self.exchange('lan10', probe.request(3, server='192.168.10.1', address='192.168.10.2'))
            assert len(self.replies) == 1 and self.replies[0]['type'] == 5, self.replies
            assert all(addr in (self.replies[0]['dns'] or []) for addr in dns_servers), self.replies
            assert self.snapshot('lan10')['bindings'][0]['address'] == '192.168.10.2'
            ctl('stop', 'dhcpv4-served@lan10.service')
            self.exchange('lan10', probe.request(3, server='192.168.10.1', address='192.168.10.2'))
            assert len(self.replies) == 1 and self.replies[0]['type'] == 5, self.replies
            assert all(addr in (self.replies[0]['dns'] or []) for addr in dns_servers), self.replies
        finally:
            for link in LINKS:
                run('resolvectl', 'revert', link, check=False)
            ctl('stop', 'systemd-resolved.service', 'systemd-resolved-varlink.socket',
                'systemd-resolved-monitor.socket', check=False)

    def check_trusted_configuration(self):
        directory = Path('/etc/dhcpv4-served')
        config = directory / 'lan10.yaml'
        target = directory / 'target.yaml'
        service = 'dhcpv4-served@lan10.service'
        socket = 'dhcpv4-served@lan10.socket'
        peer_service = 'dhcpv4-served@lan20.service'
        good = probe.pool_configuration('10')

        def repair():
            os.chown(directory, 0, 0)
            directory.chmod(0o755)
            config.unlink(missing_ok=True)
            config.write_text(good)
            os.chown(config, 0, 0)
            config.chmod(0o644)

        self.workers = {link: SystemdProcess(link) for link in LINKS}
        seen_invocations = set()
        evidence = {'cases': []}
        try:
            target.write_text(good)
            target.chmod(0o644)
            ctl('start', 'dhcpv4-served@lan20.socket')
            self.exchange('lan20', probe.request())
            self.check_reply('lan20')
            peer_invocation = prop(peer_service, 'InvocationID')
            assert peer_invocation, 'Peer invocation is missing'
            evidence['peer_invocation'] = peer_invocation

            def check_peer():
                self.exchange('lan20', probe.request())
                self.check_reply('lan20')
                assert prop(peer_service, 'ActiveState') == 'active', 'Peer stopped'
                assert prop(peer_service, 'InvocationID') == peer_invocation, 'Peer restarted'

            for fault in ('writable file', 'writable parent',
                          'untrusted file owner', 'untrusted parent owner', 'symlink'):
                case = {'fault': fault}
                evidence['cases'].append(case)
                ctl('stop', service, socket, check=False)
                ctl('reset-failed', service, socket, check=False)
                repair()
                if fault == 'writable file':
                    config.chmod(0o666)
                elif fault == 'writable parent':
                    directory.chmod(0o777)
                elif fault == 'untrusted file owner':
                    os.chown(config, 65534, 65534)
                elif fault == 'untrusted parent owner':
                    os.chown(directory, 65534, 65534)
                else:
                    config.unlink()
                    config.symlink_to(target.name)
                cursor = journal_cursor()
                ctl('start', socket)
                replies = self.exchange('lan10', probe.request())
                assert replies == [], f'{fault}: unexpected replies {replies}'
                wait(lambda: prop(service, 'ActiveState') == 'failed', f'{fault}: worker did not fail')
                invocations = configuration_rejections(service, cursor, seen_invocations)
                seen_invocations.update(invocations)
                case['rejected_invocations'] = sorted(invocations)
                check_peer()
                case['peer_during_rejection'] = peer_invocation

                ctl('stop', service, socket, check=False)
                ctl('reset-failed', service, socket, check=False)
                repair()
                ctl('start', socket)
                self.exchange('lan10', probe.request())
                self.check_reply('lan10')
                recovered = prop(service, 'InvocationID')
                assert recovered and recovered not in seen_invocations, 'No fresh recovery invocation'
                seen_invocations.add(recovered)
                case['recovered_invocation'] = recovered
                check_peer()
                case['peer_after_recovery'] = peer_invocation
        finally:
            ctl('stop', service, socket, check=False)
            repair()
            target.unlink(missing_ok=True)
            (self.output / 'trusted-config-evidence.json').write_text(json.dumps(evidence, indent=2))

    def check_sandbox(self):
        original = Path('/usr/lib/systemd/system/dhcpv4-served@.service').read_text()
        lines = ['ExecStart=/usr/bin/python3 /opt/dhcpv4-served-tests/harness/sandbox_probe.py'
                 if line.startswith('ExecStart=') else line for line in original.splitlines()
                 if not line.startswith(('Requires=', 'After='))]
        Path('/run/systemd/system/dhcpv4-served@probe.service').write_text('\n'.join(lines) + '\n')
        peer_lines = [line + ' hold' if line.startswith('ExecStart=') else line for line in lines]
        Path('/run/systemd/system/dhcpv4-served@peer.service').write_text('\n'.join(peer_lines) + '\n')
        for name, content in (('probe.yaml', 'selected config\n'), ('unrelated', 'unrelated\n')):
            path = Path('/etc/dhcpv4-served') / name
            path.write_text(content)
            path.chmod(0o644)
        ctl('daemon-reload')
        ctl('start', 'dhcpv4-served@peer.service')
        peer = Path('/var/lib/private/dhcpv4-served-peer/private')
        wait(peer.is_file, 'Peer state not created')
        assert prop('dhcpv4-served@peer.service', 'ActiveState') == 'active', 'Peer is not running'
        assert peer.read_text() == 'peer state', 'Peer fixture is missing or changed'
        ctl('start', 'dhcpv4-served@probe.service')
        wait(lambda: prop('dhcpv4-served@probe.service', 'ActiveState') in ('inactive', 'failed'), 'Probe did not finish')
        # ENOENT inside the probe is isolation only if the peer still exists
        # outside its mount namespace and its state was not changed.
        assert prop('dhcpv4-served@peer.service', 'ActiveState') == 'active', 'Peer stopped during probe'
        assert peer.read_text() == 'peer state', 'Probe changed or removed peer state'
        assert prop('dhcpv4-served@probe.service', 'Result') == 'success'
        run('systemd-run', '--unit=dhcpv4-served-bind-probe', '--wait', '--pipe',
            '--property=SocketBindDeny=any', '/usr/bin/python3', str(HERE / 'harness/sandbox_probe.py'), 'bind')

    def run_real_client(self, name, binary, out):
        """Collect evidence; the existing Robot Then keyword validates it."""
        out.mkdir()
        peer = self.peers['lan10']
        pid = self.clients[0].pid
        command = clients.client_command(name, binary, out, single_uid=False)
        unit = f'dhcpv4-served-client-{name}.service'
        peer.send(dict(action='observe', timeout=60, capture_all=True, observe_ready=True, interruptible=True))
        assert peer.poll(5) and peer.recv() == 'observing', 'Client capture did not become ready'
        self.start()
        settings = ['--property=ReadOnlyPaths=/sys', '--setenv=SYSTEMD_LOG_LEVEL=debug'] if name == 'systemd-networkd' else []
        try:
            run('systemd-run', '--unit=' + unit, '--service-type=exec',
                f'--property=NetworkNamespacePath=/proc/{pid}/ns/net', *settings, *command)

            def state(*args):
                return json.loads(run('nsenter', f'--net=/proc/{pid}/ns/net', 'ip', '-j', '-4', *args).stdout)

            def configured():
                return (any(a.get('local') == clients.ADDRESS for link in state('address', 'show', 'dev', 'eth0') for a in link['addr_info'])
                        and any(r.get('dst') == 'default' and r.get('gateway') == clients.SERVER for r in state('route')))

            timed_out = False
            try:
                wait(configured, f'{name} did not configure an address and route', timeout=45)
                if name != 'systemd-networkd':
                    wait(lambda: any(e.get('reason') == 'BOUND' for e in clients.hook_events(out)), 'Missing BOUND hook')
            except AssertionError:
                timed_out = True
            peer.send({'action': 'finish'})
            assert peer.poll(5), 'Client capture did not finish'
            packets = [p for frame in peer.recv() if (p := clients.dhcp_packet(bytes.fromhex(frame)))]
            snapshot = self.snapshot('lan10') if Path('/var/lib/dhcpv4-served-lan10/leases.json').exists() else None
            return dict(timed_out=timed_out, packets=packets,
                        addresses=state('address', 'show', 'dev', 'eth0'), routes=state('route'),
                        hook_events=clients.hook_events(out), lease_snapshot=snapshot)
        finally:
            ctl('stop', unit, check=False)
            (out / 'journal.txt').write_text(run('journalctl', '-b', '--no-pager', '-u', unit, check=False).stdout)

    def close(self, *, preserve_state=False):
        if not getattr(self, 'environment_checked', False):
            return super().close()
        try:
            for link in LINKS:
                unit = f'dhcpv4-served@{link}.service'
                (self.output / f'{link}-unit.txt').write_text(ctl('show', unit, check=False))
                (self.output / f'{link}-journal.txt').write_text(run('journalctl', '-b', '--no-pager', '-u', unit, check=False).stdout)
                if Path(f'/var/lib/dhcpv4-served-{link}/leases.json').exists():
                    self.snapshot(link)
            (self.output / 'journal.txt').write_text(run('journalctl', '-b', '--no-pager', check=False).stdout)
        finally:
            # Evidence failures must not leave a socket armed for the next test.
            try:
                for link in LINKS:
                    unit = f'dhcpv4-served@{link}.service'
                    ctl('stop', unit, f'dhcpv4-served@{link}.socket', check=False)
                    ctl('reset-failed', unit, f'dhcpv4-served@{link}.socket', check=False)
                    if not preserve_state:
                        ctl('clean', '--what=state', unit, check=False)
                override = Path('/run/systemd/system/dhcpv4-served@lan10.service.d/37-fault.conf')
                if override.exists():
                    override.unlink()
                    ctl('daemon-reload')
                if getattr(self, 'denied_state', None) is not None:
                    self.denied_state.cleanup()
                    self.denied_state = None
                ctl('stop', 'dhcpv4-served@peer.service', check=False)
                ctl('clean', '--what=state', 'dhcpv4-served@peer.service', check=False)
                ctl('stop', 'dhcpv4-served@probe.service', check=False)
                ctl('reset-failed', 'dhcpv4-served@probe.service', check=False)
                ctl('clean', '--what=state', 'dhcpv4-served@probe.service', check=False)
            finally:
                super().close()
