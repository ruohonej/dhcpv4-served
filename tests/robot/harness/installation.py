"""Acceptance checks for the actual installed Ubuntu DEB and its defaults."""
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path

from harness import fixtures as probe
from harness.systemd_fixture import (BASELINE_ENABLED_SERVICES, HERE, LINKS, ctl, enabled_services,
                             journal_cursor, listener_inventory, prop, run)

LINK = 'lan10'
SOCKET = f'dhcpv4-served@{LINK}.socket'
SERVICE = f'dhcpv4-served@{LINK}.service'
CONFIG = Path('/etc/dhcpv4-served/lan10.yaml')
STATE = Path('/var/lib/private/dhcpv4-served-lan10/leases.json')
CANDIDATE = HERE / 'packages/candidate.deb'
PREVIOUS = HERE / 'packages/previous.deb'
REBOOT_EVIDENCE = Path('/test-output/install-reboot-state.json')
BOOT_ID = Path('/proc/sys/kernel/random/boot_id')
UNIT_PATTERNS = ('dhcpv4-served@*.socket', 'dhcpv4-served@*.service')
MINIMAL_CONFIG = """pool:
  start: 192.168.10.100
  end: 192.168.10.103
lease_duration: 12h
offer_duration: 60s
decline_duration: 10m
"""


def unit_journal(cursor=None, *, units=(SOCKET, SERVICE, *UNIT_PATTERNS)):
    run('journalctl', '--sync')
    args = ['journalctl', '--boot', '--quiet', '--no-pager', '--output=json']
    args.extend(f'--unit={unit}' for unit in units)
    if cursor:
        args.append('--after-cursor=' + cursor)
    return [json.loads(line) for line in run(*args).stdout.splitlines()]


def unit_enablement_links():
    # list-unit-files sees templates in the search path but omits instances
    # that exist only as dependency links below a target.
    paths = run('systemd-analyze', 'unit-paths').stdout.splitlines()
    return sorted({
        link for path in paths for relation in ('wants', 'requires', 'upholds')
        for pattern in UNIT_PATTERNS for link in Path(path).glob(f'*.{relation}/{pattern}')
        if link.is_symlink()
    })


def inventory(backend, stage, *, armed=False):
    listeners = listener_inventory()
    units = ctl('list-unit-files', '--no-pager', '--no-legend', *UNIT_PATTERNS)
    enablement_links = unit_enablement_links()
    socket_state = ctl('is-enabled', SOCKET, check=False)
    active = ctl('list-units', '--state=active,activating,reloading,deactivating',
                 '--no-pager', '--no-legend', '--plain', *UNIT_PATTERNS)
    services = enabled_services()
    ss = run('ss', '-H', '-luntp').stdout
    properties = {unit: ctl('show', unit, '--property=ActiveState,MainPID,InvocationID,'
                            'UnitFileState,UnitFilePreset,BindToDevice,Listen')
                  for unit in (SOCKET, SERVICE, 'dhcpv4-served@lan20.socket', 'dhcpv4-served@lan20.service')}
    (backend.output / f'{stage}-inventory.json').write_text(json.dumps({
        'listeners': sorted(listeners), 'ss': ss, 'unit_files': units,
        'enablement_links': [str(link) for link in enablement_links], 'socket_state': socket_state,
        'active': active, 'enabled_services': sorted(services), 'properties': properties,
    }, indent=2))

    enabled_units = {link.name for link in enablement_links}
    active_units = {line.split()[0] for line in active.splitlines()}
    assert services == BASELINE_ENABLED_SERVICES, services ^ BASELINE_ENABLED_SERVICES
    if armed:
        assert socket_state == 'enabled', socket_state
        assert enabled_units == {SOCKET}, enabled_units
        assert SOCKET in active_units <= {SOCKET, SERVICE}, active_units
        assert prop(SOCKET, 'BindToDevice') == LINK
        assert len(listeners) == 1 and {(p, addr) for p, addr, _ in listeners} == {
            ('udp', '00000000:0043')}, listeners
        assert f'%{LINK}:67' in ss, ss
    else:
        assert socket_state == 'disabled', socket_state
        assert not (enabled_units or active_units or listeners), (enablement_links, active, listeners)
        backend.check_dormant()


def install(backend, package, stage):
    result = run('dpkg', '--install', str(package), check=False)
    (backend.output / f'{stage}-dpkg.txt').write_text(
        run('sha256sum', str(package)).stdout + result.stdout + result.stderr)
    assert result.returncode == 0, f'{stage}: dpkg failed with status {result.returncode}'
    expected = run('dpkg-deb', '-f', str(package), 'Version').stdout.strip()
    status = run('dpkg-query', '-W', '-f=${db:Status-Status} ${Version}', 'dhcpv4-served').stdout
    assert status == f'installed {expected}', status
    ctl('daemon-reload')


def assert_no_activation(backend, stage, *, since_boot=False):
    before = {link: prop(f'dhcpv4-served@{link}.service', 'InvocationID') for link in LINKS}
    cursor = None if since_boot else journal_cursor()
    for xid in (0x87654321, 0x87654322):
        for link in LINKS:
            assert backend.exchange(link, probe.request(xid=xid)) == [], f'{stage}: reply on {link}'
    after = {link: prop(f'dhcpv4-served@{link}.service', 'InvocationID') for link in LINKS}
    entries = unit_journal(cursor)
    (backend.output / f'{stage}-invocations.json').write_text(json.dumps({
        'before': before, 'after': after, 'journal': entries,
    }, indent=2))
    assert after == before, (before, after)
    assert not entries, f'{stage}: unexpected DHCP unit activity'
    inventory(backend, stage)


def arm(backend):
    CONFIG.parent.mkdir(mode=0o755)
    CONFIG.write_text(MINIMAL_CONFIG)
    CONFIG.chmod(0o644)
    run(backend.worker, 'validate', str(CONFIG))
    ctl('enable', '--now', SOCKET)
    inventory(backend, 'armed', armed=True)
    backend.check_dormant()


def disarm(*, check=True):
    ctl('disable', '--now', SOCKET, check=check)
    ctl('stop', SERVICE, check=check)


def grant_lease(backend):
    backend.exchange(LINK, probe.request(3, server='192.168.10.1', address='192.168.10.100'),
                     include_option_codes=True)
    backend.check_reply(LINK, message_type=5, minimal=True)


def request_existing_lease(backend):
    backend.exchange(LINK, probe.request(3, address='192.168.10.100'), include_option_codes=True)


def check_recovered_lease(backend):
    backend.check_reply(LINK, message_type=5, minimal=True)
    invocation = prop(SERVICE, 'InvocationID')
    assert invocation and prop(SERVICE, 'MainPID') != '0'
    return invocation


def check_installation(backend):
    manifest = json.loads((CANDIDATE.parent / 'candidate.json').read_text())
    assert hashlib.sha256(CANDIDATE.read_bytes()).hexdigest() == manifest['sha256']
    assert not CONFIG.parent.exists(), 'Fresh package created active configuration'
    assert not any(Path('/var/lib/private').glob('dhcpv4-served-*')), 'Fresh package created instance state'
    inventory(backend, 'fresh-boot')
    assert_no_activation(backend, 'fresh-boot-traffic', since_boot=True)
    try:
        arm(backend)
        assert backend.exchange('lan20', probe.request()) == [], 'Unselected link replied'
        backend.check_dormant()
        backend.monitor_other_link(LINK)
        backend.exchange(LINK, probe.request(), include_option_codes=True)
        backend.check_reply(LINK, minimal=True)
        backend.check_other_link()
        first = prop(SERVICE, 'InvocationID')
        assert first and prop(SERVICE, 'MainPID') != '0'
        grant_lease(backend)
        assert backend.exchange(LINK, probe.request(3, address='192.168.20.100')) == [], 'Default sent a NAK'
        assert not Path('/var/lib/private/dhcpv4-served-lan20').exists(), 'Unselected link created state'

        ctl('stop', SERVICE)
        inventory(backend, 'worker-stopped', armed=True)
        backend.check_dormant()
        request_existing_lease(backend)
        reactivated = check_recovered_lease(backend)
        assert reactivated != first
        (backend.output / 'activation-invocations.json').write_text(json.dumps({
            'first_discover': first, 'after_service_stop': reactivated,
        }, indent=2))
        disarm()
        assert_no_activation(backend, 'disabled')
    finally:
        disarm(check=False)


@dataclass(frozen=True)
class UpdateSnapshot:
    armed: bool
    initial: str
    dormant: str
    cursor: str
    config_bytes: bytes
    state_bytes: bytes


def prepare_update(backend, *, armed):
    starting_package = PREVIOUS if PREVIOUS.is_file() else CANDIDATE
    starting_version = run('dpkg-deb', '-f', str(starting_package), 'Version').stdout.strip()
    installed = run('dpkg-query', '-W', '-f=${Version}', 'dhcpv4-served').stdout
    assert installed == starting_version, f'Expected pristine {starting_version}, got {installed}'
    candidate_version = run('dpkg-deb', '-f', str(CANDIDATE), 'Version').stdout.strip()
    (backend.output / 'update-versions.json').write_text(json.dumps({
        'mode': 'upgrade' if PREVIOUS.is_file() else 'reinstall',
        'installed_before': installed, 'candidate': candidate_version,
        'installed_worker': run(backend.worker, '--version').stdout.strip(),
    }, indent=2))
    assert not CONFIG.parent.exists(), 'Upgrade must start with an independent image'
    assert not STATE.exists(), 'Upgrade must seed its own lease'
    inventory(backend, 'before-provisioning')
    arm(backend)
    backend.exchange(LINK, probe.request(), include_option_codes=True)
    backend.check_reply(LINK, minimal=True)
    grant_lease(backend)
    initial = prop(SERVICE, 'InvocationID')

    if armed:
        ctl('stop', SERVICE)
    else:
        disarm()
    backend.check_dormant()
    inventory(backend, 'before-update', armed=armed)
    config_bytes = CONFIG.read_bytes()
    state_bytes = STATE.read_bytes()
    dormant = prop(SERVICE, 'InvocationID')
    cursor = journal_cursor()
    return UpdateSnapshot(armed, initial, dormant, cursor, config_bytes, state_bytes)


def check_update_activity(backend, before):
    after = prop(SERVICE, 'InvocationID')
    units = (SERVICE,) if before.armed else (SOCKET, SERVICE, *UNIT_PATTERNS)
    entries = unit_journal(before.cursor, units=units)
    (backend.output / 'update-invocations.json').write_text(json.dumps({
        'lease_created': before.initial, 'before_update': before.dormant,
        'after_update': after, 'journal': entries,
    }, indent=2))
    assert after == before.dormant and not entries, 'Package update caused DHCP unit activity'
    backend.check_dormant()
    inventory(backend, 'after-update', armed=before.armed)


def check_update_files(before):
    assert CONFIG.read_bytes() == before.config_bytes, 'Configuration changed during update'
    assert STATE.read_bytes() == before.state_bytes, 'Lease state changed during update'


def check_reactivation(backend, before):
    invocation = check_recovered_lease(backend)
    assert invocation not in (before.initial, before.dormant), 'Expected first post-update invocation from traffic'
    (backend.output / 'post-update-invocation.txt').write_text(invocation + '\n')


def check_disabled_update(backend, before):
    assert_no_activation(backend, 'disabled-update')
    REBOOT_EVIDENCE.write_text(json.dumps({
        'boot_id': BOOT_ID.read_text().strip(),
        'state_sha256': hashlib.sha256(before.state_bytes).hexdigest(),
    }, indent=2))


def check_after_reboot(backend):
    previous = json.loads(REBOOT_EVIDENCE.read_text())
    assert BOOT_ID.read_text().strip() != previous['boot_id'], 'Expected a new nspawn boot'
    assert CONFIG.read_text() == MINIMAL_CONFIG
    assert hashlib.sha256(STATE.read_bytes()).hexdigest() == previous['state_sha256']
    assert_no_activation(backend, 'disabled-after-reboot', since_boot=True)
    try:
        # Start only after checking that the previous disablement survived
        # reboot. Exercise the candidate's first read of the previous lease.
        ctl('start', SOCKET)
        backend.check_dormant()
        request_existing_lease(backend)
        invocation = check_recovered_lease(backend)
        (backend.output / 'post-reboot-invocation.txt').write_text(invocation + '\n')
    finally:
        disarm(check=False)
