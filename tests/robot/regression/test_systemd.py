"""Host-safe regressions for the systemd Robot backend and sandbox probe."""
import errno
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from keywords.RealClients import RealClients
from harness.installation import UpdateSnapshot, check_update_activity, unit_enablement_links
from harness.systemd_fixture import (BASELINE_ENABLED_SERVICES, SystemdBackend,
                             configuration_rejections, listener_inventory, run)
from regression.test_keywords import acquisition
from harness import sandbox_probe


class SystemdBackendTests(unittest.TestCase):
    def test_control_failure_requires_no_reply_no_readiness_and_peer_survival(self):
        for failure, mutation in [(f, m) for f in ('Landlock unavailable', 'state access denied')
                                 for m in ('none', 'reply', 'ready', 'peer-exit', 'peer-state', 'namespace')]:
            with self.subTest(failure=failure, mutation=mutation), tempfile.TemporaryDirectory() as directory:
                backend = SystemdBackend('/unused/worker', directory)
                failed = SimpleNamespace(unit='dhcpv4-served@lan10.service', wait=lambda **_: 1, poll=lambda: 1)
                backend.workers = {'lan10': failed}
                backend.start = Mock()
                backend.commit_lease = Mock()
                backend.assign_client_address = Mock()
                backend.send_unicast_renewal = Mock()
                backend.snapshot = Mock(side_effect=[{'bindings': ['lease']},
                    {'bindings': ['changed' if mutation == 'peer-state' else 'lease']}])
                def exchange(link, *_):
                    backend.replies = ['unsafe reply'] if mutation == 'reply' and link == 'lan10' else []
                backend.exchange = Mock(side_effect=exchange)
                backend.check_reply = Mock()
                def property_value(unit, key):
                    if key == 'InvocationID':
                        return 'peer-invocation'
                    return 'failed' if mutation == 'peer-exit' and 'lan20' in unit else 'active'
                log = json.dumps(dict(event_id='state.failed', reason='permission') if failure == 'state access denied'
                                 else dict(event_id='startup.rejected', reason='abi_missing'))
                if mutation == 'namespace':
                    log = 'Failed at step NAMESPACE spawning /usr/libexec/dhcpv4-served'
                if mutation == 'ready':
                    log += '\n' + json.dumps(dict(event_id='worker.ready'))
                def mapped_path(path):
                    if str(path) == '/usr/lib/systemd/system/dhcpv4-served@.service':
                        return Path(__file__).resolve().parents[3] / 'deploy/systemd/dhcpv4-served@.service'
                    return Path(directory) / 'override' if str(path).startswith('/run/') else Path(path)
                with patch('harness.systemd_fixture.Path', side_effect=mapped_path), \
                        patch('harness.systemd_fixture.tempfile.TemporaryDirectory', return_value=SimpleNamespace(
                            name=directory + '/denied', cleanup=Mock())), \
                        patch('harness.systemd_fixture.ctl'), \
                        patch('harness.systemd_fixture.prop', side_effect=property_value), \
                        patch('harness.systemd_fixture.run', return_value=SimpleNamespace(stdout=log)):
                    if mutation == 'none':
                        backend.check_control_failure(failure)
                        backend.assign_client_address.assert_called_once_with('lan20')
                        backend.send_unicast_renewal.assert_called_once_with('lan20')
                        backend.check_reply.assert_called_once_with('lan20', message_type=5,
                                                                  dst='192.168.20.100', mac='020000000010')
                        self.assertTrue((Path(directory) / 'control-failure.json').exists())
                        if failure == 'state access denied':
                            override = (Path(directory) / 'override').read_text()
                            self.assertIn('ExecStart=\nExecStart=', override)
                            self.assertIn('--security-profile=strict', override)
                            self.assertIn('--state-dir ' + directory + '/denied', override)
                            self.assertNotIn('InaccessiblePaths', override)
                    else:
                        with self.assertRaises(AssertionError):
                            backend.check_control_failure(failure)

    def test_configuration_rejection_requires_a_fresh_worker_invocation(self):
        old = {'_SYSTEMD_INVOCATION_ID': 'old', 'MESSAGE': json.dumps(dict(event_id='startup.rejected', reason='config'))}
        fresh = {'_SYSTEMD_INVOCATION_ID': 'new', 'MESSAGE': json.dumps(dict(event_id='startup.rejected', reason='config'))}
        cases = [([old], False),
                 ([old, {'_SYSTEMD_INVOCATION_ID': 'new', 'MESSAGE': 'open lease state failed'}], False),
                 ([{'MESSAGE': json.dumps(dict(event_id='startup.rejected', reason='config'))}], False),
                 ([old, fresh], True)]
        for entries, success in cases:
            with self.subTest(entries=entries), patch('harness.systemd_fixture.run') as command:
                command.return_value.stdout = '\n'.join(json.dumps(e) for e in entries)
                if success:
                    self.assertEqual(configuration_rejections('worker.service', 'cursor', {'old'}), {'new'})
                else:
                    with self.assertRaises(AssertionError):
                        configuration_rejections('worker.service', 'cursor', {'old'})
                self.assertIn('--after-cursor=cursor', command.call_args.args)

    def test_each_config_fault_requires_recovery_and_an_uninterrupted_peer(self):
        for scenario in ('healthy', 'peer outage during fault', 'intermediate repair fails'):
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                config_dir = root / 'config'
                config_dir.mkdir()
                config = config_dir / 'lan10.yaml'
                backend = SystemdBackend('/unused/worker', root)
                owners, attempt, last_fault = {}, 0, None

                def fault():
                    if config.is_symlink():
                        return 'symlink'
                    if not config.exists():
                        return 'missing'
                    if config.stat().st_mode & 0o022:
                        return 'writable file'
                    if config_dir.stat().st_mode & 0o022:
                        return 'writable parent'
                    if owners.get(str(config), 0):
                        return 'untrusted file owner'
                    if owners.get(str(config_dir), 0):
                        return 'untrusted parent owner'
                    return None

                def control(action, *units, **kwargs):
                    nonlocal attempt
                    if action == 'start' and 'dhcpv4-served@lan10.socket' in units:
                        attempt += 1
                    return ''

                def property_value(unit, key):
                    if key == 'InvocationID':
                        return 'peer' if 'lan20' in unit else f'worker-{attempt}'
                    if key == 'MainPID':
                        return '0'
                    return 'failed' if 'lan10' in unit and fault() else 'active'

                def exchange(link, packet):
                    nonlocal last_fault
                    current = fault()
                    if link == 'lan10' and current:
                        last_fault = current
                    broken = ((link == 'lan10' and current)
                              or (link == 'lan20' and current and scenario == 'peer outage during fault')
                              or (link == 'lan10' and not current and last_fault != 'symlink'
                                  and scenario == 'intermediate repair fails'))
                    backend.replies = [] if broken else [link]
                    return backend.replies

                def check_reply(link):
                    self.assertEqual(backend.replies, [link])

                def journal(*args, **kwargs):
                    if '--lines=1' in args:
                        value = {'__CURSOR': f'cursor-{attempt}'}
                    else:
                        value = {'_SYSTEMD_INVOCATION_ID': f'worker-{attempt}',
                                 'MESSAGE': json.dumps(dict(event_id='startup.rejected', reason='config'))}
                    return SimpleNamespace(stdout=json.dumps(value))

                backend.exchange, backend.check_reply = exchange, check_reply
                with patch('harness.systemd_fixture.Path', return_value=config_dir), \
                        patch('harness.systemd_fixture.os.chown',
                              side_effect=lambda path, uid, gid: owners.update({str(path): uid})), \
                        patch('harness.systemd_fixture.ctl', side_effect=control), \
                        patch('harness.systemd_fixture.prop', side_effect=property_value), \
                        patch('harness.systemd_fixture.run', side_effect=journal):
                    if scenario != 'healthy':
                        with self.assertRaises(AssertionError):
                            backend.check_trusted_configuration()
                    else:
                        backend.check_trusted_configuration()
                        evidence = json.loads((root / 'trusted-config-evidence.json').read_text())
                        self.assertEqual({c['fault'] for c in evidence['cases']}, {
                            'writable file', 'writable parent', 'untrusted file owner',
                            'untrusted parent owner', 'symlink'})
                        for case in evidence['cases']:
                            self.assertTrue(case['rejected_invocations'])
                            self.assertTrue(case['recovered_invocation'])
                            self.assertEqual(case['peer_during_rejection'], 'peer')
                            self.assertEqual(case['peer_after_recovery'], 'peer')

    def test_update_rejects_transient_activation_even_when_dormant_again(self):
        before = UpdateSnapshot(True, 'initial', 'dormant', 'before-update', b'config', b'lease')
        with tempfile.TemporaryDirectory() as directory:
            backend = Mock(output=Path(directory))
            with patch('harness.installation.prop', return_value='dormant'), \
                    patch('harness.installation.unit_journal', return_value=[{'MESSAGE': 'worker started'}]) as journal:
                with self.assertRaisesRegex(AssertionError, 'unit activity'):
                    check_update_activity(backend, before)
                journal.assert_called_once_with('before-update', units=('dhcpv4-served@lan10.service',))
            evidence = json.loads((backend.output / 'update-invocations.json').read_text())
            self.assertEqual(evidence['before_update'], evidence['after_update'])
            self.assertTrue(evidence['journal'])

    def test_required_robot_case_must_pass_even_with_other_passing_cases(self):
        script = Path(__file__).resolve().parents[2] / 'systemd/check-robot-result.py'
        with tempfile.TemporaryDirectory() as directory:
            result = Path(directory) / 'output.xml'
            for statuses in ((), ('PASS',), ('SKIP',), ('FAIL',), ('PASS', 'PASS')):
                with self.subTest(statuses=statuses):
                    cases = ''.join(f'<test name="reboot"><status status="{status}"/></test>'
                                    for status in statuses)
                    result.write_text(f'<robot><suite>{cases}'
                                      '<test name="other"><status status="PASS"/></test>'
                                      '<test name="load"><status status="SKIP"/></test></suite></robot>')
                    command = run(sys.executable, str(script), str(result), 'reboot', check=False)
                    self.assertEqual(command.returncode, 0 if statuses == ('PASS',) else 1, command.stderr)

    def test_instance_enablement_includes_target_dependency_links(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            template = root / 'dhcpv4-served@.socket'
            template.touch()
            target = root / 'sockets.target.wants'
            target.mkdir()
            selected = target / 'dhcpv4-served@lan10.socket'
            selected.symlink_to(template)
            (target / 'other.socket').symlink_to(template)
            with patch('harness.installation.run', return_value=SimpleNamespace(stdout=directory)):
                self.assertEqual(unit_enablement_links(), [selected])

    def test_listener_inventory_tracks_only_listening_sockets(self):
        rows = {
            'tcp': 'header\n 0: 0100007F:0016 00000000:0000 0A 0:0 0:0 0 0 0 123\n'
                   ' 1: 0100007F:0017 00000000:0000 01 0:0 0:0 0 0 0 124\n',
            'udp': 'header\n 0: 00000000:0043 00000000:0000 07 0:0 0:0 0 0 0 456\n'
                   ' 1: 0100007F:2328 0100007F:0009 01 0:0 0:0 0 0 0 457\n'
                   ' 2: 00000000:0000 00000000:0000 07 0:0 0:0 0 0 0 458\n',
            'tcp6': 'header\n',
            'udp6': 'header\n 0: 00000000000000000000000001000000:2329 '
                    '00000000000000000000000001000000:0009 01 0:0 0:0 0 0 0 459\n',
        }
        with patch('harness.systemd_fixture.Path.read_text', autospec=True,
                   side_effect=lambda path: rows[path.name]):
            self.assertEqual(listener_inventory(), {
                ('tcp', '0100007F:0016', '123'), ('udp', '00000000:0043', '456'),
                ('udp', '0100007F:2328', '457'), ('udp6', '00000000000000000000000001000000:2329', '459')})

    def test_listener_lifecycle_rejects_unapproved_initial_exposure(self):
        cases = [({('tcp', '00000000:2328', '999')}, BASELINE_ENABLED_SERVICES),
                 ({('udp', '00000000:2328', '999')}, BASELINE_ENABLED_SERVICES),
                 (set(), BASELINE_ENABLED_SERVICES | {'unexpected-admin.service'}),
                 (set(), BASELINE_ENABLED_SERVICES - {'dhcpv4-served-test.service'})]
        for listeners, services in cases:
            with self.subTest(listeners=listeners, services=services), tempfile.TemporaryDirectory() as directory:
                backend = SystemdBackend('/unused/worker', directory)
                with patch('harness.systemd_fixture.listener_inventory',
                           side_effect=[listeners, listeners | {('udp', '00000000:0043', '123')}, listeners]), \
                        patch('harness.systemd_fixture.enabled_services', return_value=services), \
                        patch('harness.systemd_fixture.ctl', return_value='disabled'), \
                        patch('harness.systemd_fixture.prop', side_effect=lambda unit, key:
                              'lan10' if key == 'BindToDevice' else 'inactive'):
                    with self.assertRaises(AssertionError):
                        backend.check_listener_lifecycle()

    def test_listener_lifecycle_accepts_only_the_expected_socket_addition(self):
        for added in ({('udp', '00000000:0043', '123')},
                      {('udp', '00000000:0043', '123'), ('tcp', '00000000:2328', '999')}):
            with self.subTest(added=added), tempfile.TemporaryDirectory() as directory:
                backend = SystemdBackend('/unused/worker', directory)
                with patch('harness.systemd_fixture.listener_inventory', side_effect=[set(), added, set()]), \
                        patch('harness.systemd_fixture.enabled_services', return_value=BASELINE_ENABLED_SERVICES), \
                        patch('harness.systemd_fixture.ctl', return_value='disabled'), \
                        patch('harness.systemd_fixture.prop', side_effect=lambda unit, key:
                              'lan10' if key == 'BindToDevice' else 'inactive'):
                    if len(added) == 1:
                        backend.check_listener_lifecycle()
                    else:
                        with self.assertRaises(AssertionError):
                            backend.check_listener_lifecycle()

    def test_environment_guard_and_teardown_do_not_touch_the_host(self):
        for uid, marker in ((1000, True), (0, False)):
            with self.subTest(uid=uid, marker=marker), \
                    patch('harness.systemd_fixture.os.geteuid', return_value=uid), \
                    patch('harness.systemd_fixture.Path.is_file', return_value=marker), \
                    patch('harness.systemd_fixture.run') as command:
                backend = SystemdBackend('/unused/worker', '/unused/output')
                with self.assertRaisesRegex(RuntimeError, 'booted dhcpv4-served'):
                    backend.create()
                backend.close()
                command.assert_not_called()

    def test_default_configuration_requires_dns_and_cleans_up_resolved(self):
        dns = ['192.0.2.53', '198.51.100.53']
        for advertised in (dns, dns[:1], dns + ['203.0.113.53']):
            with self.subTest(advertised=advertised), tempfile.TemporaryDirectory() as directory:
                backend = SystemdBackend('/unused/worker', directory)
                (Path(directory) / 'config').write_text('fixture')
                backend.start = Mock()
                backend.snapshot = Mock(return_value={'bindings': [{'address': '192.168.10.2'}]})
                def exchange(link, packet):
                    backend.replies = [{'type': 5 if packet[242] == 3 else 2,
                                        'yiaddr': '192.168.10.2',
                                        'router': ['192.168.10.1'], 'dns': advertised}]
                backend.exchange = Mock(side_effect=exchange)
                with patch('harness.systemd_fixture.Path', return_value=Path(directory) / 'config'), \
                        patch('harness.systemd_fixture.ctl') as control, \
                        patch('harness.systemd_fixture.run') as command:
                    if advertised == dns:
                        backend.check_default_configuration()
                    else:
                        with self.assertRaises(AssertionError):
                            backend.check_default_configuration()
                    control.assert_any_call('stop', 'systemd-resolved.service',
                                            'systemd-resolved-varlink.socket',
                                            'systemd-resolved-monitor.socket', check=False)
                    command.assert_any_call('resolvectl', 'revert', 'lan10', check=False)
                    command.assert_any_call('resolvectl', 'revert', 'lan20', check=False)

    def test_unconfigured_topology_preserves_reboot_configuration(self):
        with tempfile.TemporaryDirectory() as directory:
            config_dir = Path(directory)
            config = config_dir / 'lan10.yaml'
            config.write_text('saved configuration')
            backend = SystemdBackend('/unused/worker', directory)
            with patch('harness.namespace_driver.FastBackend.create'), \
                    patch('harness.systemd_fixture.Path', return_value=config_dir), \
                    patch('harness.systemd_fixture.ctl'):
                backend.create(configure=False)
                self.assertEqual(config.read_text(), 'saved configuration')
                backend.clear_configuration()
            self.assertFalse(config.exists())

    def test_real_client_dispatches_through_systemd_and_keeps_robot_assertions(self):
        with tempfile.TemporaryDirectory() as directory:
            library = RealClients(backend='systemd', output=directory)
            library.client, library.binary = 'dhclient', '/unused/dhclient'
            library.output.mkdir(parents=True)
            with patch('harness.systemd_fixture.SystemdBackend') as backend, patch('keywords.RealClients.subprocess.run') as version:
                version.return_value = SimpleNamespace(stdout='test version', stderr='')
                backend.return_value.run_real_client.return_value = acquisition()
                library.the_real_dhcp_client_requests_a_lease()
                backend.return_value.create.assert_called_once_with(configure=False)
                backend.return_value.clear_configuration.assert_called_once_with()
                self.assertFalse(backend.return_value.client_bind_port)
                library.the_client_acquires_a_valid_lease_and_the_server_persists_it()
                library.clean_up_the_real_client_topology()
                backend.return_value.close.assert_called_once()

    def test_sandbox_requires_denial_and_rejects_unrelated_errors(self):
        def error(number):
            raise OSError(number, 'probe')

        for number in (errno.EPERM, errno.EACCES, errno.EROFS, errno.EAFNOSUPPORT):
            sandbox_probe.denied(lambda: error(number))
        with self.assertRaises(AssertionError):
            sandbox_probe.denied(lambda: None)
        for number in (errno.ENOENT, errno.ENOSYS, errno.EADDRINUSE):
            with self.subTest(errno=number), self.assertRaises(AssertionError):
                sandbox_probe.denied(lambda: error(number))

    def test_failed_commands_include_diagnostics(self):
        with self.assertRaisesRegex(RuntimeError, 'failure detail'):
            run(sys.executable, '-c', 'import sys; sys.exit("failure detail")')

    def test_peer_isolation_accepts_hidden_paths_but_rejects_access(self):
        with tempfile.TemporaryDirectory() as directory:
            peer = Path(directory) / 'hidden-peer' / 'private'
            operations = (peer.read_text, lambda: peer.write_text('changed'))
            for operation in operations:
                # A private mount can hide the parent, so both read and write
                # return ENOENT. Other denial checks must still reject ENOENT.
                sandbox_probe.denied(operation, allow_hidden_peer=True)
                with self.assertRaises(AssertionError):
                    sandbox_probe.denied(operation)
            peer.parent.mkdir()
            peer.write_text('peer state')
            for operation in operations:
                with self.assertRaises(AssertionError):
                    sandbox_probe.denied(operation, allow_hidden_peer=True)
        for number in (errno.ENOSYS, errno.EADDRINUSE):
            def unrelated_error():
                raise OSError(number, 'probe')
            with self.subTest(errno=number), self.assertRaises(AssertionError):
                sandbox_probe.denied(unrelated_error, allow_hidden_peer=True)
