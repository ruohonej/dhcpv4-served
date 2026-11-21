"""Regression checks for assertions that previously allowed false positives."""
from copy import deepcopy
import json
from pathlib import Path
import socket
import struct
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from keywords.DhcpIntegration import DhcpIntegration
from harness.namespace_driver import FastBackend
from harness.dhcp_packets import parse
from keywords.RealClients import RealClients
from harness import real_client_fixture as clients
from harness import fixtures as probe


def competing_offer():
    return {
        'src': '192.168.10.1', 'dst': '255.255.255.255', 'mac': 'ff' * 6,
        'yiaddr': '192.168.10.103', 'xid': 0x12345678, 'type': 2,
        'server': '192.168.10.1', 'client_id': b'other'.hex(),
        'router': ['192.168.10.1', '192.168.10.102'], 'dns': ['192.168.10.1'],
        'domain': 'lan10.example', 'ntp': '192.168.10.1',
    }


def acquisition():
    return {
        'timed_out': False,
        'addresses': [{'addr_info': [{'local': clients.ADDRESS, 'prefixlen': 24}]}],
        'routes': [{'dst': 'default', 'gateway': clients.SERVER}],
        'hook_events': [{'reason': 'BOUND'}],
        'packets': [dict(type=kind, xid=42, mac=clients.MAC, server=clients.SERVER,
                         source=clients.SERVER, address=clients.ADDRESS)
                    for kind in (1, 2, 3, 5)],
        'lease_snapshot': {'bindings': [{'address': clients.ADDRESS,
                                        'hardware': clients.MAC, 'state': 'leased'}]},
    }


class SyntheticKeywordTests(unittest.TestCase):
    def test_packet_decoder_preserves_multiple_dns_addresses(self):
        data = bytearray(probe.request())
        data[0] = 2
        options = bytes([53, 1, 2, 54, 4]) + socket.inet_aton('192.168.10.1')
        options += bytes([6, 8]) + socket.inet_aton('192.0.2.53') + socket.inet_aton('198.51.100.53')
        data[240:] = options + b'\xff'
        frame = bytearray(probe.ethernet(data))
        frame[34:38] = struct.pack('!HH', 67, 68)
        decoded = probe.decode(frame)
        self.assertEqual(decoded['dns'], ['192.0.2.53', '198.51.100.53'])

    def test_competing_offer_requires_valid_identity_and_delivery(self):
        library = DhcpIntegration()
        library.backend = FastBackend('/unused/worker', '/unused/output')
        valid = competing_offer()
        library.backend.replies = [valid]
        library.the_competing_client_receives_a_different_offer('port1')
        for field, value in {
            'type': 6, 'server': '203.0.113.1', 'client_id': b'probe'.hex(),
            'xid': 99, 'dst': '192.168.10.103', 'mac': '02' * 6,
        }.items():
            with self.subTest(field=field):
                library.backend.replies = [dict(valid, **{field: value})]
                with self.assertRaises(AssertionError):
                    library.the_competing_client_receives_a_different_offer('port1')

    def test_namespace_restart_reuses_state_until_teardown(self):
        with tempfile.TemporaryDirectory() as output, patch.dict('os.environ', DHCP_STARTUP_ROOT_HARNESS='1'):
            backend = FastBackend('worker', output)
            marker = Path('lan10-state') / 'lease'

            def start(binary, link, log, *, base):
                state = Path(base) / f'{link}-state'
                if state.exists():
                    self.assertEqual((state / 'lease').read_text(), link)
                else:
                    state.mkdir()
                    (state / 'lease').write_text(link)
                return Mock()

            with patch('harness.namespace_driver.probe.worker', side_effect=start), patch('harness.namespace_driver.probe.wait_for_worker'):
                backend.start()
                lease = Path(backend.state_root) / marker
                backend.restart()
                self.assertEqual((Path(backend.state_root) / marker), lease)
                self.assertEqual(lease.read_text(), 'lan10')
                backend.close()
                self.assertFalse(lease.exists())

    def test_each_startup_case_requires_its_expected_diagnostic(self):
        diagnostics = {
            'wrong interface': 'activation_device',
            'wrong descriptor name': 'activation',
            'wrong descriptor count': 'activation',
            'pool outside the subnet': 'config_link',
            'unexpected capabilities': 'privilege',
            'ambiguous server addresses': 'link_addresses',
            'worker-owned configuration': 'config_file',
            'untrusted configuration directory': 'config_directory',
        }
        with tempfile.TemporaryDirectory() as directory:
            backend = FastBackend('/unused/worker', directory)
            for reason, diagnostic in diagnostics.items():
                with self.subTest(reason=reason), patch('harness.namespace_driver.probe.worker') as worker, patch('harness.namespace_driver.probe.ip'):
                    worker.return_value.wait.return_value = 1
                    backend.start_invalid(reason)
                    backend.invalid_log.write_text('exec failed: missing executable\n')
                    with self.assertRaisesRegex(AssertionError, 'Expected startup diagnostic'):
                        backend.check_rejected()
                    backend.invalid_log.write_text(json.dumps(dict(event_id='startup.rejected', reason=diagnostic)) + '\n')
                    backend.check_rejected()
                    worker.return_value.wait.return_value = 0
                    with self.assertRaisesRegex(AssertionError, 'startup succeeded'):
                        backend.check_rejected()

    def test_renewal_uses_server_mac_and_unicast_ip(self):
        peer = Mock()
        peer.poll.return_value = True
        peer.recv.return_value = []
        library = DhcpIntegration()
        library.backend = FastBackend('/unused/worker', '/unused/output')
        library.backend.peers['lan10'] = peer
        server_mac = bytes.fromhex('020000000001')
        with patch('harness.namespace_driver.probe.link_mac', return_value=server_mac):
            library.the_configured_client_sends_a_unicast_renewal('port1')
        frame = bytes.fromhex(peer.send.call_args.args[0]['packet'])
        self.assertEqual(frame[:6], server_mac)
        self.assertEqual(socket.inet_ntoa(frame[26:30]), '192.168.10.100')
        self.assertEqual(socket.inet_ntoa(frame[30:34]), clients.SERVER)
        packet = clients.dhcp_packet(frame)
        self.assertIsNone(packet['server'], 'Renewal must omit the SELECTING server identifier')
        parsed, options = parse(frame)
        self.assertEqual(parsed['BOOTP'].ciaddr, '192.168.10.100')
        self.assertNotIn('requested_addr', options)
        self.assertEqual(packet['flags'], 0)


class RealClientKeywordTests(unittest.TestCase):
    def test_acquisition_requires_matching_dora(self):
        valid = acquisition()
        clients.check_acquisition(valid, 'dhclient')
        for field, value in {'type': 6, 'xid': 99, 'mac': '02:00:00:00:00:ff',
                             'server': '203.0.113.1', 'source': '203.0.113.1',
                             'address': '192.168.10.103'}.items():
            with self.subTest(field=field):
                evidence = deepcopy(valid)
                evidence['packets'][-1][field] = value
                with self.assertRaisesRegex(AssertionError, 'matching DORA'):
                    clients.check_acquisition(evidence, 'dhclient')
        evidence = deepcopy(valid)
        evidence['packets'].reverse()
        with self.assertRaisesRegex(AssertionError, 'matching DORA'):
            clients.check_acquisition(evidence, 'dhclient')

    def test_acquisition_requires_address_route_hook_and_durable_binding(self):
        for field, value in {
            'timed_out': True, 'addresses': [], 'routes': [], 'hook_events': [],
            'lease_snapshot': None,
        }.items():
            with self.subTest(field=field):
                evidence = acquisition()
                evidence[field] = value
                with self.assertRaises(AssertionError):
                    clients.check_acquisition(evidence, 'dhclient')
        for field, value in {'state': 'offered', 'hardware': '02:00:00:00:00:ff',
                             'address': '192.168.10.103'}.items():
            with self.subTest(binding_field=field):
                evidence = acquisition()
                evidence['lease_snapshot']['bindings'][0][field] = value
                with self.assertRaisesRegex(AssertionError, 'persist'):
                    clients.check_acquisition(evidence, 'dhclient')

    def test_networkd_does_not_require_hook_events(self):
        evidence = acquisition()
        evidence['hook_events'] = []
        clients.check_acquisition(evidence, 'systemd-networkd')

    def test_outcome_failure_is_reported_by_then_with_evidence_saved(self):
        with tempfile.TemporaryDirectory() as directory:
            library = RealClients(output=directory)
            library.client, library.binary = 'dhclient', '/unused/dhclient'
            library.output.mkdir(parents=True)
            evidence = acquisition()
            evidence['packets'] = []
            with patch('keywords.RealClients.fixture.run_case', return_value=evidence), patch('keywords.RealClients.subprocess.run') as version:
                version.return_value = SimpleNamespace(stdout='test version', stderr='')
                library.the_real_dhcp_client_requests_a_lease()
            self.assertTrue((library.run / 'evidence.json').is_file())
            self.assertFalse((library.run / 'results.json').exists())
            with self.assertRaisesRegex(AssertionError, 'matching DORA'):
                library.the_client_acquires_a_valid_lease_and_the_server_persists_it()
            result = json.loads((library.run / 'results.json').read_text())['dhclient']
            self.assertFalse(result['passed'])
            self.assertEqual(result['packets'], [])

    def test_success_is_recorded_after_then_validates_the_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            library = RealClients(output=directory)
            library.client = 'dhclient'
            library.run = Path(directory)
            library.result = acquisition()
            library.the_client_acquires_a_valid_lease_and_the_server_persists_it()
            result = json.loads((library.run / 'results.json').read_text())['dhclient']
            self.assertTrue(result['passed'])


if __name__ == '__main__':
    unittest.main()
