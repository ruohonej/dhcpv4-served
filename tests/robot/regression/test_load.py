"""Host-safe regressions for false-positive load evidence acceptance."""
import unittest
from collections import deque
from pathlib import Path
import socket
import struct
import tempfile
from unittest.mock import patch

from harness.load import AckLedger, assess, client, LINKS


def successful_evidence():
    phases = []
    for index in range(7):
        duration = 120 if index == 6 else 60
        flood = bool(index % 2 or index == 6)
        occupancy = (0, 80, 100)[min(index // 2, 2)]
        count = max(10, -(-128 * occupancy // 100))
        name = 'soak' if index == 6 else f'{occupancy}-' + ('flood' if flood else 'baseline')
        phases.append(dict(name=name, flood=flood, duration=duration, start=1000,
            requested_occupancy_percent=occupancy, actual_occupancy_percent=100*count/128,
            pids=dict.fromkeys(LINKS, 123),
            clients={link: dict(flood_sent=duration * 1000 if flood and link == 'lan10' else 0,
                renewals=duration * 10, latencies=[.1] * (duration * 10),
                leased=count, started_at=1000, finished_at=1000+duration+4,
                unsafe_acks=0, duplicate_grants=False) for link in LINKS},
            ingress=dict(flood=duration * 1000 if flood else 0, capture_drops=0,
                         flood_per_second={str(s): 1000 for s in range(duration)} if flood else {}),
            resources=[{link: dict(state='active', pid=123, rss_bytes=1000000, tasks=10,
                systemd=dict(MemoryMax='268435456', TasksMax='128', CPUQuotaPerSecUSec='500ms'))
                for link in LINKS}]))
    return dict(phases=phases)


class LoadEvidenceTests(unittest.TestCase):
    def test_complete_measured_evidence(self):
        self.assertEqual(assess(successful_evidence())['status'], 'pass')

    def test_peer_renewal_failure_cannot_hide_behind_flooded_worker(self):
        report = successful_evidence()
        report['phases'][1]['clients']['lan20']['latencies'] = [.1] * 590
        self.assertEqual(assess(report)['status'], 'fail')

    def test_latency_and_unsafe_ack_fail_independently(self):
        for field, value in (('latencies', [2.1] * 600), ('unsafe_acks', 1),
                             ('duplicate_grants', True)):
            with self.subTest(field=field):
                report = successful_evidence()
                report['phases'][1]['clients']['lan10'][field] = value
                self.assertEqual(assess(report)['status'], 'fail')

    def test_underdriven_or_unobservable_flood_is_invalid(self):
        for field, value in (('flood', 59999), ('capture_drops', 1)):
            with self.subTest(field=field):
                report = successful_evidence()
                report['phases'][1]['ingress'][field] = value
                self.assertEqual(assess(report)['status'], 'invalid')

    def test_restart_and_missing_production_limit_fail(self):
        for field, value in (('pid', 124), ('systemd', dict(MemoryMax='infinity',
                               TasksMax='128', CPUQuotaPerSecUSec='500ms'))):
            with self.subTest(field=field):
                report = successful_evidence()
                report['phases'][1]['resources'][0]['lan20'][field] = value
                self.assertEqual(assess(report)['status'], 'fail')

    def test_resource_peak_above_budget_fails(self):
        report = successful_evidence()
        report['phases'][1]['resources'][0]['lan20']['rss_bytes'] = 257 * 1024 * 1024
        self.assertEqual(assess(report)['status'], 'fail')

    def test_missing_phases_or_samples_are_invalid(self):
        report = successful_evidence()
        report['phases'][0]['resources'] = []
        self.assertEqual(assess(report)['status'], 'invalid')
        report = successful_evidence()
        report['phases'].pop()
        self.assertEqual(assess(report)['status'], 'invalid')

    def test_shortened_repeated_or_baseline_only_profiles_are_invalid(self):
        for mutation in ('shorten', 'baseline-only', 'repeat', 'occupancy', 'short-window'):
            with self.subTest(mutation=mutation):
                report = successful_evidence()
                if mutation == 'shorten':
                    for phase in report['phases']:
                        phase['duration'] = 1
                elif mutation == 'baseline-only':
                    for phase in report['phases']:
                        phase['flood'] = False
                elif mutation == 'repeat':
                    report['phases'][-1] = report['phases'][0]
                elif mutation == 'occupancy':
                    report['phases'][2]['requested_occupancy_percent'] = 0
                else:
                    report['phases'][1]['clients']['lan10']['finished_at'] = 1001
                self.assertEqual(assess(report)['status'], 'invalid')

    def test_missing_late_or_bunched_ingress_is_invalid(self):
        for buckets in ({'0': 60000}, {}, {str(s+1): 1000 for s in range(60)},
                        {str(s): (900 if s % 2 else 1100) for s in range(60)}):
            with self.subTest(buckets=buckets):
                report = successful_evidence()
                report['phases'][1]['ingress']['flood_per_second'] = buckets
                self.assertEqual(assess(report)['status'], 'invalid')

    def test_boundary_jitter_preserves_exact_total(self):
        report = successful_evidence()
        report['phases'][1]['ingress']['flood_per_second'].update({'0': 950, '1': 1050})
        self.assertEqual(assess(report)['status'], 'pass')

    def test_only_expected_completed_ack_duplicates_are_ignored(self):
        ledger = AckLedger('192.168.10.1')
        valid = dict(type=5, xid=1, client_id=b'owner'.hex(), yiaddr='192.168.10.100',
                     server='192.168.10.1', src='192.168.10.1', dst='192.168.10.100', mac='020000000010')
        ledger.expect(1, b'owner', '192.168.10.100', 100)
        self.assertTrue(ledger.observe(valid, 100.1))
        self.assertTrue(ledger.observe(valid, 100.2))
        self.assertEqual(len(ledger.latencies), 1)
        self.assertFalse(ledger.observe(dict(valid, xid=0x80000000), 100.3))
        self.assertFalse(ledger.observe(dict(valid, yiaddr='192.168.10.101'), 100.4))
        self.assertFalse(ledger.observe(dict(valid, src='192.168.10.2'), 100.5))
        self.assertEqual(ledger.unsafe, 3)

    def test_renewal_requires_unicast_at_ip_and_ethernet_layers(self):
        ledger = AckLedger('192.168.10.1')
        address = '192.168.10.100'
        ledger.expect(1, b'owner', address, 100)
        valid = dict(type=5, xid=1, client_id=b'owner'.hex(), yiaddr=address,
                     server=ledger.server, src=ledger.server, dst=address, mac='020000000010')
        for change in [dict(dst='255.255.255.255'), dict(mac='ffffffffffff'),
                       dict(dst='192.168.10.101'), dict(mac='020000000011')]:
            with self.subTest(change=change):
                self.assertFalse(ledger.observe(dict(valid, **change), 100.1))
                self.assertEqual(ledger.latencies, [])
        self.assertTrue(ledger.observe(valid, 100.2))
        self.assertEqual(ledger.unsafe, 4)

    def test_late_expected_ack_cannot_satisfy_renewal_budget(self):
        ledger = AckLedger('192.168.10.1')
        ledger.expect(1, b'owner', '192.168.10.100', 100)
        ledger.expire(104.1)
        valid = dict(type=5, xid=1, client_id=b'owner'.hex(), yiaddr='192.168.10.100',
                     server='192.168.10.1', src='192.168.10.1', dst='192.168.10.100', mac='020000000010')
        self.assertTrue(ledger.observe(valid, 104.2))
        self.assertEqual(ledger.latencies, [])
        self.assertEqual(ledger.unsafe, 0)

    def test_client_configures_addresses_and_checks_every_ack(self):
        configured, clock = set(), [0.0]
        server_mac = bytes.fromhex('020000000001')

        class Raw:
            def __init__(self):
                self.queue = deque()
                self.renewals = 0

            def bind(self, *_):
                pass

            def setblocking(self, *_):
                pass

            def send(self, frame):
                payload = frame[42:]
                xid = struct.unpack('!I', payload[4:8])[0]
                cid = payload[245:245+payload[244]]
                address = '192.168.10.' + str(100 + int(cid.decode().split('-')[1]))
                reply = dict(type=2 if payload[242] == 1 else 5, xid=xid,
                             yiaddr=address, client_id=cid.hex(),
                             server='192.168.10.1', src='192.168.10.1', dst='255.255.255.255', mac='ffffffffffff')
                if payload[12:16] != b'\0' * 4:
                    # Model unicast delivery: no ACK if ARP or source setup is
                    # missing, even though broadcast acquisition succeeded.
                    if address not in configured or socket.inet_ntoa(frame[26:30]) != address:
                        return
                    if frame[:6] != server_mac or socket.inet_ntoa(frame[30:34]) != '192.168.10.1':
                        raise AssertionError('renewal did not target the server')
                    reply.update(dst=address, mac='020000000010')
                    self.renewals += 1
                    self.queue.append(dict(reply, xid=0x80000000 | xid, client_id='626164'))
                    self.queue.append(reply)  # a verified retry must not count twice
                self.queue.append(reply)

            def recv(self, *_):
                return self.queue.popleft()

        raw = Raw()
        def sleep(duration):
            clock[0] += max(duration, .01)
        def ready(*_):
            return ([raw] if raw.queue else [], [], [])
        def configure(*args):
            self.assertEqual(args[:2], ('address', 'add'))
            self.assertEqual(args[3:], ('dev', 'eth0'))
            configured.add(args[2].split('/')[0])

        with tempfile.TemporaryDirectory() as directory:
            start = Path(directory) / 'start'
            start.write_text('0')
            with patch('harness.load.socket.socket', return_value=raw), \
                    patch('harness.load.select.select', side_effect=ready), \
                    patch('harness.load.packet.decode', side_effect=lambda value: value), \
                    patch('harness.load.packet.ip', side_effect=configure), \
                    patch('harness.load.time.monotonic', side_effect=lambda: clock[0]), \
                    patch('harness.load.time.sleep', side_effect=sleep):
                result = client('lan10', 2, 1, False, start, server_mac)
        self.assertEqual(configured, {'192.168.10.100', '192.168.10.101'})
        self.assertEqual(result['renewals'], 2)
        self.assertEqual(len(result['latencies']), 2)
        self.assertEqual(result['unsafe_acks'], 2)
