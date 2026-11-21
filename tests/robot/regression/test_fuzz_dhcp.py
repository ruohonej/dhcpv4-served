"""Host-safe checks for the stateful fuzz runner and replay evidence."""
from functools import partial
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from robot import run as run_robot
from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.l2 import Ether
from scapy.utils import PcapReader, PcapWriter
from harness import fixtures

from harness.fuzz_dhcp import execute, execute_packets, mutated_packets


class Peer:
    def __init__(self):
        self.response = None

    def send(self, message):
        if message['action'] == 'observe':
            self.response = 'observing'
        elif message['action'] == 'finish':
            self.response = []
        elif message['action'] == 'address':
            self.response = True

    def poll(self, timeout):
        return self.response is not None

    def recv(self):
        response, self.response = self.response, None
        return response


class FakeBackend:
    duplicate = False
    created = 0
    last = None

    def __init__(self, worker, output, state_root):
        self.peers = {link: Peer() for link in ('lan10', 'lan20')}
        self.leases = {'lan10': {}, 'lan20': {}}
        self.offers = {}
        self.output = Path(output)
        type(self).created += 1
        type(self).last = self
        self.requests = []

    def create(self):
        (self.output / 'lan10.pcap').write_bytes(b'capture')

    def start(self):
        pass

    def restart(self):
        pass

    def close(self):
        pass

    def exchange(self, link, payload, **kwargs):
        bootp = BOOTP(payload)
        opts = {option[0]: option[1] for option in bootp[DHCP].options if isinstance(option, tuple)}
        client = opts['client_id']
        number = link[3:]
        server = f'192.168.{number}.1'
        self.requests.append((link, bytes(payload)))
        if opts['message-type'] == 1:
            addresses = [f'192.168.{number}.100', f'192.168.{number}.103']
            used = set(self.leases[link].values()) | {address for (scope, _), address in self.offers.items() if scope == link}
            available = [address for address in addresses if address not in used]
            if self.duplicate and self.leases[link]:
                address = next(iter(self.leases[link].values()))
            elif not available:
                return []
            else:
                address = available[0]
            self.offers[(link, client)] = address
            kind = 2
        else:
            address = opts.get('requested_addr', bootp.ciaddr)
            if opts.get('server_id') == '192.0.2.254':
                self.offers.pop((link, client), None)
                return []
            self.offers.pop((link, client), None)
            self.leases[link][client] = address
            kind = 5
        return [dict(type=kind, client_id=client.hex(), xid=bootp.xid, server=server,
                     src=server, yiaddr=address)]


class StatefulFuzzTests(unittest.TestCase):
    def test_client_capture_is_visible_while_writer_is_open(self):
        class Pipe:
            def send(self, value):
                pass

            def recv(self):
                return {'action': 'stop'}

        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / 'capture.pcap')
            writer = PcapWriter(path, linktype=1, sync=True)
            frame = bytes(Ether(src='02:00:00:00:00:01', dst='ff:ff:ff:ff:ff:ff'))
            writer.write_header(None)
            writer.write(frame)
            with PcapReader(path) as reader:
                self.assertEqual(bytes(reader.read_packet()), frame)
            writer.close()
            with patch('harness.fixtures.ctypes.CDLL') as libc, patch('harness.fixtures.ip'), \
                    patch('harness.fixtures.socket.socket', return_value=MagicMock()), \
                    patch('harness.fixtures.PcapWriter', wraps=PcapWriter) as factory:
                libc.return_value.unshare.return_value = 0
                fixtures.client(Pipe(), path)
                factory.assert_called_once_with(path, linktype=1, sync=True)

    def test_robot_runs_replay_and_generated_sequences(self):
        suite = str(Path(__file__).resolve().parents[1] / 'suites/fuzz_and_replay.robot')
        with tempfile.TemporaryDirectory() as directory, patch('harness.fuzz_dhcp.execute') as execute_sequence:
            result = run_robot(suite, outputdir=directory, log='NONE', report='NONE',
                               console='none', variable=['EXAMPLES:2'],
                               test=['Replay DHCP sequence', 'Generate DHCP sequences'])
            self.assertEqual(result, 0)
            self.assertEqual(execute_sequence.call_count, 3)
            self.assertEqual(execute_sequence.call_args_list[0].args[0],
                             json.loads((Path(__file__).resolve().parents[1] / 'data/fuzz-replay.json').read_text()))
            self.assertTrue((Path(directory) / 'output.xml').is_file())

    def test_scapy_generates_varying_dhcp_datagrams(self):
        cases = mutated_packets(8)
        payloads = [bytes.fromhex(case['payload']) for case in cases]
        self.assertEqual(len(cases), 8)
        self.assertEqual({case['link'] for case in cases}, {'lan10', 'lan20'})
        self.assertGreater(len(set(payloads)), 1)
        self.assertTrue(all(len(payload) >= 240 and payload[236:240] == bytes.fromhex('63825363')
                            for payload in payloads))

    def test_robot_invokes_packet_fuzz_case(self):
        suite = str(Path(__file__).resolve().parents[1] / 'suites/fuzz_and_replay.robot')
        with tempfile.TemporaryDirectory() as directory, patch('harness.fuzz_dhcp.execute_packets') as execute_packets:
            result = run_robot(suite, outputdir=directory, log='NONE', report='NONE',
                               console='none', test=['Fuzz DHCP packet fields'], variable=['EXAMPLES:2'])
            self.assertEqual(result, 0)
            self.assertEqual(execute_packets.call_count, 2)
            self.assertEqual(execute_packets.call_args_list[0].args[0],
                             execute_packets.call_args_list[1].args[0])
            self.assertEqual(len(execute_packets.call_args_list[0].args[0]), 8)

    def test_packet_fuzz_sends_mutations_and_checks_leases(self):
        cases = mutated_packets(8)
        payloads = {bytes.fromhex(case['payload']) for case in cases}

        class PacketBackend(FakeBackend):
            def __init__(self, *args):
                super().__init__(*args)
                self.workers = {'lan10': MagicMock(), 'lan20': MagicMock()}
                for worker in self.workers.values():
                    worker.poll.return_value = None
                self.mutations = []

            def exchange(self, link, payload, **kwargs):
                if bytes(payload) in payloads:
                    self.mutations.append((link, bytes(payload)))
                    return []
                return super().exchange(link, payload, **kwargs)

        with tempfile.TemporaryDirectory() as directory:
            execute_packets(cases, '/unused', directory, backend_factory=PacketBackend)
            backend = PacketBackend.last
            self.assertEqual(backend.mutations, [(case['link'], bytes.fromhex(case['payload'])) for case in cases])
            self.assertEqual(len(backend.requests), 6)  # Acquire and then renew on each link.

    def test_packet_fuzz_saves_exact_inputs_on_worker_failure(self):
        cases = mutated_packets(2)
        first = bytes.fromhex(cases[0]['payload'])

        class BrokenWorker(FakeBackend):
            def __init__(self, *args):
                super().__init__(*args)
                self.workers = {'lan10': MagicMock(), 'lan20': MagicMock()}
                for worker in self.workers.values():
                    worker.poll.return_value = None

            def exchange(self, link, payload, **kwargs):
                if bytes(payload) == first:
                    self.workers['lan10'].poll.return_value = 1
                    return []
                return super().exchange(link, payload, **kwargs)

        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(AssertionError, 'worker exited'):
                execute_packets(cases, '/unused', directory, backend_factory=BrokenWorker)
            saved = json.loads((Path(directory) / 'packet-sequence.json').read_text())
            self.assertEqual(saved, cases[:1])
            self.assertEqual((Path(directory) / 'lan10.pcap').read_bytes(), b'capture')
            with self.assertRaisesRegex(AssertionError, 'worker exited'):
                execute_packets(saved, '/unused', directory, backend_factory=BrokenWorker)

    def test_robot_reports_fuzz_failure(self):
        suite = str(Path(__file__).resolve().parents[1] / 'suites/fuzz_and_replay.robot')
        with tempfile.TemporaryDirectory() as directory, \
                patch('harness.fuzz_dhcp.execute', side_effect=AssertionError('fuzz failure')):
            result = run_robot(suite, outputdir=directory, log='NONE', report='NONE',
                               console='none', test=['Replay DHCP sequence'])
            self.assertNotEqual(result, 0)

    def test_robot_keeps_captures_with_their_failing_sequences(self):
        class StatefulFailure(FakeBackend):
            capture = b'stateful capture'

            def create(self):
                (self.output / 'lan10.pcap').write_bytes(self.capture)

            def exchange(self, link, payload, **kwargs):
                raise AssertionError('fixture failure')

        class PacketFailure(StatefulFailure):
            capture = b'packet capture'

        suite = str(Path(__file__).resolve().parents[1] / 'suites/fuzz_and_replay.robot')
        with tempfile.TemporaryDirectory() as directory:
            evidence = Path(directory) / 'evidence'
            with patch('harness.fuzz_dhcp.execute', side_effect=partial(execute, backend_factory=StatefulFailure)), \
                    patch('harness.fuzz_dhcp.execute_packets',
                          side_effect=partial(execute_packets, backend_factory=PacketFailure)), \
                    patch('harness.fuzz_dhcp.mutated_packets', return_value=[]):
                result = run_robot(suite, outputdir=directory, log='NONE', report='NONE',
                                   console='none', variable=['EXAMPLES:1', f'FUZZ_OUTPUT:{evidence}'],
                                   test=['Generate DHCP sequences', 'Fuzz DHCP packet fields'])
            self.assertEqual(result, 2)
            stateful = evidence / 'stateful-generated'
            packets = evidence / 'packet-generated'
            self.assertTrue((stateful / 'sequence.json').is_file())
            self.assertTrue((packets / 'packet-sequence.json').is_file())
            self.assertEqual((stateful / 'lan10.pcap').read_bytes(), StatefulFailure.capture)
            self.assertEqual((packets / 'lan10.pcap').read_bytes(), PacketFailure.capture)

    def test_replay_runs_from_fresh_state(self):
        sequence = json.loads((Path(__file__).resolve().parents[1] / 'data/fuzz-replay.json').read_text())
        with tempfile.TemporaryDirectory() as directory, patch('harness.fuzz_dhcp.packet.link_mac', return_value=b'\0' * 6):
            before = FakeBackend.created
            execute(sequence, '/unused', directory, backend_factory=FakeBackend)
            execute(sequence, '/unused', directory, backend_factory=FakeBackend)
            self.assertEqual(FakeBackend.created, before + 2)

    def test_retry_resends_original_selecting_request(self):
        sequence = [('acquire', 'lan10', 0), ('retry', 'lan10', 0)]
        with tempfile.TemporaryDirectory() as directory:
            execute(sequence, '/unused', directory, backend_factory=FakeBackend)
        requests = [payload for link, payload in FakeBackend.last.requests if link == 'lan10']
        self.assertEqual(requests[1], requests[2])
        parsed = BOOTP(requests[2])
        options = dict(option[:2] for option in parsed[DHCP].options if isinstance(option, tuple))
        self.assertEqual(parsed.xid, 1)
        self.assertEqual(options['server_id'], '192.168.10.1')

    def test_restart_probes_before_owner_recovers(self):
        sequence = [('acquire', 'lan10', 0), ('restart', 'lan10', 0)]
        with tempfile.TemporaryDirectory() as directory:
            execute(sequence, '/unused', directory, backend_factory=FakeBackend)
        requests = [BOOTP(payload) for link, payload in FakeBackend.last.requests if link == 'lan10']
        options = [dict(option[:2] for option in request[DHCP].options if isinstance(option, tuple))
                   for request in requests]
        self.assertEqual(options[2]['client_id'], b'fuzz-recovery-probe')
        self.assertEqual(options[2]['message-type'], 1)
        self.assertEqual(options[2]['requested_addr'], '192.168.10.100')
        self.assertEqual(options[3]['server_id'], '192.0.2.254')
        self.assertEqual(options[4]['client_id'], b'fuzz-0')
        self.assertNotIn('server_id', options[4])

    def test_restart_detects_lost_reservation(self):
        class LostReservation(FakeBackend):
            def restart(self):
                self.leases = {'lan10': {}, 'lan20': {}}

        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(AssertionError):
                execute([('acquire', 'lan10', 0), ('restart', 'lan10', 0)],
                        '/unused', directory, backend_factory=LostReservation)

    def test_restart_requires_offer_when_pool_has_room(self):
        class SilentAfterRestart(FakeBackend):
            def restart(self):
                self.restarted = True

            def exchange(self, link, payload, **kwargs):
                options = dict(option[:2] for option in BOOTP(payload)[DHCP].options
                               if isinstance(option, tuple))
                if getattr(self, 'restarted', False) and options['message-type'] == 1:
                    return []
                return super().exchange(link, payload, **kwargs)

        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(AssertionError):
                execute([('acquire', 'lan10', 0), ('restart', 'lan10', 0)],
                        '/unused', directory, backend_factory=SilentAfterRestart)

    def test_restart_probes_each_reserved_address_when_pool_is_full(self):
        sequence = [('acquire', 'lan10', 0), ('acquire', 'lan10', 1), ('restart', 'lan10', 0)]
        with tempfile.TemporaryDirectory() as directory:
            execute(sequence, '/unused', directory, backend_factory=FakeBackend)
        requests = [BOOTP(payload) for link, payload in FakeBackend.last.requests if link == 'lan10']
        options = [dict(option[:2] for option in request[DHCP].options if isinstance(option, tuple))
                   for request in requests]
        probes = [option for option in options if option.get('client_id') == b'fuzz-recovery-probe']
        self.assertEqual([option['requested_addr'] for option in probes],
                         ['192.168.10.100', '192.168.10.103'])

    def test_restart_rejects_offer_of_requested_reservation(self):
        class OffersRequestedReservation(FakeBackend):
            def exchange(self, link, payload, **kwargs):
                request = BOOTP(payload)
                options = dict(option[:2] for option in request[DHCP].options
                               if isinstance(option, tuple))
                if (options.get('client_id') == b'fuzz-recovery-probe'
                        and options.get('requested_addr') == '192.168.10.103'):
                    server = '192.168.10.1'
                    return [dict(type=2, client_id=b'fuzz-recovery-probe'.hex(), xid=request.xid,
                                 server=server, src=server, yiaddr=options['requested_addr'])]
                return super().exchange(link, payload, **kwargs)

        sequence = [('acquire', 'lan10', 0), ('acquire', 'lan10', 1), ('restart', 'lan10', 0)]
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(AssertionError):
                execute(sequence, '/unused', directory, backend_factory=OffersRequestedReservation)

    def test_duplicate_lease_fails_and_saves_replay(self):
        class DuplicateBackend(FakeBackend):
            duplicate = True

        sequence = [('acquire', 'lan10', 0), ('acquire', 'lan10', 1)]
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(AssertionError):
                execute(sequence, '/unused', directory, backend_factory=DuplicateBackend)
            saved = Path(directory) / 'sequence.json'
            self.assertEqual(json.loads(saved.read_text()), [list(item) for item in sequence])
            self.assertEqual((Path(directory) / 'lan10.pcap').read_bytes(), b'capture')
            with self.assertRaises(AssertionError):
                execute(json.loads(saved.read_text()), '/unused', directory, backend_factory=DuplicateBackend)


if __name__ == '__main__':
    unittest.main()
