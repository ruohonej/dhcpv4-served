"""Stateful DHCP sequence fuzzing against the worker in isolated namespaces."""
import json
from pathlib import Path
import shutil
import tempfile

from hypothesis import HealthCheck, given, settings, strategies as st
from robot.api.deco import keyword
from scapy.layers.dhcp import BOOTP, DHCP
from scapy.packet import fuzz as scapy_fuzz

from harness.namespace_driver import FastBackend
from harness import fixtures as packet

ROBOT_AUTO_KEYWORDS = False


class FuzzBackend(FastBackend):
    """Reuse each worker's private state directory across process restarts."""

    def __init__(self, worker, output, state_root):
        super().__init__(worker, output)
        self.state_root = Path(state_root)

    def start(self):
        for link in ('lan10', 'lan20'):
            base = self.state_root / link
            base.mkdir(mode=0o755, exist_ok=True)
            log = self.output / f'{link}.log'
            self.workers[link] = packet.worker(self.worker, link, log, base=base)
        for link, proc in self.workers.items():
            packet.wait_for_worker(proc, self.output / f'{link}.log')


def execute(sequence, worker, output, backend_factory=FuzzBackend):
    """Execute one sequence with fresh state and persist evidence on failure."""
    output = Path(output).resolve()
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='dhcp-fuzz-', dir='/tmp') as temporary:
        root = Path(temporary)
        root.chmod(0o755)
        capture = root / 'capture'
        capture.mkdir(mode=0o777)
        backend = backend_factory(worker, capture, root)
        leases = {'lan10': {}, 'lan20': {}}
        completed = []
        selecting = {'lan10': {}, 'lan20': {}}

        def exchange(link, payload, **kwargs):
            other = 'lan20' if link == 'lan10' else 'lan10'
            peer = backend.peers[other]
            peer.send({'action': 'observe', 'timeout': 5, 'capture_all': True,
                       'observe_ready': True, 'interruptible': True})
            assert peer.poll(5) and peer.recv() == 'observing', 'other link capture not ready'
            replies = backend.exchange(link, payload, **kwargs)
            peer.send({'action': 'finish'})
            assert peer.poll(5), 'other link capture did not finish'
            frames = peer.recv()
            assert not [frame for frame in frames if packet.decode(bytes.fromhex(frame))], 'reply crossed links'
            return replies

        def check_reply(link, replies, kind, client_id, xid, address=None):
            assert len(replies) == 1, (link, replies)
            reply = replies[0]
            server = f'192.168.{link[3:]}.1'
            assert (reply['type'], reply['client_id'], reply['xid'], reply['server'], reply['src']) == (
                kind, client_id.hex(), xid, server, server), reply
            if address is not None:
                assert reply['yiaddr'] == address, reply
            return reply['yiaddr']

        def recover(link, client, xid):
            address = leases[link][client]
            client_id = f'fuzz-{client}'.encode()
            reply = exchange(link, packet.request(3, address=address, client_id=client_id, xid=xid))
            check_reply(link, reply, 5, client_id, xid, address)

        try:
            backend.create()
            backend.start()
            for index, action in enumerate(sequence):
                completed.append(action)
                operation, link, client = action
                xid = index + 1
                client_id = f'fuzz-{client}'.encode()
                server = f'192.168.{link[3:]}.1'
                if operation == 'restart':
                    backend.restart()
                    for existing_link, owners in leases.items():
                        if not owners:
                            continue
                        probe_id = b'fuzz-recovery-probe'
                        pool = {f'192.168.{existing_link[3:]}.100',
                                f'192.168.{existing_link[3:]}.103'}
                        assert set(owners.values()) <= pool, (existing_link, owners)
                        for reserved in owners.values():
                            probe = packet.request(client_id=probe_id, xid=xid, address=reserved)
                            offered = exchange(existing_link, probe)
                            if pool - set(owners.values()):
                                address = check_reply(existing_link, offered, 2, probe_id, xid)
                                assert address in pool and address not in owners.values(), (existing_link, owners, address)
                                # Selecting another server releases this probe's temporary offer.
                                release = packet.request(3, server='192.0.2.254', address=address,
                                                         client_id=probe_id, xid=xid)
                                assert not exchange(existing_link, release), 'unexpected response to other server'
                            else:
                                assert not offered, (existing_link, owners, offered)
                        for owner in owners:
                            recover(existing_link, owner, xid)
                    continue
                if operation == 'acquire' and client not in leases[link]:
                    offered = check_reply(link, exchange(link, packet.request(client_id=client_id, xid=xid)),
                                          2, client_id, xid)
                    assert offered not in leases[link].values(), (link, leases[link], offered)
                    request = packet.request(3, server=server, address=offered,
                                             client_id=client_id, xid=xid)
                    ack = exchange(link, request)
                    check_reply(link, ack, 5, client_id, xid, offered)
                    leases[link][client] = offered
                    selecting[link][client] = (request, xid)
                    peer = backend.peers[link]
                    peer.send({'action': 'address', 'address': offered})
                    assert peer.poll(5) and peer.recv() is True, 'client address setup failed'
                elif client in leases[link] and operation in ('retry', 'acquire'):
                    request, original_xid = selecting[link][client]
                    replies = exchange(link, request)
                    check_reply(link, replies, 5, client_id, original_xid, leases[link][client])
                elif client in leases[link] and operation == 'renew':
                    address = leases[link][client]
                    payload = packet.request(3, broadcast=False, client=address, client_id=client_id, xid=xid)
                    replies = exchange(link, payload, src=address, dst=server, dstmac=packet.link_mac(link))
                    check_reply(link, replies, 5, client_id, xid, address)
        except Exception:
            (output / 'sequence.json').write_text(json.dumps(completed, indent=2) + '\n')
            for path in capture.glob('*'):
                if path.is_file():
                    shutil.copy2(path, output / path.name)
            raise
        finally:
            backend.close()


@keyword("lease isolation holds for the recorded sequence")
def replay_dhcp_sequence(replay, worker="work/dhcpv4-served", output="work/fuzz-dhcp"):
    execute(json.loads(Path(replay).read_text()), worker, output)


@keyword("lease isolation holds for generated sequences")
def fuzz_dhcp_sequences(examples: int = 4, worker="work/dhcpv4-served", output="work/fuzz-dhcp"):
    action = st.tuples(st.sampled_from(('acquire', 'retry', 'renew', 'restart')),
                       st.sampled_from(('lan10', 'lan20')), st.integers(min_value=0, max_value=1))

    @settings(max_examples=examples, deadline=None, database=None,
              suppress_health_check=[HealthCheck.too_slow])
    @given(st.lists(action, min_size=1, max_size=5))
    def fuzz(actions):
        execute([('acquire', 'lan10', 0), *actions], worker, output)

    fuzz()


def mutated_packets(count):
    """Generate concrete DHCP datagrams using Scapy's field randomization."""
    cases = []
    for index in range(count):
        bootp = BOOTP(op=1, htype=1, hlen=6, hops=0, ciaddr='0.0.0.0',
                      yiaddr='0.0.0.0', siaddr='0.0.0.0', giaddr='0.0.0.0',
                      chaddr=packet.MAC)
        if index % 2:
            # Scapy randomizes DHCP option content and BOOTP header fields.
            datagram = bytes(scapy_fuzz(bootp / DHCP()))[:1200]
        else:
            # Keep common options valid while varying the BOOTP header fields.
            datagram = bytes(scapy_fuzz(bootp / DHCP(options=[
                ('message-type', 1), ('client_id', b'fuzz-packet'), 'end'])))
        cases.append({'link': 'lan10' if index % 2 == 0 else 'lan20',
                      'payload': datagram.hex()})
    return cases


def execute_packets(cases, worker, output, backend_factory=FuzzBackend):
    """Send exact mutated DHCP datagrams and check the workers remain responsive."""
    output = Path(output).resolve()
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='dhcp-packet-fuzz-', dir='/tmp') as temporary:
        root = Path(temporary)
        root.chmod(0o755)
        capture = root / 'capture'
        capture.mkdir(mode=0o777)
        backend = backend_factory(worker, capture, root)
        sent = []
        try:
            backend.create()
            backend.start()
            health_leases = {}
            client_id = b'fuzz-health'
            for link in ('lan10', 'lan20'):
                xid = 0x5a5a5a5a
                server = f'192.168.{link[3:]}.1'
                replies = backend.exchange(link, packet.request(client_id=client_id, xid=xid))
                assert len(replies) == 1, (link, replies)
                offer = replies[0]
                assert (offer['type'], offer['xid'], offer['client_id'], offer['server'], offer['src']) == (
                    2, xid, client_id.hex(), server, server), offer
                address = offer['yiaddr']
                replies = backend.exchange(link, packet.request(3, server=server, address=address,
                                                               client_id=client_id, xid=xid))
                assert len(replies) == 1, (link, replies)
                ack = replies[0]
                assert (ack['type'], ack['xid'], ack['client_id'], ack['server'], ack['src'], ack['yiaddr']) == (
                    5, xid, client_id.hex(), server, server, address), ack
                health_leases[link] = address
            backend.exchange_timeout = 0.15
            for case in cases:
                if case['link'] not in ('lan10', 'lan20'):
                    raise ValueError('invalid fuzz link')
                payload = bytes.fromhex(case['payload'])
                sent.append(case)
                backend.exchange(case['link'], payload)
                for link, worker_process in backend.workers.items():
                    assert worker_process.poll() is None, f'{link} worker exited'
            backend.exchange_timeout = 0.6
            for link, address in health_leases.items():
                xid = 0x5a5a5a5b
                server = f'192.168.{link[3:]}.1'
                replies = backend.exchange(link, packet.request(3, address=address, client_id=client_id, xid=xid))
                assert len(replies) == 1, (link, replies)
                reply = replies[0]
                assert (reply['type'], reply['xid'], reply['client_id'], reply['server'], reply['src'], reply['yiaddr']) == (
                    5, xid, client_id.hex(), server, server, address), reply
        except Exception:
            (output / 'packet-sequence.json').write_text(json.dumps(sent, indent=2) + '\n')
            for path in capture.glob('*'):
                if path.is_file():
                    shutil.copy2(path, output / path.name)
            raise
        finally:
            backend.close()


@keyword("both workers retain their leases across generated packets and replay")
def fuzz_dhcp_packet_fields(examples: int = 4, worker="work/dhcpv4-served", output="work/fuzz-dhcp"):
    cases = mutated_packets(max(8, examples * 2))
    execute_packets(cases, worker, output)
    # Repeat the exact datagrams against fresh state to exercise replay.
    execute_packets(cases, worker, output)


@keyword("both workers retain their leases across the recorded packets")
def replay_dhcp_packet_sequence(replay, worker="work/dhcpv4-served", output="work/fuzz-dhcp"):
    execute_packets(json.loads(Path(replay).read_text()), worker, output)
