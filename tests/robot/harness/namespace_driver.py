"""Drive a two-link DHCP topology inside an isolated namespace."""
import multiprocessing as mp
from contextlib import ExitStack
from pathlib import Path
import subprocess

from harness import fixtures as probe
from harness.reply_checks import check_fields, expected_reply, only_reply


class FastBackend:
    exchange_timeout = 0.6

    def __init__(self, worker, output):
        self.worker = str(Path(worker).resolve())
        self.output = Path(output).resolve()
        self.resources = ExitStack()
        self.state_root = None
        self.context = mp.get_context("fork")
        self.peers, self.clients, self.workers = {}, [], {}
        self.links = []
        self.replies = None
        self.opposite_replies = None
        self.extra_workers = []
        self.last_worker = None
        self.client_bind_port = True

    def check_environment(self):
        probe.namespace_check()

    def create(self):
        self.check_environment()
        self.output.mkdir(parents=True, exist_ok=True)
        for number in (10, 20):
            link = f'lan{number}'
            parent, child = self.context.Pipe()
            proc = self.context.Process(target=probe.client, args=(child, str(self.output / f'{link}.pcap'), True),
                                        kwargs={'bind_port': self.client_bind_port})
            proc.start()
            child.close()
            self.clients.append(proc)
            self.peers[link] = parent
            if not parent.poll(5):
                raise RuntimeError(f'{link} client namespace startup timed out')
            pid = parent.recv()
            probe.ip('link', 'add', link, 'type', 'veth', 'peer', 'name', 'eth0', 'netns', str(pid))
            self.links.append(link)
            Path(f'/proc/sys/net/ipv6/conf/{link}/disable_ipv6').write_text('1')
            probe.ip('address', 'add', f'192.168.{number}.1/24', 'dev', link)
            probe.ip('link', 'set', link, 'up')
            parent.send(True)
            if not parent.poll(5) or parent.recv() != 'ready':
                raise RuntimeError(f'{link} client did not become ready')
        probe.ip('link', 'set', 'lo', 'up')

    def start(self, *, worker_base=None):
        if worker_base is None:
            if self.state_root is None:
                self.state_root = self.resources.enter_context(probe.worker_directory(self.output))
            worker_base = self.state_root
        for link in ('lan10', 'lan20'):
            log = self.output / f'{link}.log'
            self.workers[link] = probe.worker(self.worker, link, log, base=worker_base)
        for link, proc in self.workers.items():
            probe.wait_for_worker(proc, self.output / f'{link}.log')

    def check_reply(self, link, **kwargs):
        check_fields(link, only_reply(link, self.replies), expected_reply(link, **kwargs))

    def check_other_link(self):
        if not self.observed_peer.poll(5):
            raise RuntimeError('Other link observation timed out')
        self.opposite_replies = self.observed_peer.recv()
        if self.opposite_replies != []:
            raise AssertionError(f'Unexpected cross-link packets (hex): {self.opposite_replies!r}')

    def exchange(self, link, payload, *, include_option_codes=False, capture_all=False, **kwargs):
        peer = self.peers[link]
        peer.send({'action': 'exchange', 'packet': probe.ethernet(payload, **kwargs).hex(),
                   'timeout': self.exchange_timeout, 'include_option_codes': include_option_codes,
                   'capture_all': capture_all})
        if not peer.poll(5):
            raise RuntimeError(f'{link} exchange timed out')
        self.replies = peer.recv()
        return self.replies

    def start_invalid(self, reason):
        options = {
            'wrong interface': ({'bound': 'lan20'}, 'activation_device'),
            'wrong descriptor name': ({'name': 'wrong'}, 'activation'),
            'wrong descriptor count': ({'count': '2'}, 'activation'),
            'pool outside the subnet': ({'pool_number': '20'}, 'config_link'),
            'unexpected capabilities': ({'startup_caps': True}, 'privilege'),
            'ambiguous server addresses': ({}, 'link_addresses'),
            'worker-owned configuration': ({'configuration_owner': 65534},
                                           'config_file'),
            'untrusted configuration directory': ({'directory_owner': 65534},
                                                  'config_directory'),
        }
        if reason not in options:
            raise ValueError(f'Unknown invalid startup: {reason}')
        if reason == 'ambiguous server addresses':
            probe.ip('address', 'add', '192.168.10.2/24', 'dev', 'lan10')
        settings, self.expected_diagnostic = options[reason]
        log = self.output / 'invalid.log'
        self.last_worker = probe.worker(self.worker, 'lan10', log, **settings)
        self.extra_workers.append(self.last_worker)
        self.invalid_log = log

    def check_rejected(self):
        if self.last_worker.wait(timeout=5) == 0:
            raise AssertionError('Invalid worker startup succeeded')
        diagnostic = self.invalid_log.read_text()
        if not any(event.get('event_id') in ('startup.rejected', 'state.failed')
                   and event.get('reason') == self.expected_diagnostic for event in probe.worker_events(diagnostic)):
            raise AssertionError(f'Expected startup diagnostic {self.expected_diagnostic!r}; received {diagnostic!r}')

    def check_privileges(self):
        for proc in self.workers.values():
            statuses = [p.read_text() for p in Path(f'/proc/{proc.pid}/task').glob('*/status')]
            if not statuses or not all(
                all(line.split()[1] == '0000000000000000' for line in status.splitlines() if line.startswith('Cap'))
                and 'NoNewPrivs:\t1' in status
                and all(int(v) != 0 for line in status.splitlines() if line.startswith('Uid:') for v in line.split()[1:])
                for status in statuses):
                raise AssertionError(f'Unexpected privileges in worker {proc.pid}')

    def commit_lease(self, link):
        self.exchange(link, probe.request())
        self.check_reply(link)
        offer, = self.replies
        self.exchange(link, probe.request(3, server=offer['server'], address=offer['yiaddr']))
        self.check_reply(link, message_type=5)

    def send_unicast_renewal(self, link):
        subnet = f'192.168.{link[3:]}'
        address = f'{subnet}.100'
        self.exchange(link, probe.request(3, broadcast=False, client=address),
                      src=address, dst=f'{subnet}.1', dstmac=probe.link_mac(link))

    def check_unicast_ack(self, link):
        self.check_reply(link, message_type=5, dst=f'192.168.{link[3:]}.100', mac=probe.MAC.hex())

    def restart(self):
        for proc in self.workers.values():
            proc.terminate()
            proc.wait(timeout=5)
        self.workers = {}
        self.start()

    def flush_neighbors(self, link):
        probe.ip('neigh', 'flush', 'dev', link)

    def neighbor_entries(self, link):
        return subprocess.check_output(['ip', 'neigh', 'show', 'dev', link], text=True)

    def replace_link(self, link):
        probe.ip('link', 'del', link)
        probe.ip('link', 'add', link, 'type', 'veth', 'peer', 'name', 'replacement0')
        probe.ip('address', 'add', f'192.168.{link[3:]}.1/24', 'dev', link)
        probe.ip('link', 'set', link, 'up')

    def remove_server_address(self, link):
        probe.ip('address', 'del', f'192.168.{link[3:]}.1/24', 'dev', link)

    def monitor_other_link(self, link):
        other = 'lan20' if link == 'lan10' else 'lan10'
        self.observed_peer = self.peers[other]
        self.observed_peer.send({'action': 'observe', 'timeout': 2.0, 'capture_all': True, 'observe_ready': True})
        if not self.observed_peer.poll(5) or self.observed_peer.recv() != 'observing':
            raise RuntimeError('Other link observation did not start')

    def assign_client_address(self, link):
        peer = self.peers[link]
        peer.send({'action': 'address', 'address': f'192.168.{link[3:]}.100'})
        if not peer.poll(5) or peer.recv() is not True:
            raise RuntimeError('Client address assignment failed')

    def close(self):
        for proc in list(self.workers.values()) + self.extra_workers:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=3)
                except Exception:
                    proc.kill()
                    proc.wait()
        for proc in self.clients:
            if proc.is_alive():
                proc.terminate()
            proc.join(timeout=3)
            if proc.is_alive():
                proc.kill()
                proc.join()
        for peer in self.peers.values():
            peer.close()
        for link in self.links:
            # Removing the client namespace normally removes its veth pair.
            # If it remains, delete only links created by this fixture.
            subprocess.run(['ip', 'link', 'del', link], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
        self.resources.close()
