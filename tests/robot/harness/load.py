"""Optional production-path load acceptance; run only in the disposable nspawn image.

The parent owns two systemd workers. A process in each client namespace drives
acquisition and renewals; an independent host-side packet socket counts ingress.
Nothing in this module substitutes sender counts for measured input.
"""
import argparse
import json
import math
import os
from pathlib import Path
import select
import socket
import struct
import subprocess
import sys
import threading
import tempfile
import time

from scapy.utils import PcapWriter

from harness import fixtures as packet
from harness.dhcp_packets import request_xid

LINKS = ('lan10', 'lan20')
RATE = 1000
DURATION = 60
SOAK = 120
FLOOD_XID = 0x80000000
# Receipt timestamps can move a few packets across one-second boundaries.
# Totals must still be exact: this allowance never excuses lost input.
RATE_JITTER = 50  # 50 packets / 50 ms at the required 1,000 packets/s
PHASE_PLAN = tuple((f'{occupancy}-' + ('flood' if flood else 'baseline'), occupancy, flood, 60)
                   for occupancy in (0, 80, 100) for flood in (False, True)) + (('soak', 100, True, 120),)


def percentile(values, fraction):
    return sorted(values)[max(0, math.ceil(len(values) * fraction) - 1)] if values else None


def assess(report):
    """Missing samples and under-driven traffic are invalid, never a pass."""
    errors, invalid = [], []
    phases = report.get('phases', [])
    if len(phases) != len(PHASE_PLAN):
        invalid.append('expected baseline/flood for three occupancies and one steady soak')
    for phase, (name, occupancy, flood, duration) in zip(phases, PHASE_PLAN):
        count = max(10, math.ceil(128 * occupancy / 100))
        if (phase.get('name'), phase.get('requested_occupancy_percent'),
                phase.get('flood'), phase.get('duration')) != (name, occupancy, flood, duration):
            invalid.append(f'{name}: phase plan differs from the required qualification profile')
        if phase.get('actual_occupancy_percent') != 100 * count / 128:
            invalid.append(f'{name}: incorrect measured pool occupancy')
        if flood:
            expected = RATE * duration
            if phase['clients']['lan10']['flood_sent'] != expected or phase['ingress']['flood'] != expected:
                invalid.append(f"{phase['name']}: generator/ingress did not sustain {expected} datagrams")
            buckets = phase['ingress'].get('flood_per_second', {})
            expected_buckets = {str(second) for second in range(duration)}
            buckets = {str(second): value for second, value in buckets.items()}
            if (set(buckets) != expected_buckets
                    or any(not isinstance(n, int) or abs(n - RATE) > RATE_JITTER for n in buckets.values())
                    or sum(buckets.values()) != expected):
                invalid.append(f'{name}: missing, late or unsustained one-second ingress measurements')
        elif phase['ingress']['flood'] or phase['clients']['lan10']['flood_sent']:
            invalid.append(f'{name}: baseline contains flood traffic')
        if phase['ingress']['capture_drops']:
            invalid.append(f"{phase['name']}: ingress capture dropped packets")
        if not phase.get('resources'):
            invalid.append(f"{phase['name']}: missing resource samples")
        for link in LINKS:
            client = phase['clients'][link]
            expected = 10 * duration
            if client.get('leased') != count:
                invalid.append(f'{name}/{link}: incorrect number of established leases')
            start = phase.get('start')
            if (start is None or client.get('started_at') is None or client.get('finished_at') is None
                    or not 0 <= client['started_at'] - start <= .1
                    or client['finished_at'] < start + duration):
                invalid.append(f'{name}/{link}: missing or shortened measured phase window')
            latencies = client['latencies']
            if len(latencies) < .99 * expected:
                errors.append(f"{phase['name']}/{link}: fewer than 99% successful renewals within four seconds")
            p95 = percentile(latencies, .95)
            if p95 is None or p95 > 2:
                errors.append(f"{phase['name']}/{link}: p95 first-success latency exceeds two seconds")
            if client['unsafe_acks'] or client['duplicate_grants']:
                errors.append(f"{phase['name']}/{link}: unsafe ACK or duplicate grant")
            if client['renewals'] != expected:
                invalid.append(f"{phase['name']}/{link}: missing scheduled renewals")
        for sample in phase['resources']:
            for link in LINKS:
                worker = sample[link]
                if worker['state'] != 'active' or worker['pid'] != phase['pids'][link]:
                    errors.append(f"{phase['name']}/{link}: worker exited or restarted")
                limits = worker['systemd']
                if (limits['MemoryMax'] != '268435456' or limits['TasksMax'] != '128'
                        or limits['CPUQuotaPerSecUSec'] != '500ms'):
                    errors.append(f"{phase['name']}/{link}: production resource limits differ from acceptance defaults")
                if worker['rss_bytes'] > 256 * 1024 * 1024 or worker['tasks'] > 128:
                    errors.append(f"{phase['name']}/{link}: resource ceiling exceeded")
    return {'status': 'invalid' if invalid else 'fail' if errors else 'pass',
            'invalid': sorted(set(invalid)), 'failures': sorted(set(errors))}


class Ingress:
    def __init__(self):
        self.raw = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
        self.raw.bind(('lan10', 0))
        self.raw.settimeout(.1)
        self.flood = self.total = 0
        self.start = None
        self.buckets = {}
        self.stopping = threading.Event()
        self.thread = threading.Thread(target=self.read, daemon=True)

    def read(self):
        while not self.stopping.is_set():
            try:
                frame = self.raw.recv(65535)
            except TimeoutError:
                continue
            xid = request_xid(frame)
            if xid is None:
                continue
            self.total += 1
            self.flood += bool(xid & FLOOD_XID)
            if xid & FLOOD_XID and self.start is not None:
                second = math.floor(time.monotonic() - self.start)
                self.buckets[second] = self.buckets.get(second, 0) + 1

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *_):
        self.stopping.set()
        self.thread.join()
        _, drops = struct.unpack('II', self.raw.getsockopt(263, 6, 8))  # PACKET_STATISTICS
        self.result = dict(total=self.total, flood=self.flood, capture_drops=drops, flood_per_second=self.buckets)
        self.raw.close()


class AckLedger:
    """Keep expected grants after completion so only verified retries are ignored."""
    def __init__(self, server):
        self.server = server
        self.pending, self.completed = {}, {}
        self.latencies, self.unsafe = [], 0

    def expect(self, xid, cid, address, started=None, payload=None):
        self.pending[xid] = dict(cid=cid, address=address, start=started, last=started, payload=payload)

    def observe(self, reply, now):
        item = self.pending.get(reply['xid']) or self.completed.get(reply['xid'])
        if (item is None or reply['client_id'] != item['cid'].hex()
                or reply['yiaddr'] != item['address'] or reply['server'] != self.server
                or reply['src'] != self.server
                or (item['start'] is not None and
                    (reply['dst'] != item['address'] or reply['mac'] != packet.MAC.hex()))):
            self.unsafe += 1
            return False
        if reply['xid'] in self.pending:
            self.completed[reply['xid']] = self.pending.pop(reply['xid'])
            if item['start'] is not None and now - item['start'] <= 4:
                self.latencies.append(now - item['start'])
        return True

    def expire(self, now):
        for xid, item in list(self.pending.items()):
            if item['start'] is not None and now - item['start'] > 4:
                self.completed[xid] = self.pending.pop(xid)


def client(link, count, duration, flood, start_file, server_mac, capture=None):
    """Runs after nsenter; raw socket sees broadcast setup and unicast renewals."""
    number = link[3:]
    raw = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
    raw.bind(('eth0', 0))
    raw.setblocking(False)
    leases = {}
    acknowledgements = AckLedger(f'192.168.{number}.1')
    next_xid = 1

    def send(payload):
        source = socket.inet_ntoa(payload[12:16])
        if source == '0.0.0.0':
            frame = packet.ethernet(payload)
        else:
            frame = packet.ethernet(payload, src=source, dst=acknowledgements.server, dstmac=server_mac)
        raw.send(frame)
        if capture is not None:
            capture.write(frame)

    def receive():
        frame = raw.recv(65535)
        if capture is not None:
            capture.write(frame)
        return packet.decode(frame)

    def exchange(payload, xid, kind):
        for _ in range(4):
            send(payload)
            end = time.monotonic() + 1
            while time.monotonic() < end:
                if select.select([raw], [], [], max(0, end-time.monotonic()))[0]:
                    reply = receive()
                    if reply and reply['type'] == 5 and not acknowledgements.observe(reply, time.monotonic()):
                        continue
                    if reply and reply['xid'] == xid and reply['type'] == kind:
                        return reply
        raise RuntimeError(f'{link}: acquisition timeout, xid={xid}, kind={kind}')

    for identity in range(count):
        cid = f'load-{identity}'.encode()
        xid = next_xid
        next_xid += 1
        offer = exchange(packet.request(client_id=cid, xid=xid), xid, 2)
        acknowledgements.expect(xid, cid, offer['yiaddr'])
        ack = exchange(packet.request(3, client_id=cid, xid=xid,
                                      server=f'192.168.{number}.1', address=offer['yiaddr']), xid, 5)
        if ack['yiaddr'] in leases.values():
            raise RuntimeError('duplicate lease grant during setup')
        leases[cid] = ack['yiaddr']
        # The kernel must answer ARP for every simulated client before the
        # server can deliver its unicast ACKs. These aliases live only in this
        # disposable client namespace and disappear with the phase topology.
        packet.ip('address', 'add', ack['yiaddr'] + '/24', 'dev', 'eth0')
    # Synchronize only after both namespaces have durable leases.
    Path(str(start_file) + '.' + link + '.ready').write_text('ready')
    while not Path(start_file).exists():
        time.sleep(.01)
    start_at = float(Path(start_file).read_text())
    # The namespace owner binds UDP/68, avoiding ICMP errors for broadcast replies.
    while time.monotonic() < start_at:
        time.sleep(.01)
    if time.monotonic() - start_at > .1:
        raise RuntimeError('setup exceeded scheduled start; run is invalid')
    started_at = time.monotonic()
    begin, end = start_at, start_at + duration
    next_renewal, flood_sent = 0, 0
    renewals = 0
    while time.monotonic() < end + 4:
        now = time.monotonic()
        elapsed = now - begin
        if next_renewal < duration and elapsed >= next_renewal:
            for cid, address in list(leases.items())[:10]:
                xid = next_xid
                next_xid += 1
                payload = packet.request(3, client_id=cid, xid=xid, client=address, broadcast=False)
                acknowledgements.expect(xid, cid, address, now, payload)
                send(payload)
                renewals += 1
            next_renewal += 1
        if flood and now < end:
            target = min(RATE * duration, int(elapsed * RATE) + 1)
            # Pace independently of identity; malformed and valid frames alternate.
            while flood_sent < target:
                xid = FLOOD_XID | flood_sent
                payload = packet.request(xid=xid, client_id=f'flood-{flood_sent}'.encode())
                if flood_sent % 2:
                    payload = payload[:240] + bytes([53, 255, 1])  # option length exceeds packet
                send(payload)
                flood_sent += 1
        # Drain replies without allowing a busy receive socket to starve pacing.
        for _ in range(256):
            if not select.select([raw], [], [], 0)[0]:
                break
            reply = receive()
            if not reply or reply['type'] != 5:
                continue
            acknowledgements.observe(reply, time.monotonic())
        acknowledgements.expire(now)
        for item in acknowledgements.pending.values():
            if now - item['last'] >= 1:
                send(item['payload'])
                item['last'] = now
        time.sleep(.0002)
    return dict(flood_sent=flood_sent, renewals=renewals, latencies=acknowledgements.latencies,
                unsafe_acks=acknowledgements.unsafe, leased=len(leases), duplicate_grants=False,
                started_at=started_at, finished_at=time.monotonic())


def resources():
    from harness.systemd_fixture import ctl
    result = {'time': time.monotonic()}
    for link in LINKS:
        unit = f'dhcpv4-served@{link}.service'
        fields = dict(line.split('=', 1) for line in ctl('show', unit,
            '--property=MainPID,ActiveState,MemoryCurrent,MemoryPeak,TasksCurrent,CPUUsageNSec,CPUQuotaPerSecUSec,MemoryMax,TasksMax').splitlines())
        pid = int(fields['MainPID'])
        rss = 0
        if pid and Path(f'/proc/{pid}/status').exists():
            for line in Path(f'/proc/{pid}/status').read_text().splitlines():
                if line.startswith('VmRSS:'):
                    rss = int(line.split()[1]) * 1024
        result[link] = dict(pid=pid, state=fields['ActiveState'], rss_bytes=rss,
                            tasks=int(fields['TasksCurrent']) if fields['TasksCurrent'].isdigit() else 0,
                            systemd=fields)
    return result



def storage_probe():
    """Synthetic fsync latency on /var/lib, outside worker state; not syscall tracing."""
    samples = []
    fd, name = tempfile.mkstemp(prefix='dhcpv4-served-load-storage-', dir='/var/lib')
    try:
        for _ in range(20):
            os.lseek(fd, 0, os.SEEK_SET)
            os.write(fd, b'x' * 4096)
            start = time.monotonic()
            os.fsync(fd)
            samples.append(time.monotonic() - start)
    finally:
        os.close(fd)
        os.unlink(name)
    return dict(kind='synthetic 4KiB overwrite/fsync on /var/lib before load',
                seconds=samples, p95_seconds=percentile(samples, .95))


def run_load(output):
    from harness.systemd_fixture import SystemdBackend, ctl, run
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    report = dict(kernel=run('uname', '-a').stdout.strip(),
                  systemd=run('systemd', '--version').stdout,
                  worker_version=run('/usr/libexec/dhcpv4-served', '--version').stdout.strip(),
                  worker_sha256=run('sha256sum', '/usr/libexec/dhcpv4-served').stdout.strip(),
                  package=run('dpkg-query', '-W', '-f=${Package} ${Version} ${Architecture}\n', 'dhcpv4-served').stdout.strip(),
                  profile='strict shipped service; no overrides', phases=[],
                  storage_probe=storage_probe(),
                  occupancy_note='Ten pre-existing renewals require at least 10/128 leases; requested 0% means 0 background leases, actual occupancy is recorded.')
    try:
        for occupancy in (0, 80, 100):
            for flood in (False, True):
                phase = dict(name=f'{occupancy}-' + ('flood' if flood else 'baseline'),
                             requested_occupancy_percent=occupancy, duration=DURATION, flood=flood)
                count = max(10, math.ceil(128 * occupancy / 100))
                phase['actual_occupancy_percent'] = 100 * count / 128
                execute_phase(output, phase, count, report)
        execute_phase(output, dict(name='soak', duration=SOAK, flood=True,
                                  requested_occupancy_percent=100, actual_occupancy_percent=100), 128, report)
        report.update(assess(report))
    except Exception as error:
        report.update(status='invalid', error=str(error))
        raise
    finally:
        (output / 'load.json').write_text(json.dumps(report, indent=2))
    return report


def execute_phase(output, phase, count, report):
    from harness.systemd_fixture import SystemdBackend
    backend = SystemdBackend('/usr/libexec/dhcpv4-served', output / phase['name'])
    children = {}
    report['phases'].append(phase)
    try:
        backend.create()
        for link in LINKS:
            n = link[3:]
            Path(f'/etc/dhcpv4-served/{link}.yaml').write_text(
                f'pool:\n  start: 192.168.{n}.100\n  end: 192.168.{n}.227\n'
                'lease_duration: 12h\noffer_duration: 10s\ndecline_duration: 10m\n')
        backend.start()
        # Acquisition runs concurrently; allow durable setup on slow storage.
        start_file = backend.output / 'start'
        start = None
        setup_deadline = time.monotonic() + 180
        for link, owner in zip(LINKS, backend.clients):
            file = open(backend.output / f'{link}-load.json', 'w')
            children[link] = (subprocess.Popen(['nsenter', '--target', str(owner.pid), '--net',
                sys.executable, '-m', 'harness.load', '--client', link,
                '--count', str(count), '--duration', str(phase['duration']),
                '--server-mac', packet.link_mac(link).hex(),
                *(['--capture', str(backend.output / f'{link}-renewals.pcap')] if phase['name'] == 'renewal-smoke' else []),
                '--start-file', str(start_file), *(['--flood'] if phase['flood'] and link == 'lan10' else [])],
                stdout=file, stderr=subprocess.PIPE, text=True), file)
        # Collect setup resources as well as the measured phase.
        phase['resources'] = []
        phase['pids'] = {}
        with Ingress() as ingress:
            while any(child.poll() is None for child, _ in children.values()):
                now = time.monotonic()
                if start is None and all(Path(str(start_file) + '.' + link + '.ready').exists() for link in LINKS):
                    start = now + 2
                    phase['start'] = start
                    ingress.start = start
                    start_file.write_text(str(start))
                if (start is None and now > setup_deadline) or (start is not None and now > start + phase['duration'] + 15):
                    raise RuntimeError('load client timed out')
                if start is not None and now >= start:
                    sample = resources()
                    phase['resources'].append(sample)
                    if not phase['pids']:
                        phase['pids'] = {link: sample[link]['pid'] for link in LINKS}
                time.sleep(.5)
        phase['ingress'] = ingress.result
        phase['clients'] = {}
        for link, (child, file) in children.items():
            file.close()
            if child.returncode:
                raise RuntimeError(f'{link}: {child.stderr.read()}')
            phase['clients'][link] = json.loads((backend.output / f'{link}-load.json').read_text())
        for link in LINKS:
            samples = phase['resources']
            if len(samples) >= 2:
                elapsed = samples[-1]['time'] - samples[0]['time']
                cpu = int(samples[-1][link]['systemd']['CPUUsageNSec']) - int(samples[0][link]['systemd']['CPUUsageNSec'])
                phase['clients'][link]['cpu_fraction_one_core'] = cpu / (elapsed * 1e9)
            phase['clients'][link]['p95_seconds'] = percentile(phase['clients'][link]['latencies'], .95)
            snapshot = backend.snapshot(link)
            addresses = [item['address'] for item in snapshot['bindings'] if item['state'] == 'leased']
            phase['clients'][link]['duplicate_grants'] = len(addresses) != len(set(addresses))
    finally:
        for child, file in children.values():
            if child.poll() is None:
                child.kill()
            child.wait()
            file.close()
        backend.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--client', choices=LINKS)
    parser.add_argument('--count', type=int)
    parser.add_argument('--duration', type=int)
    parser.add_argument('--start-file')
    parser.add_argument('--server-mac', required=True, type=bytes.fromhex)
    parser.add_argument('--capture', type=Path)
    parser.add_argument('--flood', action='store_true')
    args = parser.parse_args()
    if not args.client:
        parser.error('Use the Robot renewal_under_load.robot suite; client mode is internal')
    params = args.client, args.count, args.duration, args.flood, args.start_file, args.server_mac
    if args.capture:
        with PcapWriter(str(args.capture), linktype=1, sync=True) as capture:
            result = client(*params, capture=capture)
    else:
        result = client(*params)
    print(json.dumps(result))
