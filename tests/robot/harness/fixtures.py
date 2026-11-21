"""Shared network, packet and worker fixtures for Robot tests."""
from contextlib import nullcontext
import ctypes
import fcntl
import json
import os
from pathlib import Path
import select
import socket
import subprocess
import sys
import tempfile
import time

from scapy.utils import PcapWriter
from harness.dhcp_packets import request, ethernet, decode

MAC = bytes.fromhex("020000000010")  # deliberately identical on both links


def ip(*args):
    subprocess.run(["ip", *args], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def namespace_check(*, require_writable_proc=False):
    mapping = [tuple(map(int, line.split()))
               for line in Path("/proc/self/uid_map").read_text().splitlines()]
    with open("/proc/self/ns/net", "rb") as ns:
        owner = fcntl.ioctl(ns.fileno(), 0xb701)  # NS_GET_USERNS
    try:
        owned = os.fstat(owner).st_ino == os.stat("/proc/self/ns/user").st_ino
    finally:
        os.close(owner)
    root_harness = (os.environ.get("DHCP_STARTUP_ROOT_HARNESS") == "1"
                    and os.getuid() == 0 and sum(size for _, _, size in mapping) < 2**32 - 1
                    and any(start <= 65534 < start + size for start, _, size in mapping))
    single_uid = len(mapping) == 1 and mapping[0][2] == 1 and os.getuid() != 0
    if not owned or not (root_harness or single_uid):
        raise RuntimeError("run in a fresh mapped user/network namespace as documented")
    if require_writable_proc and os.statvfs("/proc/sys").f_flag & os.ST_RDONLY:
        raise RuntimeError("/proc/sys is read-only; use --mount --pid --fork --mount-proc "
                           "and Docker --security-opt systempaths=unconfined as documented")


def link_mac(link):
    links = json.loads(subprocess.check_output(["ip", "-j", "link", "show", "dev", link], text=True))
    return bytes.fromhex(links[0]["address"].replace(":", ""))


def worker_events(output):
    """Read structured worker records from either raw output or journalctl's short format."""
    for line in output.splitlines():
        start = line.find('{')
        if start >= 0:
            try:
                event = json.loads(line[start:])
            except ValueError:
                continue
            if isinstance(event, dict):
                yield event


def wait_for_worker(proc, log, timeout=5):
    deadline = time.monotonic() + timeout
    while True:
        if proc.poll() is not None:
            raise RuntimeError(f"Worker exited; inspect {log}")
        if any(e.get('event_id') == 'worker.ready' for e in worker_events(log.read_text())):
            return
        if time.monotonic() >= deadline:
            raise RuntimeError(f"Worker startup timed out; inspect {log}")
        time.sleep(0.02)


def client(pipe, capture, disable_ipv6=False, bind_port=True):
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.unshare(0x40000000) != 0:  # CLONE_NEWNET, nested within harness userns
        raise OSError(ctypes.get_errno(), "client unshare")
    pipe.send(os.getpid())
    pipe.recv()  # parent places a veth here
    if disable_ipv6:
        Path("/proc/sys/net/ipv6/conf/eth0/disable_ipv6").write_text("1")
    ip("link", "set", "lo", "up")
    ip("link", "set", "eth0", "address", "02:00:00:00:00:10")
    ip("link", "set", "eth0", "up")
    raw = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
    raw.bind(("eth0", 0))
    raw.setblocking(False)
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    if bind_port:
        udp.bind(("0.0.0.0", 68))  # avoid kernel ICMP port-unreachable responses
    pipe.send("ready")
    with PcapWriter(capture, linktype=1, sync=True) as pcap:
        pcap.write_header(None)
        def record(frame):
            pcap.write(frame)

        while True:
            cmd = pipe.recv()
            if cmd["action"] == "stop":
                return
            if cmd["action"] == "address":
                ip("address", "add", cmd["address"] + "/24", "dev", "eth0")
                pipe.send(True)
                continue
            while select.select([raw], [], [], 0)[0]:
                raw.recv(65535)
            if cmd.get("observe_ready"):
                pipe.send("observing")
            if cmd.get("packet"):
                frame = bytes.fromhex(cmd["packet"])
                raw.send(frame)
                record(frame)
            found, until = [], time.monotonic() + cmd.get("timeout", 0.6)
            while time.monotonic() < until:
                watched = [raw, pipe] if cmd.get("interruptible") else [raw]
                ready = select.select(watched, [], [], max(0, until-time.monotonic()))[0]
                if raw in ready:
                    frame = raw.recv(65535)
                    record(frame)
                    if cmd.get("capture_all"):
                        found.append(frame.hex())
                    else:
                        reply = decode(frame, include_option_codes=cmd.get("include_option_codes", False))
                        if reply:
                            found.append(reply)
                elif pipe in ready:
                    if pipe.recv() != {"action": "finish"}:
                        raise RuntimeError("expected capture finish")
                    break
            pcap.flush()
            pipe.send(found)


def pool_configuration(pool_number):
    return f"pool:\n  start: 192.168.{pool_number}.100\n  end: 192.168.{pool_number}.103\nexcluded_addresses: [192.168.{pool_number}.101]\ndns_servers: [192.168.{pool_number}.1]\noptions:\n  routers: [192.168.{pool_number}.1, 192.168.{pool_number}.102]\n  domain_name: lan{pool_number}.example\n  ntp_servers: [192.168.{pool_number}.1]\nlease_duration: 12h\noffer_duration: 60s\ndecline_duration: 10m\nauthoritative: false\n"


def worker_directory(output):
    """Keep state across a scenario's restarts under a trusted parent."""
    if os.environ.get("DHCP_STARTUP_ROOT_HARNESS") == "1":
        return tempfile.TemporaryDirectory(prefix="dhcp-worker-", dir="/tmp")
    return nullcontext(output)


def worker(binary, link, out, *, bound=None, name="dhcp", count="1", startup_caps=False, pool_number=None,
           configuration_owner=None, directory_owner=None, configure=True, base=None):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, (bound or link).encode() + b"\0")
    sock.bind(("0.0.0.0", 67))
    number = "10" if link == "lan10" else "20"
    pool_number = pool_number or number
    root_harness = os.environ.get("DHCP_STARTUP_ROOT_HARNESS") == "1"
    if (configuration_owner is not None or directory_owner is not None) and not root_harness:
        raise RuntimeError("ownership cases require the mapped root startup harness")
    if base is None:
        base = Path(tempfile.mkdtemp(prefix="dhcp-startup-", dir="/tmp")) if root_harness else out.parent
    else:
        base = Path(base)
    if root_harness:
        base.chmod(0o755)
    state = base / (link + "-state")
    state.mkdir(mode=0o700, exist_ok=True)
    if root_harness:
        os.chown(state, 65534, 65534)
    configuration = base / (link + ".yaml")
    if configure:
        configuration.write_text(pool_configuration(pool_number))
        if root_harness:
            configuration.chmod(0o644)
    if configuration_owner is not None:
        os.chown(configuration, configuration_owner, configuration_owner)
    if directory_owner is not None:
        os.chown(base, directory_owner, directory_owner)
    # Fast fixture deliberately opts into the lab security profile.
    args = [binary, "--security-profile=lab-best-effort", "--config", str(configuration), "--interface", link, "--state-dir", str(state)]
    # exec preserves PID through setpriv so LISTEN_PID is authentic. Only the
    # activated descriptor survives; parent/harness keeps the privileged setup.
    launcher = """
import os,sys
fd=int(sys.argv[1]); os.dup2(fd,3); os.set_inheritable(3,True)
if fd!=3: os.close(fd)
os.environ['LISTEN_PID']=str(os.getpid())
caps='-all,+net_raw,+setpcap' if os.environ['STARTUP_CAPS']=='1' else '-all'
identity=['--reuid=65534','--regid=65534','--clear-groups'] if os.environ.get('DHCP_STARTUP_ROOT_HARNESS')=='1' else []
os.execvp('setpriv',['setpriv',*identity,'--bounding-set='+caps,'--inh-caps='+caps,'--ambient-caps='+caps,'--no-new-privs',*sys.argv[2:]])
"""
    env = dict(os.environ, LISTEN_FDS=count, LISTEN_FDNAMES=name, STARTUP_CAPS="1" if startup_caps else "0")
    with open(out, "w") as log:
        proc = subprocess.Popen([sys.executable, "-c", launcher, str(sock.fileno()), *args], pass_fds=(sock.fileno(),), env=env, stdout=log, stderr=log)
    sock.close()
    return proc
