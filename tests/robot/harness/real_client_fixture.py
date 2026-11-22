"""Isolated real DHCP client fixtures for Robot tests."""
import ctypes
import json
import multiprocessing as mp
import os
from pathlib import Path
import select
import shutil
import signal
import socket
import subprocess
import sys
import time
import traceback

from scapy.utils import PcapWriter
from harness.dhcp_packets import dhcp_packet
from harness.fixtures import ip, wait_for_worker, worker, worker_directory

MAC = "02:00:00:00:00:10"
ADDRESS = "192.168.10.2"
SERVER = "192.168.10.1"
CAPS = "+net_admin,+net_raw,+net_bind_service"


def syscall(name, *args):
    libc = ctypes.CDLL(None, use_errno=True)
    if getattr(libc, name)(*args) != 0:
        raise OSError(ctypes.get_errno(), name)


def private_client_namespace(out):
    syscall("unshare", 0x40000000 | 0x00020000)  # CLONE_NEWNET | CLONE_NEWNS
    syscall("mount", None, b"/", None, 0x4000 | 0x40000, None)  # recursive private
    syscall("mount", b"tmpfs", b"/run", b"tmpfs", 0, b"mode=0755")
    syscall("mount", b"tmpfs", b"/var/lib", b"tmpfs", 0, b"mode=0755")
    # Prevent loading host configuration. Mask all existing persistent search
    # paths; the runtime path below lives on the private tmpfs.
    empty = out / "empty-network"
    empty.mkdir()
    for directory in ("/etc/systemd/network", "/usr/lib/systemd/network",
                      "/usr/local/lib/systemd/network"):
        if Path(directory).is_dir():
            syscall("mount", os.fsencode(empty), os.fsencode(directory), None, 4096, None)
    Path("/run/systemd/network").mkdir(parents=True)
    Path("/run/systemd/netif").mkdir(parents=True)


def make_hook(out, configure_address=True):
    # Both dhclient and dhcpcd invoke this instead of their distribution hooks.
    # Configure the interface, but keep DNS and all other host files untouched.
    hook = out / "lease-hook.py"
    hook.write_text(f"""#!{sys.executable}
import ipaddress, json, os, subprocess
from pathlib import Path
e = os.environ
reason = e.get('reason', '')
with open({str(out / 'hook-events.jsonl')!r}, 'a') as log:
    log.write(json.dumps({{k: v for k, v in e.items() if k.startswith('new_') or k in ('reason', 'interface')}}) + '\\n')
if {configure_address!r} and reason in ('BOUND', 'RENEW', 'REBIND', 'REBOOT', 'TIMEOUT'):
    address = e['new_ip_address']
    prefix = ipaddress.IPv4Network('0.0.0.0/' + e['new_subnet_mask']).prefixlen
    subprocess.run(['ip', 'address', 'replace', f'{{address}}/{{prefix}}', 'dev', 'eth0'], check=True)
    routers = e.get('new_routers', '').split()
    if routers:
        subprocess.run(['ip', 'route', 'replace', 'default', 'via', routers[0], 'dev', 'eth0'], check=True)
""")
    hook.chmod(0o755)
    return hook


def client_command(name, binary, out, *, single_uid=True):
    if name == "dhclient":
        config = out / "dhclient.conf"
        config.write_text("timeout 30;\nretry 2;\nrequest subnet-mask, routers, domain-name-servers;\n")
        return [binary, "-4", "-d", "-v", "-cf", str(config), "-lf",
                str(out / "dhclient.leases"), "-pf", "/run/dhclient.pid",
                "-sf", str(make_hook(out)), "eth0"]
    if name == "dhcpcd":
        # Packaged dhcpcd has no switch to disable privilege separation. Its
        # fallback when the service account is absent is
        # needed here: a single-UID user namespace cannot switch to that account.
        passwd = out / "passwd"
        if single_uid:
            passwd.write_text("\n".join(line for line in Path("/etc/passwd").read_text().splitlines()
                                    if int(line.split(":")[2]) in (0, os.getuid())) + "\n")
            syscall("mount", os.fsencode(passwd), b"/etc/passwd", None, 4096, None)
        config = out / "dhcpcd.conf"
        config.write_text("noipv6\nnoipv4ll\noption subnet_mask, routers, domain_name_servers\n")
        return [binary, "-4", "-B", "-d", "-f", str(config),
                "-c", str(make_hook(out, configure_address=False)), "eth0"]
    Path("/run/systemd/network").mkdir(parents=True, exist_ok=True)
    Path("/run/systemd/network/00-dhcp-test.network").write_text(
        "[Match]\nName=eth0\n[Network]\nDHCP=ipv4\nLinkLocalAddressing=no\n"
        "IPv6AcceptRA=no\n[DHCPv4]\nClientIdentifier=mac\nSendHostname=no\n"
        "UseDNS=no\nUseNTP=no\nUseDomains=no\n")
    return [binary]


def stop_process(proc):
    if proc is not None and proc.poll() is None:
        # Clients stay in the foreground; a process group also catches hooks.
        os.killpg(proc.pid, signal.SIGTERM)
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            os.killpg(proc.pid, signal.SIGKILL)
            proc.wait(timeout=3)


def addresses():
    return json.loads(subprocess.check_output(
        ["ip", "-j", "-4", "address", "show", "dev", "eth0"], text=True))


def hook_events(out):
    try:
        return [json.loads(line) for line in (out / "hook-events.jsonl").read_text().splitlines()]
    except (FileNotFoundError, ValueError):
        # A hook may still be appending its current event while we poll.
        return []


def check_acquisition(result, name):
    """Validate the collected evidence in Robot's assertion step."""
    if not result:
        raise AssertionError("No client acquisition evidence was collected")
    if result["timed_out"]:
        raise AssertionError(f"{name} did not acquire {ADDRESS}/24 and a default route before the deadline")
    if not any(a.get("local") == ADDRESS and a.get("prefixlen") == 24
               for link in result["addresses"] for a in link["addr_info"]):
        raise AssertionError(f"Client did not configure {ADDRESS}/24")
    if not any(r.get("dst") == "default" and r.get("gateway") == SERVER for r in result["routes"]):
        raise AssertionError(f"Client did not configure a default route via {SERVER}")
    if name != "systemd-networkd" and not any(e.get("reason") == "BOUND" for e in result["hook_events"]):
        raise AssertionError("Client hook did not record a BOUND event")

    # Require an ordered DISCOVER/OFFER/REQUEST/ACK with matching identity.
    stage, xid = 0, None
    for packet in result["packets"]:
        if packet["mac"] != MAC or packet["type"] != (1, 2, 3, 5)[stage]:
            continue
        if stage == 0:
            xid = packet["xid"]
        if packet["xid"] != xid:
            continue
        if stage in (1, 3) and (packet["server"] != SERVER or packet["source"] != SERVER or packet["address"] != ADDRESS):
            continue
        stage += 1
        if stage == 4:
            break
    if stage != 4:
        raise AssertionError("missing matching DORA exchange")
    snapshot = result["lease_snapshot"]
    if snapshot is None or not any(b["address"] == ADDRESS and b["hardware"] == MAC and b["state"] == "leased"
                                   for b in snapshot["bindings"]):
        raise AssertionError("server did not persist the client's lease")


def client(pipe, name, binary, out, timeout):
    # multiprocessing may use forkserver/spawn, which does not inherit main's
    # signal handler. Always unwind and stop daemon groups on parent teardown.
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(143))
    proc = None
    try:
        private_client_namespace(out)
        pipe.send({"pid": os.getpid()})
        pipe.recv()  # parent has moved eth0 here
        ip("link", "set", "lo", "up")
        ip("link", "set", "eth0", "address", MAC)
        ip("link", "set", "eth0", "up")
        assert not any(a["family"] == "inet" for link in addresses() for a in link["addr_info"])
        pipe.send({"ready": True})
        pipe.recv()  # worker starts after both ends of the link are up
        command = ["setpriv", "--inh-caps=" + CAPS, "--ambient-caps=" + CAPS,
                   *client_command(name, binary, out)]
        (out / "command.json").write_text(json.dumps(command, indent=2) + "\n")
        raw = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
        raw.bind(("eth0", 0))
        raw.setblocking(False)
        packets = []
        with raw, PcapWriter(str(out / "traffic.pcap"), linktype=1) as pcap, open(out / "client.log", "w") as log:
            pcap.write_header(None)
            env = dict(os.environ, SYSTEMD_LOG_LEVEL="debug", SYSTEMD_LOG_TARGET="console")
            proc = subprocess.Popen(command, stdout=log, stderr=log, env=env, start_new_session=True)
            deadline = time.monotonic() + timeout
            timed_out = False
            while time.monotonic() < deadline:
                if select.select([raw], [], [], 0.1)[0]:
                    frame = raw.recv(65535)
                    pcap.write(frame)
                    packet = dhcp_packet(frame)
                    if packet:
                        packets.append(packet)
                state = addresses()
                configured = any(a.get("local") == ADDRESS and a.get("prefixlen") == 24
                                 for link in state for a in link["addr_info"])
                if configured and any(p["type"] == 5 for p in packets):
                    routes = json.loads(subprocess.check_output(["ip", "-j", "-4", "route"], text=True))
                    hooks_ready = name == "systemd-networkd" or any(e.get("reason") == "BOUND" for e in hook_events(out))
                    if hooks_ready and any(r.get("dst") == "default" and r.get("gateway") == SERVER for r in routes):
                        break
                if proc.poll() is not None:
                    raise RuntimeError(f"{name} exited with {proc.returncode}; inspect client.log")
            else:
                # Return partial evidence so Robot reports an acquisition
                # failure at Then, while infrastructure failures remain at When.
                timed_out = True
            state = addresses()
            routes = json.loads(subprocess.check_output(["ip", "-j", "-4", "route"], text=True))
            (out / "addresses.json").write_text(json.dumps(state, indent=2) + "\n")
            (out / "routes.json").write_text(json.dumps(routes, indent=2) + "\n")
            if name == "systemd-networkd":
                for source in Path("/run/systemd/netif").rglob("*"):
                    if source.is_file():  # runtime also contains UNIX sockets
                        target = out / "networkd-state" / source.relative_to("/run/systemd/netif")
                        target.parent.mkdir(parents=True, exist_ok=True)
                        shutil.copyfile(source, target)
            pipe.send({"timed_out": timed_out, "packets": packets, "addresses": state,
                       "routes": routes, "hook_events": hook_events(out)})
            pipe.recv()  # keep lease alive until parent checks server persistence
    except BaseException:
        error = traceback.format_exc()
        (out / "client-error.log").write_text(error)
        pipe.send({"passed": False, "error": error})
    finally:
        stop_process(proc)
        pipe.close()


def receive(pipe, timeout):
    if not pipe.poll(timeout):
        raise TimeoutError("client harness timed out")
    message = pipe.recv()
    if "error" in message:
        raise RuntimeError(message["error"])
    return message


def run_case(name, binary, args, out):
    with worker_directory(out) as base:
        return run_client(name, binary, args, out, Path(base))


def run_client(name, binary, args, out, state_root):
    out.mkdir()
    context = mp.get_context("fork")
    parent, child = context.Pipe()
    proc = context.Process(target=client, args=(child, name, binary, out, args.timeout))
    server = None
    linked = False
    try:
        proc.start()
        child.close()
        pid = receive(parent, 10)["pid"]
        ip("link", "add", "lan10", "type", "veth", "peer", "name", "eth0", "netns", str(pid))
        linked = True
        ip("address", "add", SERVER + "/24", "dev", "lan10")
        ip("link", "set", "lan10", "up")
        parent.send("configure")
        if not receive(parent, 5).get("ready"):
            raise RuntimeError("client link setup failed")
        config = state_root / "lan10.yaml"
        config.write_text("pool:\n  start: 192.168.10.2\n  end: 192.168.10.254\nrouter: 192.168.10.1\nlease_duration: 12h\noffer_duration: 60s\ndecline_duration: 10m\n")
        config.chmod(0o644)
        server = worker(args.worker, "lan10", out / "worker.log", configure=False, base=state_root)
        wait_for_worker(server, out / "worker.log")
        parent.send(True)
        result = receive(parent, args.timeout + 10)
        if server.poll() is not None:
            raise RuntimeError("worker exited during acquisition")
        try:
            snapshot = json.loads((state_root / "lan10-state/leases.json").read_text())
        except (FileNotFoundError, ValueError):
            snapshot = None
        result["lease_snapshot"] = snapshot
        if snapshot is not None:
            (out / "acquired-lease.json").write_text(json.dumps(snapshot, indent=2) + "\n")
        parent.send("stop")
        proc.join(timeout=5)
        if proc.exitcode != 0:
            raise RuntimeError("client harness did not exit cleanly")
        return result
    finally:
        if proc.is_alive():
            # The child handles SIGTERM through its finally block, stopping the
            # entire client process group before its namespaces disappear.
            proc.terminate()
            proc.join(timeout=5)
            if proc.is_alive():
                proc.kill()
                proc.join()
        if server is not None and server.poll() is None:
            server.terminate()
            try:
                server.wait(timeout=3)
            except subprocess.TimeoutExpired:
                server.kill()
                server.wait(timeout=3)
        parent.close()
        if linked:
            subprocess.run(["ip", "link", "del", "lan10"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
