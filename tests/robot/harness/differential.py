"""Run the shared DHCP scenarios against dhcpv4-served or dnsmasq."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time

from scapy.layers.dhcp import BOOTP
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether

from harness.namespace_driver import FastBackend
from harness.dhcp_packets import decode
from harness.reply_checks import check_fields, expected_reply, only_reply


def server_frames(frames):
    for frame_hex in frames:
        frame = bytes.fromhex(frame_hex)
        packet = Ether(frame, stop_dissection_after=UDP)
        if IP in packet and UDP in packet and (packet[UDP].sport, packet[UDP].dport) == (67, 68):
            yield frame


class DifferentialBackend(FastBackend):
    def __init__(self, worker, output, backend, scenario):
        super().__init__(worker, output)
        self.dnsmasq = backend == "differential-dnsmasq"
        (self.output / "scenario.txt").write_text(f"{scenario}\n")
        self.trace = {}
        self.trace_path = self.output.parent / "comparison" / f"{scenario}.json"
        self.trace_path.parent.mkdir(exist_ok=True)
        self.offer = None
        self.worker_directory = None

    def start(self):
        if not self.dnsmasq:
            self.worker_directory = tempfile.TemporaryDirectory(prefix="dhcp-differential-", dir="/tmp")
            base = Path(self.worker_directory.name)
            try:
                super().start(worker_base=base)
            finally:
                for config in base.glob("*.yaml"):
                    shutil.copyfile(config, self.output / config.name)
            return

        # With --no-daemon dnsmasq stays in the foreground and does not
        # change identity. Both links are inside the fixture namespace.
        config = self.output / "dnsmasq.conf"
        log = self.output / "dnsmasq.log"
        settings = [
            "port=0", "no-daemon", "bind-interfaces", "no-ping", "log-dhcp",
            f"dhcp-leasefile={self.output / 'dnsmasq.leases'}",
        ]
        for link in self.links:
            subnet = f"192.168.{link[3:]}"
            settings.extend([
                f"interface={link}",
                f"dhcp-range=set:{link},{subnet}.100,{subnet}.100,255.255.255.0,12h",
                f"dhcp-range=set:{link},{subnet}.103,{subnet}.103,255.255.255.0,12h",
                f"dhcp-option-force=tag:{link},option:router,{subnet}.1,{subnet}.102",
                f"dhcp-option-force=tag:{link},option:dns-server,{subnet}.1",
                f"dhcp-option-force=tag:{link},option:domain-name,{link}.example",
                f"dhcp-option-force=tag:{link},option:ntp-server,{subnet}.1",
            ])
        config.write_text("\n".join(settings) + "\n")
        with log.open("w") as output:
            proc = subprocess.Popen(
                ["dnsmasq", f"--conf-file={config}"], stdout=output, stderr=output,
                env=dict(os.environ, LC_ALL="C"),
            )
        self.workers["dnsmasq"] = proc
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                raise RuntimeError(f"dnsmasq exited; inspect {log}")
            if log.read_text().count("DHCP, IP range") == 2 * len(self.links):
                return
            time.sleep(0.02)
        raise RuntimeError(f"dnsmasq startup timed out; inspect {log}")

    def exchange(self, link, payload, **kwargs):
        request = BOOTP(payload)
        self.request_chaddr = request.chaddr[:request.hlen].hex()
        frames = super().exchange(link, payload, capture_all=True, **kwargs)
        self.replies = [decode(frame, include_differential_fields=True) for frame in server_frames(frames)]
        return self.replies

    def check_reply(self, link, *, message_type=2):
        reply = only_reply(link, self.replies)
        if message_type == 2:
            eligible = {f"192.168.{link[3:]}.{host}" for host in (100, 103)}
            if reply["yiaddr"] not in eligible:
                raise AssertionError(f"{link}: offered {reply['yiaddr']}, expected one of {sorted(eligible)}")
            self.offer = reply
        expected = expected_reply(link, message_type=message_type, address=self.offer["yiaddr"])
        expected.update(chaddr=self.request_chaddr, ntp=[expected["ntp"]],
                        lease_time=43200, subnet_mask="255.255.255.0")
        # Some dnsmasq versions omit option 61 in replies. Check it if present.
        if self.dnsmasq and not reply["client_id"]:
            expected["client_id"] = ""
        check_fields(link, reply, expected)
        # The lease address and client ID are validated above. The address
        # may differ across runs, and option 61 echo is optional in this pilot.
        normalized = dict(reply, yiaddr="<selected lease>")
        normalized.pop("client_id")
        self.trace[f"{link} DHCP type {message_type}"] = normalized
        self.write_trace()

    def check_other_link(self):
        if not self.observed_peer.poll(5):
            raise RuntimeError("Other link observation timed out")
        replies = list(server_frames(self.observed_peer.recv()))
        if replies:
            raise AssertionError(f"Unexpected DHCP replies on idle link: {[reply.hex() for reply in replies]}")
        self.trace["idle link DHCP replies"] = len(replies)
        self.write_trace()

    def close(self):
        try:
            super().close()
        finally:
            if self.worker_directory is not None:
                self.worker_directory.cleanup()

    def write_trace(self):
        self.trace_path.write_text(json.dumps(self.trace, indent=2, sort_keys=True) + "\n")
