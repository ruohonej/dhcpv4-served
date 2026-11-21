"""Regression checks for fields compared on the DHCP wire."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether

from harness.differential import DifferentialBackend
from harness.dhcp_packets import request


class DifferentialTests(unittest.TestCase):
    def test_reply_validates_client_address_and_all_ntp_servers(self):
        client = bytes.fromhex("020000000042")
        server = "192.168.10.1"
        address = "192.168.10.100"

        def reply(kind, *, chaddr=client, ntp=(server,)):
            return bytes(
                Ether(src="02:00:00:00:00:01", dst="ff:ff:ff:ff:ff:ff") /
                IP(src=server, dst="255.255.255.255") / UDP(sport=67, dport=68) /
                BOOTP(op=2, xid=0x12345678, yiaddr=address, chaddr=chaddr) /
                DHCP(options=[
                    ("message-type", kind), ("server_id", server), ("client_id", b"probe"),
                    ("router", server, "192.168.10.102"), ("name_server", server),
                    ("domain", b"lan10.example"), ("NTP_server", *ntp),
                    ("lease_time", 43200), ("subnet_mask", "255.255.255.0"), "end",
                ])
            ).hex()

        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "scenario"
            output.mkdir()
            backend = DifferentialBackend("dhcpv4-served", output, "differential-go", "test")
            for request_kind, reply_kind in ((1, 2), (3, 5)):
                payload = BOOTP(request(request_kind))
                payload.chaddr = client
                with self.subTest(reply=reply_kind):
                    with patch("harness.differential.FastBackend.exchange", return_value=[reply(reply_kind)]):
                        backend.exchange("lan10", bytes(payload))
                        backend.check_reply("lan10", message_type=reply_kind)
                    for field, changed_reply in (
                        ("chaddr", reply(reply_kind, chaddr=bytes.fromhex("020000000043"))),
                        ("ntp", reply(reply_kind, ntp=(server, "192.168.10.9"))),
                    ):
                        with self.subTest(field=field), patch("harness.differential.FastBackend.exchange",
                                                             return_value=[changed_reply]):
                            backend.exchange("lan10", bytes(payload))
                            with self.assertRaisesRegex(AssertionError, f"{field}: expected"):
                                backend.check_reply("lan10", message_type=reply_kind)
