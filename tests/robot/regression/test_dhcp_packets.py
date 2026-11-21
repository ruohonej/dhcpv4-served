"""Wire compatibility and capture checks for the shared packet helpers."""
from pathlib import Path
import tempfile
import unittest

from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from scapy.utils import PcapReader, PcapWriter

from harness import dhcp_packets as packets


class PacketTests(unittest.TestCase):
    def test_request_round_trip(self):
        payload = packets.request(3, broadcast=False, client="192.168.10.100",
                                  server="192.168.10.1", address="192.168.10.100",
                                  relay="192.0.2.1", hops=1, xid=42, client_id=b"abc")
        parsed = BOOTP(payload)
        self.assertEqual(len(payload), 300)
        self.assertEqual((parsed.xid, parsed.ciaddr, parsed.giaddr, parsed.hops, int(parsed.flags)),
                         (42, "192.168.10.100", "192.0.2.1", 1, 0))
        self.assertIn(("client_id", b"abc"), parsed[DHCP].options)
        frame = packets.ethernet(payload, src="192.168.10.100", dst="192.168.10.1")
        decoded = packets.dhcp_packet(frame)
        self.assertEqual((decoded["xid"], decoded["flags"], decoded["server"]),
                         (42, 0, "192.168.10.1"))

    def test_reply_options_and_capture(self):
        frame = bytes(Ether(src="02:00:00:00:00:01", dst="ff:ff:ff:ff:ff:ff") /
                      IP(src="192.168.10.1", dst="255.255.255.255") /
                      UDP(sport=67, dport=68) /
                      BOOTP(op=2, xid=42, yiaddr="192.168.10.100") /
                      DHCP(options=[("message-type", 2), ("server_id", "192.168.10.1"),
                                    ("name_server", "192.0.2.53", "198.51.100.53"), "end"]))
        reply = packets.decode(frame, include_option_codes=True)
        self.assertEqual(reply["dns"], ["192.0.2.53", "198.51.100.53"])
        self.assertEqual(reply["option_codes"], [6, 53, 54])
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / "traffic.pcap")
            with PcapWriter(path, linktype=1) as writer:
                writer.write_header(None)
                writer.write(frame)
            with PcapReader(path) as reader:
                self.assertEqual(bytes(reader.read_packet()), frame)

    def test_ignores_unrelated_or_truncated_packets(self):
        self.assertIsNone(packets.decode(b"\x00" * 20))
        self.assertIsNone(packets.dhcp_packet(bytes(Ether() / IP() / UDP())))

    def test_rejects_malformed_reply_options(self):
        reply = (Ether(src="02:00:00:00:00:01", dst="ff:ff:ff:ff:ff:ff") /
                 IP(src="192.168.10.1", dst="255.255.255.255") /
                 UDP(sport=67, dport=68) /
                 BOOTP(op=2, xid=42, yiaddr="192.168.10.100", chaddr=packets.MAC))
        options = [("message-type", 2), ("server_id", "192.168.10.1")]
        cases = {
            "missing END": [],
            "option after END": ["end", ("name_server", "192.0.2.53")],
            "truncated option": [b"\x06\x04\xc0\x00"],
        }
        for name, tail in cases.items():
            with self.subTest(name=name):
                frame = bytes(reply / DHCP(options=options + tail))
                self.assertIsNone(packets.decode(frame))
                self.assertIsNone(packets.dhcp_packet(frame))

    def test_request_xid_counts_malformed_load_traffic(self):
        xid = 0x80000001
        request = packets.request(xid=xid)
        malformed = request[:240] + bytes([53, 255, 1])
        self.assertEqual(packets.request_xid(packets.ethernet(request)), xid)
        frame = packets.ethernet(malformed)
        self.assertEqual(packets.request_xid(frame), xid)
        self.assertIsNone(packets.dhcp_packet(frame))


if __name__ == "__main__":
    unittest.main()
