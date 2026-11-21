"""DHCP wire helpers shared by the synthetic, real-client, and load tests."""
from scapy.layers.dhcp import BOOTP, DHCP, DHCPOptions, dhcpmagic
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Raw

MAC = bytes.fromhex("020000000010")


def request(kind=1, broadcast=True, client="0.0.0.0", server=None, address=None,
            relay="0.0.0.0", xid=0x12345678, client_id=b"probe", hops=0):
    options = [("message-type", kind), ("client_id", client_id)]
    if server:
        options.append(("server_id", server))
    if address:
        options.append(("requested_addr", address))
    options.append("end")
    packet = BOOTP(op=1, htype=1, hlen=6, hops=hops, xid=xid,
                   flags=0x8000 if broadcast else 0, ciaddr=client,
                   giaddr=relay, chaddr=MAC) / DHCP(options=options)
    return bytes(packet).ljust(300, b"\0")


def ethernet(payload, src="0.0.0.0", dst="255.255.255.255", dstmac=b"\xff" * 6):
    return bytes(Ether(src=MAC, dst=dstmac) / IP(src=src, dst=dst, id=1) /
                 UDP(sport=68, dport=67, chksum=0) / Raw(bytes(payload)))


def _dhcp_frame(frame, *, stop_dissection_after=None):
    try:
        packet = Ether(frame, stop_dissection_after=stop_dissection_after)
    except (ValueError, IndexError, TypeError):
        return None
    if not all(layer in packet for layer in (IP, UDP, BOOTP)):
        return None
    udp = packet[UDP]
    if (udp.sport, udp.dport) not in ((68, 67), (67, 68)):
        return None
    if packet[BOOTP].options != dhcpmagic:
        return None
    return packet


def request_xid(frame):
    """Count DHCP requests by header, including those with malformed options."""
    packet = _dhcp_frame(frame, stop_dissection_after=BOOTP)
    if packet is None or packet[UDP].sport != 68:
        return None
    return packet[BOOTP].xid


def parse(frame):
    packet = _dhcp_frame(frame)
    if packet is None or DHCP not in packet:
        return None
    options = {}
    entries = iter(packet[DHCP].options)
    for option in entries:
        if option == "end":
            # Scapy continues dissecting after END. Only padding is valid there.
            return (packet, options) if all(entry == "pad" for entry in entries) else None
        if option == "pad":
            continue
        # Scapy leaves malformed option bytes undecoded.
        if not isinstance(option, tuple) or len(option) < 2:
            return None
        options[option[0]] = option[1:]
    return None


def decode(frame, *, include_option_codes=False, include_differential_fields=False):
    parsed = parse(frame)
    if not parsed:
        return None
    packet, options = parsed
    if (packet[UDP].sport, packet[UDP].dport) != (67, 68) or packet[BOOTP].op != 2:
        return None
    if "message-type" not in options or "server_id" not in options:
        return None
    bootp = packet[BOOTP]
    domain = options.get("domain", (b"",))[0]
    reply = {"src": packet[IP].src, "dst": packet[IP].dst,
             "mac": packet[Ether].dst.replace(":", ""), "yiaddr": bootp.yiaddr,
             "xid": bootp.xid, "type": options["message-type"][0],
             "server": options["server_id"][0],
             "client_id": options.get("client_id", (b"",))[0].hex(),
             "router": list(options["router"]) if "router" in options else None,
             "dns": list(options["name_server"]) if "name_server" in options else None,
             "domain": domain.decode("ascii") if isinstance(domain, bytes) else domain,
             "ntp": options.get("NTP_server", (None,))[0]}
    if include_differential_fields:
        reply["chaddr"] = bootp.chaddr[:bootp.hlen].hex()
        reply["ntp"] = list(options["NTP_server"]) if "NTP_server" in options else None
        reply["lease_time"] = options.get("lease_time", (None,))[0]
        reply["subnet_mask"] = options.get("subnet_mask", (None,))[0]
    if include_option_codes:
        codes = {getattr(value, "name", value): code for code, value in DHCPOptions.items()}
        reply["option_codes"] = sorted(codes[name] if name in codes else name
                                       for name in options if name in codes or isinstance(name, int))
    return reply


def dhcp_packet(frame):
    parsed = parse(frame)
    if not parsed:
        return None
    packet, options = parsed
    bootp = packet[BOOTP]
    return {"type": options.get("message-type", (0,))[0], "xid": bootp.xid,
            "flags": int(bootp.flags), "mac": ":".join(f"{b:02x}" for b in bootp.chaddr[:6]),
            "address": bootp.yiaddr, "server": options.get("server_id", (None,))[0],
            "source": packet[IP].src, "destination": packet[IP].dst}
