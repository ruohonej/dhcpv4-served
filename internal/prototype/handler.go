// Package prototype contains a deliberately fixed, single-client DHCP fixture.
// It is a transport probe, not a lease allocator or a production DHCP server.
package prototype

import (
	"bytes"
	"fmt"
	"net"
	"net/netip"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/iana"

	"dhcpv4-served/internal/protocol"
)

// Fixture describes the single server/client pair used by the transport probe.
type Fixture struct {
	Server  netip.Addr
	Address netip.Addr
	Subnet  netip.Prefix
	MAC     net.HardwareAddr
}

// Response contains the encoded reply and its destination address.
type Response struct {
	Packet      []byte
	Destination netip.Addr
}

func (f Fixture) Validate() error {
	canonicalIPv4 := f.Subnet.IsValid() && f.Subnet.Addr().Is4() && f.Subnet == f.Subnet.Masked()
	if !canonicalIPv4 || f.Subnet.Bits() > 30 || f.Subnet.Bits() < 1 {
		return fmt.Errorf("require a canonical IPv4 subnet, /1 through /30")
	}

	for _, address := range []netip.Addr{f.Server, f.Address} {
		if !address.Is4() || !address.IsGlobalUnicast() || !f.Subnet.Contains(address) {
			return fmt.Errorf("invalid fixture address %s", address)
		}
		if address == f.Subnet.Addr() || address == f.broadcast() {
			return fmt.Errorf("invalid fixture address %s", address)
		}
	}

	validMAC := len(f.MAC) == 6 && f.MAC[0]&1 == 0 && !bytes.Equal(f.MAC, make([]byte, 6))
	if f.Server == f.Address || !validMAC {
		return fmt.Errorf("require distinct server/client addresses and a unicast Ethernet client MAC")
	}
	return nil
}

func (f Fixture) broadcast() netip.Addr {
	address := f.Subnet.Addr().As4()
	mask := net.CIDRMask(f.Subnet.Bits(), 32)
	for i := range address {
		address[i] |= ^mask[i]
	}
	return netip.AddrFrom4(address)
}

func (f Fixture) Reply(data []byte) (*Response, error) {
	packet, err := protocol.Parse(data)
	if err != nil {
		return nil, err
	}
	if packet.OpCode != dhcpv4.OpcodeBootRequest || packet.HWType != iana.HWTypeEthernet {
		return nil, nil
	}
	if !bytes.Equal(packet.ClientHWAddr, f.MAC) {
		return nil, nil
	}
	// Only direct client traffic with no reserved flag bits is supported.
	if !packet.GatewayIPAddr.Equal(net.IPv4zero) || packet.HopCount != 0 || packet.Flags&0x7fff != 0 {
		return nil, nil
	}

	// This fixture supports only DISCOVER, SELECTING and RENEWING/REBINDING.
	// Validate option lengths explicitly; parsed getters can hide invalid input.
	for code, size := range map[dhcpv4.OptionCode]int{
		dhcpv4.OptionDHCPMessageType:    1,
		dhcpv4.OptionServerIdentifier:   4,
		dhcpv4.OptionRequestedIPAddress: 4,
	} {
		if raw, ok := packet.Options[code.Code()]; ok && len(raw) != size {
			return nil, nil
		}
	}

	replyType := dhcpv4.MessageTypeOffer
	unspecifiedClientIP := packet.ClientIPAddr.Equal(net.IPv4zero)
	serverIP := net.IP(f.Server.AsSlice())
	offeredIP := net.IP(f.Address.AsSlice())
	switch packet.MessageType() {
	case dhcpv4.MessageTypeDiscover:
		if !unspecifiedClientIP || packet.ServerIdentifier() != nil {
			return nil, nil
		}
	case dhcpv4.MessageTypeRequest:
		replyType = dhcpv4.MessageTypeAck
		if unspecifiedClientIP {
			if !packet.ServerIdentifier().Equal(serverIP) || !packet.RequestedIPAddress().Equal(offeredIP) {
				return nil, nil
			}
		} else if !packet.ClientIPAddr.Equal(offeredIP) || packet.ServerIdentifier() != nil || packet.RequestedIPAddress() != nil {
			return nil, nil
		}
	default:
		return nil, nil
	}

	reply, err := dhcpv4.NewReplyFromRequest(packet,
		dhcpv4.WithMessageType(replyType),
		dhcpv4.WithYourIP(offeredIP),
		dhcpv4.WithClientIP(packet.ClientIPAddr),
		dhcpv4.WithOption(dhcpv4.OptServerIdentifier(serverIP)),
		dhcpv4.WithNetmask(net.CIDRMask(f.Subnet.Bits(), 32)),
		dhcpv4.WithLeaseTime(60),
	)
	if err != nil {
		return nil, err
	}

	destination := f.Address
	if unspecifiedClientIP {
		destination = netip.MustParseAddr("255.255.255.255")
	}
	return &Response{
		Packet:      reply.ToBytes(),
		Destination: destination,
	}, nil
}
