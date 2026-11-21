package prototype

import (
	"net"
	"net/netip"
	"testing"

	"github.com/insomniacslk/dhcp/dhcpv4"
)

func fixture() Fixture {
	return Fixture{netip.MustParseAddr("192.168.10.1"), netip.MustParseAddr("192.168.10.100"), netip.MustParsePrefix("192.168.10.0/24"), net.HardwareAddr{2, 0, 0, 0, 0, 16}}
}

func TestDelivery(t *testing.T) {
	f := fixture()
	for _, tc := range []struct {
		name             string
		broadcast, renew bool
		dst              string
	}{
		{"broadcast", true, false, "255.255.255.255"},
		{"broadcast-fallback", false, false, "255.255.255.255"},
		{"renewal", true, true, "192.168.10.100"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, err := dhcpv4.New(
				dhcpv4.WithHwAddr(f.MAC),
				dhcpv4.WithBroadcast(tc.broadcast),
				dhcpv4.WithMessageType(dhcpv4.MessageTypeDiscover),
				dhcpv4.WithGeneric(dhcpv4.OptionClientIdentifier, []byte("probe")),
			)
			if err != nil {
				t.Fatal(err)
			}
			if tc.renew {
				p.ClientIPAddr = net.IP(f.Address.AsSlice())
				p.UpdateOption(dhcpv4.OptMessageType(dhcpv4.MessageTypeRequest))
			}
			reply, err := f.Reply(p.ToBytes())
			if err != nil || reply == nil || reply.Destination.String() != tc.dst {
				t.Fatalf("reply=%v err=%v", reply, err)
			}

			r, err := dhcpv4.FromBytes(reply.Packet)
			if err != nil {
				t.Fatal(err)
			}
			if r.TransactionID != p.TransactionID || !r.ServerIdentifier().Equal(net.IP(f.Server.AsSlice())) || string(r.Options[61]) != "probe" || !r.YourIPAddr.Equal(net.IP(f.Address.AsSlice())) {
				t.Fatal("reply fields not preserved")
			}
		})
	}
}

func TestRejectRequests(t *testing.T) {
	f := fixture()
	for _, tc := range []struct {
		name   string
		modify func(*dhcpv4.DHCPv4)
	}{
		{"relay", func(p *dhcpv4.DHCPv4) { p.GatewayIPAddr = net.IP{192, 168, 10, 2} }},
		{"wrong-client", func(p *dhcpv4.DHCPv4) { p.ClientHWAddr[5]++ }},
		{"wrong-server", func(p *dhcpv4.DHCPv4) {
			p.UpdateOption(dhcpv4.OptMessageType(dhcpv4.MessageTypeRequest))
			p.UpdateOption(dhcpv4.OptServerIdentifier(net.IP{192, 168, 20, 1}))
		}},
		{"cross-subnet", func(p *dhcpv4.DHCPv4) {
			p.UpdateOption(dhcpv4.OptMessageType(dhcpv4.MessageTypeRequest))
			p.UpdateOption(dhcpv4.OptServerIdentifier(net.IP(f.Server.AsSlice())))
			p.UpdateOption(dhcpv4.OptRequestedIPAddress(net.IP{192, 168, 20, 100}))
		}},
		{"bad-option", func(p *dhcpv4.DHCPv4) { p.Options[53] = []byte{1, 2} }},
		{"server-message", func(p *dhcpv4.DHCPv4) { p.UpdateOption(dhcpv4.OptMessageType(dhcpv4.MessageTypeAck)) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, err := dhcpv4.New(
				dhcpv4.WithHwAddr(append(net.HardwareAddr(nil), f.MAC...)),
				dhcpv4.WithMessageType(dhcpv4.MessageTypeDiscover),
			)
			if err != nil {
				t.Fatal(err)
			}
			tc.modify(p)
			data, _ := f.Reply(p.ToBytes())
			if data != nil {
				t.Fatal("invalid request got reply")
			}
		})
	}
}

func TestSelecting(t *testing.T) {
	f := fixture()
	p, err := dhcpv4.New(
		dhcpv4.WithHwAddr(f.MAC),
		dhcpv4.WithBroadcast(true),
		dhcpv4.WithMessageType(dhcpv4.MessageTypeRequest),
		dhcpv4.WithOption(dhcpv4.OptServerIdentifier(net.IP(f.Server.AsSlice()))),
		dhcpv4.WithOption(dhcpv4.OptRequestedIPAddress(net.IP(f.Address.AsSlice()))),
	)
	if err != nil {
		t.Fatal(err)
	}
	data, err := f.Reply(p.ToBytes())
	if err != nil || data == nil {
		t.Fatalf("no ACK: %v", err)
	}
	r, err := dhcpv4.FromBytes(data.Packet)
	if err != nil || r.MessageType() != dhcpv4.MessageTypeAck {
		t.Fatal("not ACK")
	}
}

func FuzzReply(f *testing.F) {
	f.Add([]byte{})
	p, err := dhcpv4.New(dhcpv4.WithHwAddr(fixture().MAC), dhcpv4.WithMessageType(dhcpv4.MessageTypeDiscover))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(p.ToBytes())
	f.Fuzz(func(t *testing.T, data []byte) { fixture().Reply(data) })
}

// The transport fixture has no durable binding evidence. INIT-REBOOT must never
// turn a remembered address into a fresh lease, even for the configured MAC.
func TestInitRebootSilence(t *testing.T) {
	f := fixture()
	for _, known := range []bool{true, false} {
		for _, address := range []string{"192.168.10.100", "192.168.10.101", "192.168.20.100"} {
			mac := append(net.HardwareAddr(nil), f.MAC...)
			if !known {
				mac[5]++
			}
			p, err := dhcpv4.New(
				dhcpv4.WithHwAddr(mac),
				dhcpv4.WithMessageType(dhcpv4.MessageTypeRequest),
				dhcpv4.WithOption(dhcpv4.OptRequestedIPAddress(net.ParseIP(address))),
			)
			if err != nil {
				t.Fatal(err)
			}
			if reply, err := f.Reply(p.ToBytes()); err != nil || reply != nil {
				t.Fatalf("known=%v address=%s reply=%v err=%v", known, address, reply, err)
			}
		}
	}
}
