package server

import (
	"bytes"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4"

	"dhcpv4-served/internal/config"
	"dhcpv4-served/internal/lease"
	"dhcpv4-served/internal/store"
)

func TestWorkerLeaseRecovery(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	cfg := lease.Config{
		Instance:        "lan",
		Start:           netip.MustParseAddr("192.0.2.10"),
		End:             netip.MustParseAddr("192.0.2.11"),
		OfferDuration:   time.Minute,
		LeaseDuration:   time.Hour,
		DeclineDuration: time.Minute,
	}
	db, recovered, err := store.OpenSnapshot(dir, "lan", "192.0.2.0/24")
	if err != nil {
		t.Fatal(err)
	}
	e, err := lease.New(db, slog.Default(), time.Now, cfg, recovered)
	if err != nil {
		t.Fatal(err)
	}
	h := New(e, time.Now, Config{
		Server:        netip.MustParseAddr("192.0.2.1"),
		Subnet:        netip.MustParsePrefix("192.0.2.0/24"),
		LeaseDuration: time.Hour,
		Router:        netip.MustParseAddr("192.0.2.1"),
		DNS:           []netip.Addr{netip.MustParseAddr("192.0.2.53")},
		Options:       []config.EncodedOption{{Code: 15, Value: []byte("example.test")}, {Code: 42, Value: []byte{192, 0, 2, 5}}},
		Authoritative: true,
	})
	packet := func(id string, typ dhcpv4.MessageType) *dhcpv4.DHCPv4 {
		p, err := dhcpv4.New(
			dhcpv4.WithHwAddr(net.HardwareAddr{2, 0, 0, 0, 0, 1}),
			dhcpv4.WithMessageType(typ),
			dhcpv4.WithGeneric(dhcpv4.OptionClientIdentifier, []byte(id)),
		)
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	discover := packet("client-a", dhcpv4.MessageTypeDiscover)
	discover.UpdateOption(dhcpv4.OptGeneric(dhcpv4.OptionParameterRequestList, []byte{6, 15}))
	offer, err := h.Reply(discover.ToBytes())
	if err != nil || offer == nil {
		t.Fatalf("offer %v %v", offer, err)
	}
	parsed, err := dhcpv4.FromBytes(offer.Packet)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Options.Has(dhcpv4.OptionRouter) || !parsed.Options.Has(dhcpv4.OptionDomainNameServer) {
		t.Fatal("parameter request list not honored")
	}
	if string(parsed.Options[15]) != "example.test" || parsed.Options.Has(dhcpv4.OptionNTPServers) {
		t.Fatal("configured option filtering failed")
	}
	request := packet("client-a", dhcpv4.MessageTypeRequest)
	request.TransactionID = discover.TransactionID
	request.UpdateOption(dhcpv4.OptServerIdentifier(net.ParseIP("192.0.2.1")))
	request.UpdateOption(dhcpv4.OptRequestedIPAddress(parsed.YourIPAddr))
	ack, err := h.Reply(request.ToBytes())
	if err != nil || ack == nil {
		t.Fatalf("ack %v %v", ack, err)
	}
	reboot := packet("unknown", dhcpv4.MessageTypeRequest)
	reboot.UpdateOption(dhcpv4.OptRequestedIPAddress(net.ParseIP("192.0.2.11")))
	if reply, err := h.Reply(reboot.ToBytes()); err != nil || reply != nil {
		t.Fatalf("unknown client must be silent: %v", err)
	}
	reboot = packet("client-a", dhcpv4.MessageTypeRequest)
	reboot.UpdateOption(dhcpv4.OptRequestedIPAddress(net.ParseIP("192.0.2.11")))
	nak, err := h.Reply(reboot.ToBytes())
	if err != nil || nak == nil {
		t.Fatalf("missing NAK: %v", err)
	}
	nakPacket, err := dhcpv4.FromBytes(nak.Packet)
	if err != nil || nakPacket.MessageType() != dhcpv4.MessageTypeNak || nak.Destination.String() != "255.255.255.255" {
		t.Fatal("invalid authoritative NAK")
	}
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	db, recovered, err = store.OpenSnapshot(dir, "lan", "192.0.2.0/24")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	e, err = lease.New(db, slog.Default(), time.Now, cfg, recovered)
	if err != nil {
		t.Fatal(err)
	}
	h = New(e, time.Now, h.cfg)
	second := packet("client-b", dhcpv4.MessageTypeDiscover)
	second.UpdateOption(dhcpv4.OptRequestedIPAddress(parsed.YourIPAddr))
	reply, err := h.Reply(second.ToBytes())
	if err != nil || reply == nil {
		t.Fatalf("second offer %v %v", reply, err)
	}
	secondOffer, _ := dhcpv4.FromBytes(reply.Packet)
	if secondOffer.YourIPAddr.Equal(parsed.YourIPAddr) {
		t.Fatal("recovered address offered to another client")
	}
	h.cfg.Options = []config.EncodedOption{
		{Code: 15, Value: bytes.Repeat([]byte("x"), 500)},
		{Code: 42, Value: []byte{192, 0, 2, 5}},
	}
	sized, err := h.Reply(packet("client-b", dhcpv4.MessageTypeDiscover).ToBytes())
	if err != nil || sized == nil || len(sized.Packet) > 576 {
		t.Fatalf("invalid bounded response: %v", err)
	}
	sizedPacket, err := dhcpv4.FromBytes(sized.Packet)
	if err != nil || sizedPacket.Options.Has(dhcpv4.OptionDomainName) || !sizedPacket.Options.Has(dhcpv4.OptionNTPServers) {
		t.Fatal("oversized optional setting was not omitted")
	}
	retry, err := h.Reply(request.ToBytes())
	if err != nil || retry == nil {
		t.Fatalf("lost ACK retry: %v", err)
	}
}

func TestNewRequiresDependencies(t *testing.T) {
	handler, _ := gateHandler(t)
	for _, tt := range []struct {
		name   string
		engine *lease.Engine
		now    func() time.Time
		want   string
	}{
		{"engine", nil, time.Now, "server: lease engine is required"},
		{"clock", handler.leases, nil, "server: clock is required"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				if got := recover(); got != tt.want {
					t.Fatalf("expected panic %q, got %v", tt.want, got)
				}
			}()
			New(tt.engine, tt.now, handler.cfg)
		})
	}
}

func TestNewOwnsResponseSettings(t *testing.T) {
	fixture, _ := gateHandler(t)
	cfg := fixture.cfg
	cfg.DNS = []netip.Addr{netip.MustParseAddr("192.0.2.53")}
	cfg.Options = []config.EncodedOption{{Code: 15, Value: []byte("original.test")}}
	handler := New(fixture.leases, time.Now, cfg)

	// Mutating the caller's settings must not retarget or alter live replies.
	cfg.Server = netip.MustParseAddr("192.0.2.99")
	cfg.DNS[0] = netip.MustParseAddr("192.0.2.99")
	cfg.Options[0].Value[0] = 'x'
	cfg.Options[0].Code = 42
	reply, err := handler.Reply(gatePacket(t, "owner", dhcpv4.MessageTypeDiscover).ToBytes())
	if err != nil || reply == nil {
		t.Fatalf("expected offer, got reply=%v error=%v", reply, err)
	}
	packet, err := dhcpv4.FromBytes(reply.Packet)
	if err != nil {
		t.Fatal(err)
	}
	if !packet.ServerIdentifier().Equal(net.ParseIP("192.0.2.1")) ||
		!bytes.Equal(packet.Options[6], []byte{192, 0, 2, 53}) ||
		string(packet.Options[15]) != "original.test" || packet.Options.Has(dhcpv4.OptionNTPServers) {
		t.Fatal("caller mutation changed response settings")
	}
}

func TestHandlerUsesInjectedClock(t *testing.T) {
	fixture, _ := gateHandler(t)
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	handler := New(fixture.leases, func() time.Time { return now }, fixture.cfg)
	handler.admission.general = bucket{last: now}
	request := gatePacket(t, "owner", dhcpv4.MessageTypeDiscover).ToBytes()
	if reply, err := handler.Reply(request); err != nil || reply != nil {
		t.Fatalf("depleted bucket accepted request: reply=%v error=%v", reply, err)
	}
	now = now.Add(time.Second / AdmissionRate)
	if reply, err := handler.Reply(request); err != nil || reply == nil {
		t.Fatalf("injected clock did not refill bucket: reply=%v error=%v", reply, err)
	}
}
