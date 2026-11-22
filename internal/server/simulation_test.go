package server

import (
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4"

	"dhcpv4-served/internal/lease"
)

type simulation struct {
	t       *testing.T
	now     time.Time
	store   gateStore
	handler *Handler
}

func (s *simulation) restart() {
	s.t.Helper()
	clock := func() time.Time { return s.now }
	address := netip.MustParseAddr("192.0.2.10")
	engine, err := lease.New(&s.store, slog.New(slog.NewTextHandler(io.Discard, nil)), clock, lease.Config{
		Instance: "test", Start: address, End: address,
		OfferDuration: time.Minute, LeaseDuration: time.Minute, DeclineDuration: time.Minute,
	}, s.store.bindings)
	if err != nil {
		s.t.Fatal(err)
	}
	s.handler = New(engine, clock, Config{Server: netip.MustParseAddr("192.0.2.1"), Subnet: netip.MustParsePrefix("192.0.2.0/24"), LeaseDuration: time.Minute})
}

func (s *simulation) send(packet *dhcpv4.DHCPv4, want dhcpv4.MessageType, wantErr error) {
	s.t.Helper()
	before := s.store.calls
	reply, err := s.handler.Reply(packet.ToBytes())
	if !errors.Is(err, wantErr) {
		s.t.Fatalf("at %s: error %v, want %v", s.now, err, wantErr)
	}
	if want == 0 {
		if reply != nil {
			s.t.Fatalf("at %s: unexpected reply", s.now)
		}
		return
	}
	if reply == nil {
		s.t.Fatalf("at %s: missing %s", s.now, want)
	}
	parsed, err := dhcpv4.FromBytes(reply.Packet)
	if err != nil || parsed.MessageType() != want || !parsed.YourIPAddr.Equal(net.ParseIP("192.0.2.10")) {
		s.t.Fatalf("at %s: invalid reply %v, error %v", s.now, parsed, err)
	}
	if want == dhcpv4.MessageTypeAck && (s.store.calls != before+1 || len(s.store.bindings) != 1 || s.store.bindings[0].State != lease.Leased || s.store.bindings[0].Client != "i:"+hex.EncodeToString(packet.Options[61])) {
		s.t.Fatalf("ACK without a new committed lease: %+v", s.store)
	}
}

func simulationPackets(t *testing.T, client string) (discover, selecting, renewal *dhcpv4.DHCPv4) {
	t.Helper()
	discover = gatePacket(t, client, dhcpv4.MessageTypeDiscover)
	selecting = gatePacket(t, client, dhcpv4.MessageTypeRequest)
	selecting.UpdateOption(dhcpv4.OptRequestedIPAddress(net.ParseIP("192.0.2.10")))
	selecting.UpdateOption(dhcpv4.OptServerIdentifier(net.ParseIP("192.0.2.1")))
	renewal = gatePacket(t, client, dhcpv4.MessageTypeRequest)
	renewal.ClientIPAddr = net.ParseIP("192.0.2.10")
	return
}

func TestLeaseRecoverySequence(t *testing.T) {
	for _, scenario := range []string{"stale renewal", "renew before expiry", "expiry save failure", "lost acknowledgement"} {
		t.Run(scenario, func(t *testing.T) {
			s := &simulation{t: t, now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
			s.restart()
			aDiscover, aSelect, aRenew := simulationPackets(t, "client-a")
			bDiscover, bSelect, bRenew := simulationPackets(t, "client-b")
			s.send(aDiscover, dhcpv4.MessageTypeOffer, nil)
			s.send(aSelect, dhcpv4.MessageTypeAck, nil)
			if scenario == "lost acknowledgement" {
				s.restart()
				s.send(bDiscover, 0, lease.ErrExhausted)
				s.send(aSelect, dhcpv4.MessageTypeAck, nil)
				return
			}
			s.now = s.now.Add(50 * time.Second)
			s.restart()
			s.now = s.now.Add(10 * time.Second)
			s.send(bDiscover, 0, lease.ErrExhausted)
			s.now = s.now.Add(50*time.Second - time.Nanosecond)
			if scenario == "renew before expiry" {
				s.send(aRenew, dhcpv4.MessageTypeAck, nil)
				s.now = s.now.Add(time.Nanosecond)
				s.send(bDiscover, 0, lease.ErrExhausted)
				return
			}
			s.send(bDiscover, 0, lease.ErrExhausted)
			s.now = s.now.Add(time.Nanosecond)
			if scenario == "expiry save failure" {
				s.store.fail = true
				s.send(bDiscover, 0, lease.ErrStorage)
				if len(s.store.bindings) != 1 {
					t.Fatal("failed save removed recovered lease")
				}
				s.store.fail = false
				s.send(bDiscover, 0, lease.ErrStorage)
				s.restart()
				s.send(bDiscover, 0, lease.ErrExhausted)
				return
			}
			s.send(bDiscover, dhcpv4.MessageTypeOffer, nil)
			if len(s.store.bindings) != 0 {
				t.Fatal("offer preceded durable expiry")
			}
			s.send(bSelect, dhcpv4.MessageTypeAck, nil)
			owner := s.store.bindings[0].Client
			s.send(aRenew, 0, nil)
			if len(s.store.bindings) != 1 || s.store.bindings[0].Client != owner {
				t.Fatal("stale renewal changed ownership")
			}
			s.send(bRenew, dhcpv4.MessageTypeAck, nil)
		})
	}
}
