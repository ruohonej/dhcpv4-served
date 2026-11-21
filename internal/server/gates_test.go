package server

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"reflect"
	"testing"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4"

	"dhcpv4-served/internal/lease"
)

type gateStore struct {
	bindings []lease.Binding
	calls    int
	fail     bool
}

func (s *gateStore) Save(bindings []lease.Binding) error {
	s.calls++
	if s.fail {
		return errors.New("injected commit failure")
	}
	s.bindings = append([]lease.Binding(nil), bindings...)
	return nil
}

func gateHandler(t *testing.T) (*Handler, *gateStore) {
	t.Helper()
	db := &gateStore{}
	engine, err := lease.New(db, slog.Default(), func() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) }, lease.Config{
		Instance:        "test",
		Start:           netip.MustParseAddr("192.0.2.10"),
		End:             netip.MustParseAddr("192.0.2.10"),
		OfferDuration:   time.Minute,
		LeaseDuration:   time.Hour,
		DeclineDuration: time.Minute,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return New(engine, time.Now, Config{
		Server:        netip.MustParseAddr("192.0.2.1"),
		Subnet:        netip.MustParsePrefix("192.0.2.0/24"),
		LeaseDuration: time.Hour,
	}), db
}

func gatePacket(t *testing.T, client string, kind dhcpv4.MessageType) *dhcpv4.DHCPv4 {
	t.Helper()
	p, err := dhcpv4.New(dhcpv4.WithHwAddr(net.HardwareAddr{2, 0, 0, 0, 0, 1}),
		dhcpv4.WithMessageType(kind), dhcpv4.WithGeneric(dhcpv4.OptionClientIdentifier, []byte(client)))
	if err != nil {
		t.Fatal(err)
	}
	p.TransactionID = [4]byte{0, 0, 0, 1}
	return p
}

func gateSelecting(t *testing.T, h *Handler) *dhcpv4.DHCPv4 {
	t.Helper()
	discover := gatePacket(t, "owner", dhcpv4.MessageTypeDiscover)
	reply, err := h.Reply(discover.ToBytes())
	if err != nil || reply == nil {
		t.Fatalf("discover: reply=%v error=%v", reply, err)
	}
	offer, err := dhcpv4.FromBytes(reply.Packet)
	if err != nil || offer.MessageType() != dhcpv4.MessageTypeOffer {
		t.Fatalf("invalid offer: %v", err)
	}
	p := gatePacket(t, "owner", dhcpv4.MessageTypeRequest)
	p.UpdateOption(dhcpv4.OptRequestedIPAddress(offer.YourIPAddr))
	p.UpdateOption(dhcpv4.OptServerIdentifier(net.IP(h.cfg.Server.AsSlice())))
	return p
}

func gateACK(t *testing.T, reply *Response, db *gateStore) {
	t.Helper()
	if reply == nil {
		t.Fatal("missing ACK")
	}
	p, err := dhcpv4.FromBytes(reply.Packet)
	if err != nil || p.MessageType() != dhcpv4.MessageTypeAck {
		t.Fatalf("expected ACK: %v", err)
	}
	if db.calls == 0 || len(db.bindings) != 1 || db.bindings[0].State != lease.Leased {
		t.Fatalf("ACK without committed lease: %+v", db)
	}
}

func TestGateDurableACK(t *testing.T) {
	for _, mode := range []string{"grant", "renewal"} {
		for _, fail := range []bool{false, true} {
			name := mode + "/success"
			if fail {
				name = mode + "/failed_commit"
			}
			t.Run(name, func(t *testing.T) {
				h, db := gateHandler(t)
				request := gateSelecting(t, h)
				if db.calls != 0 {
					t.Fatal("offer unexpectedly persisted")
				}
				if mode == "renewal" {
					reply, err := h.Reply(request.ToBytes())
					if err != nil {
						t.Fatal(err)
					}
					gateACK(t, reply, db)
					request = gatePacket(t, "owner", dhcpv4.MessageTypeRequest)
					request.ClientIPAddr = net.ParseIP("192.0.2.10")
				}
				before := db.calls
				db.fail = fail
				reply, err := h.Reply(request.ToBytes())
				if db.calls <= before {
					t.Fatal("grant/renewal did not attempt a durable commit")
				}
				if !fail {
					if err != nil {
						t.Fatal(err)
					}
					gateACK(t, reply, db)
					return
				}
				if reply != nil || !errors.Is(err, lease.ErrStorage) {
					t.Fatalf("failed commit must suppress ACK: reply=%v error=%v", reply, err)
				}
				db.fail = false // Restoring storage does not silently revive the failed engine.
				reply, err = h.Reply(gatePacket(t, "other", dhcpv4.MessageTypeDiscover).ToBytes())
				if reply != nil || !errors.Is(err, lease.ErrStorage) {
					t.Fatalf("allocation continued after uncertain commit: %v %v", reply, err)
				}
			})
		}
	}
}

func TestGateSelectingOwnership(t *testing.T) {
	for _, scenario := range []string{"matching", "other_identifier", "other_transaction", "offer_lost_on_restart"} {
		t.Run(scenario, func(t *testing.T) {
			h, db := gateHandler(t)
			request := gateSelecting(t, h)
			switch scenario {
			case "other_identifier":
				request.UpdateOption(dhcpv4.OptGeneric(dhcpv4.OptionClientIdentifier, []byte("other")))
			case "other_transaction":
				request.TransactionID[3]++
			case "offer_lost_on_restart":
				h, db = gateHandler(t)
			}
			reply, err := h.Reply(request.ToBytes())
			if err != nil {
				t.Fatal(err)
			}
			if scenario == "matching" {
				gateACK(t, reply, db)
			} else if reply != nil || db.calls != 0 {
				t.Fatalf("request without matching ownership was granted: %v %+v", reply, db)
			}
		})
	}
}

func TestGateReleaseDeclineOwnership(t *testing.T) {
	for _, kind := range []dhcpv4.MessageType{dhcpv4.MessageTypeRelease, dhcpv4.MessageTypeDecline} {
		for _, identity := range []string{"matching", "other_identifier", "matching_identifier_other_mac"} {
			t.Run(kind.String()+"/"+identity, func(t *testing.T) {
				h, db := gateHandler(t)
				reply, err := h.Reply(gateSelecting(t, h).ToBytes())
				if err != nil {
					t.Fatal(err)
				}
				gateACK(t, reply, db)
				before := append([]lease.Binding(nil), db.bindings...)
				calls := db.calls
				client := "owner"
				if identity == "other_identifier" {
					client = "other"
				}
				p := gatePacket(t, client, kind)
				if identity == "matching_identifier_other_mac" {
					p.ClientHWAddr[5]++ // DHCP cannot authenticate this matching spoofed ID.
				}
				p.UpdateOption(dhcpv4.OptServerIdentifier(net.IP(h.cfg.Server.AsSlice())))
				if kind == dhcpv4.MessageTypeRelease {
					p.ClientIPAddr = net.ParseIP("192.0.2.10")
				} else {
					p.UpdateOption(dhcpv4.OptRequestedIPAddress(net.ParseIP("192.0.2.10")))
				}
				reply, err = h.Reply(p.ToBytes())
				if err != nil || reply != nil {
					t.Fatalf("release/decline response: %v %v", reply, err)
				}
				if identity == "other_identifier" {
					if db.calls != calls || !reflect.DeepEqual(db.bindings, before) {
						t.Fatal("another identifier changed durable ownership")
					}
				} else if db.calls != calls+1 {
					t.Fatal("matching identifier transition was not committed")
				} else if kind == dhcpv4.MessageTypeRelease && len(db.bindings) != 0 {
					t.Fatal("matching release retained its lease")
				} else if kind == dhcpv4.MessageTypeDecline && (len(db.bindings) != 1 || db.bindings[0].State != lease.Quarantined) {
					t.Fatal("matching decline did not quarantine the lease")
				}
			})
		}
	}
}

// Relay fields are rejected before either transient offers or durable state change.
func TestRelayFieldsDoNotReserveAddress(t *testing.T) {
	for _, tc := range []struct {
		name string
		set  func(*dhcpv4.DHCPv4)
	}{
		{"gateway", func(p *dhcpv4.DHCPv4) { p.GatewayIPAddr = net.IPv4(192, 0, 2, 2) }},
		{"hops", func(p *dhcpv4.DHCPv4) { p.HopCount = 1 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, db := gateHandler(t)
			p := gatePacket(t, "relay", dhcpv4.MessageTypeDiscover)
			tc.set(p)
			if reply, err := h.Reply(p.ToBytes()); err != nil || reply != nil {
				t.Fatalf("relay: reply=%v error=%v", reply, err)
			}
			if db.calls != 0 {
				t.Fatal("relay wrote durable state")
			}
			reply, err := h.Reply(gatePacket(t, "direct", dhcpv4.MessageTypeDiscover).ToBytes())
			if err != nil || reply == nil {
				t.Fatalf("relay reserved the only address: reply=%v error=%v", reply, err)
			}
		})
	}
}

func TestRequestFormsAndInform(t *testing.T) {
	for _, authoritative := range []bool{false, true} {
		for _, form := range []string{"selecting", "reboot", "renewal", "inform"} {
			t.Run(fmt.Sprintf("authoritative=%t/%s", authoritative, form), func(t *testing.T) {
				h, db := gateHandler(t)
				h.cfg.Authoritative = authoritative
				request := gateSelecting(t, h)
				switch form {
				case "reboot", "renewal":
					if reply, err := h.Reply(request.ToBytes()); err != nil || reply == nil {
						t.Fatalf("initial grant: %v %v", reply, err)
					}
					request = gatePacket(t, "owner", dhcpv4.MessageTypeRequest)
					if form == "reboot" {
						request.UpdateOption(dhcpv4.OptRequestedIPAddress(net.ParseIP("192.0.2.10")))
					} else {
						request.ClientIPAddr = net.ParseIP("192.0.2.10")
					}
				case "inform":
					request = gatePacket(t, "other", dhcpv4.MessageTypeInform)
					request.ClientIPAddr = net.ParseIP("192.0.2.11")
				}
				before := db.calls
				reply, err := h.Reply(request.ToBytes())
				if err != nil || reply == nil {
					t.Fatalf("request: %v %v", reply, err)
				}
				p, err := dhcpv4.FromBytes(reply.Packet)
				if err != nil || p.MessageType() != dhcpv4.MessageTypeAck {
					t.Fatalf("expected ACK: %v", err)
				}
				if form == "inform" {
					if db.calls != before || p.Options.Has(dhcpv4.OptionIPAddressLeaseTime) {
						t.Fatal("INFORM allocated a lease")
					}
				} else if db.calls != before+1 {
					t.Fatal("ACK did not commit")
				}
			})
		}
	}
}

func TestRequestRejectionAndSpoofing(t *testing.T) {
	for _, authoritative := range []bool{false, true} {
		for _, scenario := range []string{"selecting-other", "reboot-other", "renewal-other", "reboot-off-link", "spoofed-identifier"} {
			t.Run(fmt.Sprintf("authoritative=%t/%s", authoritative, scenario), func(t *testing.T) {
				h, db := gateHandler(t)
				h.cfg.Authoritative = authoritative
				request := gateSelecting(t, h)
				if scenario != "selecting-other" {
					if reply, err := h.Reply(request.ToBytes()); err != nil || reply == nil {
						t.Fatalf("grant: %v", err)
					}
				}
				switch scenario {
				case "selecting-other":
					request.UpdateOption(dhcpv4.OptGeneric(dhcpv4.OptionClientIdentifier, []byte("other")))
				case "reboot-other":
					request = gatePacket(t, "other", dhcpv4.MessageTypeRequest)
					request.UpdateOption(dhcpv4.OptRequestedIPAddress(net.ParseIP("192.0.2.10")))
				case "renewal-other":
					request = gatePacket(t, "other", dhcpv4.MessageTypeRequest)
					request.ClientIPAddr = net.ParseIP("192.0.2.10")
				case "reboot-off-link":
					request = gatePacket(t, "owner", dhcpv4.MessageTypeRequest)
					request.UpdateOption(dhcpv4.OptRequestedIPAddress(net.ParseIP("198.51.100.10")))
				case "spoofed-identifier":
					request = gatePacket(t, "owner", dhcpv4.MessageTypeRequest)
					request.ClientHWAddr[5]++
					request.ClientIPAddr = net.ParseIP("192.0.2.10")
				}
				before := db.calls
				reply, err := h.Reply(request.ToBytes())
				if err != nil {
					t.Fatal(err)
				}
				if scenario == "spoofed-identifier" {
					gateACK(t, reply, db)
					if db.calls != before+1 {
						t.Fatal("matching spoofed identifier did not renew")
					}
					return
				}
				if scenario == "reboot-off-link" && authoritative {
					if reply == nil {
						t.Fatal("missing authoritative NAK")
					}
					p, err := dhcpv4.FromBytes(reply.Packet)
					if err != nil || p.MessageType() != dhcpv4.MessageTypeNak {
						t.Fatalf("expected NAK: %v", err)
					}
				} else if reply != nil {
					t.Fatal("unexpected response")
				}
				if db.calls != before {
					t.Fatal("rejected request changed durable state")
				}
			})
		}
	}
}

func TestLostOfferAfterRestartWithCompetitor(t *testing.T) {
	h, _ := gateHandler(t)
	original := gateSelecting(t, h)
	h, db := gateHandler(t) // Offers are not durable.
	competitor := gatePacket(t, "competitor", dhcpv4.MessageTypeDiscover)
	if reply, err := h.Reply(competitor.ToBytes()); err != nil || reply == nil {
		t.Fatalf("competitor offer: %v", err)
	}
	if reply, err := h.Reply(original.ToBytes()); err != nil || reply != nil || db.calls != 0 {
		t.Fatalf("lost offer granted: %v %v", reply, err)
	}
}
