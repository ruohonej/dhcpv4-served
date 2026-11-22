package server

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"dhcpv4-served/internal/lease"
	"github.com/insomniacslk/dhcp/dhcpv4"
)

type sequenceStore struct {
	bindings []lease.Binding
	failNext bool
	calls    int
}

func (s *sequenceStore) Save(bindings []lease.Binding) error {
	s.calls++
	if s.failNext {
		s.failNext = false
		return errors.New("injected save failure")
	}
	s.bindings = append([]lease.Binding(nil), bindings...)
	return nil
}

// One address and deterministic transaction IDs make ownership expectations independent
// of the worker's internal state. The persisted owner can outlive its deadline.
type sequenceModel struct {
	owner       int // 0 free, 1 A, 2 B
	durable     int
	offered     bool
	quarantined bool
	transaction [4]byte
	deadline    time.Time
	stopped     bool
	failNext    bool
}

var sequenceSeeds = [][]byte{
	// Opcodes 0-7 are discover, select, renew, replay, advance, sweep,
	// restart, fail-next-save. Bit 3 selects B. Higher bits select time mode.
	// Bytes 0x17/0x1f release and 0x27/0x2f decline for A/B.
	{0, 1, 6, 4 | 16, 8, 1 | 8, 2, 2 | 8},
	{0, 1, 6, 4 | 16, 7, 8, 6, 8},
	{0, 1, 6, 4 | 48, 2, 4 | 240, 8},
	{0, 1, 6, 8, 1},
	{0, 0, 3, 1},
	{0, 1, 4 | 16, 8, 1 | 8},
	{0, 1 | 128, 6, 1},
	{0, 4 | 16, 8},
	{0, 1, 0x17, 8, 9},
	{0, 0x27, 6, 8, 20, 8, 9},
	{0, 1, 0x27, 6, 8, 20, 8, 9},
	{0, 0x27, 0xe4, 6, 0xe4, 0xe4, 8, 0x34, 8, 0xf4, 8, 9},
	{0, 1, 0x1f, 0x2f, 7, 0x17, 6, 8},
	{0, 1, 6, 4 | 16, 5, 6, 8},
	{0, 1, 6, 4 | 16, 6, 8},
}

func FuzzLeaseSequences(f *testing.F) {
	for _, seed := range sequenceSeeds {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input []byte) {
		runLeaseSequence(t, input, nil)
	})
}

func runLeaseSequence(t *testing.T, input []byte, observe func(string)) {
	emit := func(event string) {
		if observe != nil {
			observe(event)
		}
	}
	if len(input) > 32 {
		input = input[:32]
	}
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	store := &sequenceStore{}
	addr := netip.MustParseAddr("192.0.2.10")
	cfg := lease.Config{Instance: "test", Start: addr, End: addr, OfferDuration: 10 * time.Second, LeaseDuration: time.Minute, DeclineDuration: 30 * time.Second}
	var engine *lease.Engine
	var handler *Handler
	restart := func() {
		var err error
		engine, err = lease.New(store, slog.New(slog.NewTextHandler(io.Discard, nil)), clock, cfg, store.bindings)
		if err != nil {
			t.Fatal(err)
		}
		handler = New(engine, clock, Config{Server: netip.MustParseAddr("192.0.2.1"), Subnet: netip.MustParsePrefix("192.0.2.0/24"), LeaseDuration: time.Minute})
	}
	restart()
	model := sequenceModel{}
	var saved [2][]byte
	var transactions [2]uint32
	var trace []string
	var lastLeaseOwner int
	var reassigned bool
	var clientExpiry [2]time.Time
	var clientAddress [2]netip.Addr
	var offeredAddress [2]netip.Addr
	fail := func(format string, args ...any) {
		t.Helper()
		t.Fatalf("%s\ntrace:\n%s", fmt.Sprintf(format, args...), strings.Join(trace, "\n"))
	}
	for i, b := range input {
		op := int(b & 7)
		client := int((b>>3)&1) + 1
		if op == 7 && b>>4 == 1 {
			op = 8
		}
		if op == 7 && b>>4 == 2 {
			op = 9
		}
		trace = append(trace, fmt.Sprintf("%d time=%s op=%d client=%d byte=%02x", i, now.Format(time.RFC3339Nano), op, client, b))
		switch op {
		case 4:
			target := now.Add(time.Second)
			if b>>4 == 14 {
				target = now.Add(10 * time.Second)
			} else if b>>4 == 15 {
				target = now.Add(time.Nanosecond)
			} else if b>>4 != 0 && model.owner != 0 {
				target = model.deadline
				switch (b >> 4) % 3 {
				case 0:
					target = target.Add(-time.Nanosecond)
				case 2:
					target = target.Add(time.Nanosecond)
				}
				if target.Before(now) {
					target = now
				}
			}
			now = target
			continue
		case 6:
			if model.durable != 0 && !now.Before(model.deadline) {
				emit("restart_after_deadline")
			}
			emit("restart")
			restart()
			model.owner = model.durable
			model.offered = false
			model.stopped = false
			if model.owner != 0 {
				if model.quarantined {
					model.deadline = now.Add(30 * time.Second)
				} else {
					model.deadline = now.Add(time.Minute)
				}
			}
			continue
		case 7:
			store.failNext = true
			model.failNext = true
			continue
		}
		var packet []byte
		var transaction [4]byte
		if op < 4 || op == 8 || op == 9 {
			discover, selecting, renewal := simulationPackets(t, []string{"client-a", "client-b"}[client-1])
			switch op {
			case 0:
				transactions[client-1]++
				binary.BigEndian.PutUint32(discover.TransactionID[:], transactions[client-1])
				binary.BigEndian.PutUint32(selecting.TransactionID[:], transactions[client-1])
				if len(saved[client-1]) == 0 {
					saved[client-1] = selecting.ToBytes()
				}
				packet = discover.ToBytes()
			case 1:
				if offeredAddress[client-1].IsValid() {
					selecting.UpdateOption(dhcpv4.OptRequestedIPAddress(net.IP(offeredAddress[client-1].AsSlice())))
				}
				binary.BigEndian.PutUint32(selecting.TransactionID[:], transactions[client-1])
				packet = selecting.ToBytes()
			case 2:
				packet = renewal.ToBytes()
			case 3:
				packet = saved[client-1]
			case 8, 9:
				kind := dhcpv4.MessageTypeRelease
				if op == 9 {
					kind = dhcpv4.MessageTypeDecline
				}
				p := gatePacket(t, []string{"client-a", "client-b"}[client-1], kind)
				p.UpdateOption(dhcpv4.OptServerIdentifier(net.ParseIP("192.0.2.1")))
				if op == 8 {
					p.ClientIPAddr = net.IP(addr.AsSlice())
				} else {
					p.UpdateOption(dhcpv4.OptRequestedIPAddress(net.IP(addr.AsSlice())))
				}
				packet = p.ToBytes()
				clientExpiry[client-1] = time.Time{}
			}
			if len(packet) == 0 {
				continue
			}
			if op == 1 || op == 2 {
				saved[client-1] = append([]byte(nil), packet...)
			}
			// The replay operation has the same semantic kind as the retained packet.
			parsed, err := dhcpv4.FromBytes(packet)
			if err != nil {
				t.Fatal(err)
			}
			transaction = parsed.TransactionID
			switch parsed.MessageType() {
			case dhcpv4.MessageTypeDiscover:
				op = 0
			case dhcpv4.MessageTypeRequest:
				if parsed.ClientIPAddr.IsUnspecified() {
					op = 1
				} else {
					op = 2
				}
			}
		}
		if b&7 == 3 && op == 1 {
			emit("replayed_selecting")
		}
		if b&7 == 3 && op == 2 {
			emit("replayed_renewal")
		}
		if op == 1 && !model.stopped && model.offered && now.Before(model.deadline) && model.owner == client && transaction != model.transaction {
			emit("stale_selecting")
			if b&7 == 3 {
				emit("replayed_stale_selecting")
			}
		}
		if op == 2 && !model.stopped && !model.quarantined && model.durable != 0 && now.Before(model.deadline) && model.durable != client {
			emit("other_client_renewal")
			if reassigned && lastLeaseOwner == model.durable {
				emit("renewal_after_reassignment")
				if b&7 == 3 {
					emit("replayed_renewal_after_reassignment")
				}
			}
		}
		beforeCalls := store.calls
		expectedCalls := 0
		want := dhcpv4.MessageType(0)
		wantStorage := model.stopped
		wantExhausted := false
		save := func() bool {
			expectedCalls++
			if model.failNext {
				model.failNext = false
				emit("save_failed")
				model.stopped = true
				wantStorage = true
				return false
			}
			return true
		}
		if !model.stopped && model.owner != 0 && !now.Before(model.deadline) {
			if !model.offered {
				if model.quarantined {
					emit("quarantine_expiry_attempt")
				} else {
					emit("lease_expiry_attempt")
				}
				if model.failNext {
					emit("expiry_save_failure")
				}
			}
			if model.offered || save() {
				if !model.offered {
					if model.quarantined {
						emit("quarantine_expired")
					} else {
						emit("lease_expired")
					}
				}
				model.owner = 0
				model.offered = false
				model.quarantined = false
				model.durable = 0
			}
		}
		if !model.stopped {
			switch op {
			case 0:
				if model.owner == 0 {
					model.owner = client
					model.transaction = transaction
					model.offered = true
					model.deadline = now.Add(10 * time.Second)
					want = dhcpv4.MessageTypeOffer
				} else if model.owner == client && !model.quarantined {
					if model.offered {
						model.transaction = transaction
					}
					want = dhcpv4.MessageTypeOffer
				} else {
					wantExhausted = true
				}
			case 1, 2:
				if !model.quarantined && model.owner == client && model.failNext && (!model.offered || (op == 1 && transaction == model.transaction)) {
					if model.offered {
						emit("grant_save_failure")
					} else {
						emit("renewal_save_failure")
					}
				}
				if !model.quarantined && model.owner == client && (!model.offered || (op == 1 && transaction == model.transaction)) && save() {
					if model.offered {
						emit("lease_granted")
						if lastLeaseOwner != 0 && lastLeaseOwner != client {
							emit("reassignment")
							reassigned = true
						}
						lastLeaseOwner = client
					} else {
						emit("lease_renewed")
					}
					model.offered = false
					model.durable = client
					model.deadline = now.Add(time.Minute)
					want = dhcpv4.MessageTypeAck
				}
			case 8, 9:
				if !model.quarantined && model.owner == client && (op == 9 || !model.offered) && save() {
					if op == 9 {
						model.offered = false
						model.quarantined = true
						model.durable = client
						model.deadline = now.Add(30 * time.Second)
						emit("declined")
					} else {
						model.owner = 0
						model.durable = 0
						emit("released")
					}
				}
			}
		}
		var reply *Response
		var err error
		if op == 5 {
			err = engine.Sweep()
		} else {
			reply, err = handler.Reply(packet)
		}
		if wantStorage != errors.Is(err, lease.ErrStorage) || wantExhausted != errors.Is(err, lease.ErrExhausted) || (err != nil && !errors.Is(err, lease.ErrStorage) && !errors.Is(err, lease.ErrExhausted)) {
			fail("unexpected error: %v, storage=%v exhausted=%v", err, wantStorage, wantExhausted)
		}
		if (reply == nil) != (want == 0) {
			fail("reply=%v want=%v", reply, want)
		}
		if errors.Is(err, lease.ErrStorage) {
			emit("storage_error")
		}
		if reply == nil && err == nil && op != 5 {
			emit("silence")
		}
		if reply != nil {
			switch want {
			case dhcpv4.MessageTypeOffer:
				emit("offer")
			case dhcpv4.MessageTypeAck:
				emit("ack")
			}
			p, e := dhcpv4.FromBytes(reply.Packet)
			if e != nil || p.MessageType() != want || !p.YourIPAddr.Equal(net.IP(addr.AsSlice())) {
				fail("reply type mismatch: %v %v", p, e)
			}
			if want == dhcpv4.MessageTypeOffer {
				offeredAddress[client-1], _ = netip.AddrFromSlice(p.YourIPAddr.To4())
			}
			if want == dhcpv4.MessageTypeAck {
				duration := p.Options[51]
				if len(duration) != 4 || binary.BigEndian.Uint32(duration) != uint32(cfg.LeaseDuration/time.Second) {
					fail("ACK has incorrect lease duration: %v", duration)
				}
			}
			if want == dhcpv4.MessageTypeAck && b&128 == 0 {
				duration := p.Options[51]
				clientAddress[client-1], _ = netip.AddrFromSlice(p.YourIPAddr.To4())
				clientExpiry[client-1] = now.Add(time.Duration(binary.BigEndian.Uint32(duration)) * time.Second)
				other := 1 - (client - 1)
				if now.Before(clientExpiry[other]) && clientAddress[other] == clientAddress[client-1] && now.Before(clientExpiry[client-1]) {
					fail("clients have overlapping leases for %s until %v and %v", clientAddress[other], clientExpiry[other], clientExpiry[client-1])
				}
				emit("ack_delivered")
			} else if want == dhcpv4.MessageTypeAck {
				emit("ack_lost")
			}
		}
		if len(store.bindings) != (map[bool]int{true: 1, false: 0}[model.durable != 0]) {
			fail("snapshot count mismatch: %+v model=%+v", store.bindings, model)
		}
		expectedState := lease.Leased
		if model.quarantined {
			expectedState = lease.Quarantined
		}
		if model.durable != 0 && (store.bindings[0].Client != []string{"", "i:636c69656e742d61", "i:636c69656e742d62"}[model.durable] || store.bindings[0].Address != addr || store.bindings[0].State != expectedState) {
			fail("snapshot owner mismatch: %+v model=%+v", store.bindings, model)
		}
		if store.calls-beforeCalls != expectedCalls {
			fail("save calls=%d want=%d", store.calls-beforeCalls, expectedCalls)
		}
		if store.failNext != model.failNext {
			fail("save fault state mismatch")
		}
	}
}
