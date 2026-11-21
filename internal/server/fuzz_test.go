package server

import (
	"net"
	"reflect"
	"testing"

	"github.com/insomniacslk/dhcp/dhcpv4"

	"dhcpv4-served/internal/lease"
	"dhcpv4-served/internal/protocol"
)

// Each input is tried in independent empty, offered and leased engines. State
// never carries between fuzz iterations, but successful transitions are reachable.
func FuzzHandler(f *testing.F) {
	for _, packet := range handlerFuzzSeeds(f) {
		f.Add(packet)
	}
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		for _, state := range []string{"empty", "offered", "leased"} {
			for _, authoritative := range []bool{false, true} {
				h, db := handlerFuzzState(t, state)
				h.cfg.Authoritative = authoritative
				checkHandlerFuzzInput(t, h, db, data)
			}
		}
	})
}

func handlerFuzzSeeds(tb testing.TB) map[string][]byte {
	tb.Helper()
	seeds := make(map[string][]byte)
	for _, form := range []string{"discover", "selecting", "reboot", "renewal", "release", "decline", "inform"} {
		kind := dhcpv4.MessageTypeRequest
		switch form {
		case "discover":
			kind = dhcpv4.MessageTypeDiscover
		case "release":
			kind = dhcpv4.MessageTypeRelease
		case "decline":
			kind = dhcpv4.MessageTypeDecline
		case "inform":
			kind = dhcpv4.MessageTypeInform
		}
		p, err := dhcpv4.New(dhcpv4.WithHwAddr(net.HardwareAddr{2, 0, 0, 0, 0, 1}),
			dhcpv4.WithMessageType(kind), dhcpv4.WithGeneric(dhcpv4.OptionClientIdentifier, []byte("owner")))
		if err != nil {
			tb.Fatal(err)
		}
		p.TransactionID = [4]byte{0, 0, 0, 1}
		if form == "selecting" || form == "decline" || form == "reboot" {
			p.UpdateOption(dhcpv4.OptRequestedIPAddress(net.ParseIP("192.0.2.10")))
		}
		if form == "selecting" || form == "decline" || form == "release" {
			p.UpdateOption(dhcpv4.OptServerIdentifier(net.ParseIP("192.0.2.1")))
		}
		if form == "renewal" || form == "release" || form == "inform" {
			p.ClientIPAddr = net.ParseIP("192.0.2.10")
		}
		seeds[form] = p.ToBytes()
	}
	return seeds
}

func handlerFuzzState(t *testing.T, state string) (*Handler, *gateStore) {
	t.Helper()
	h, db := gateHandler(t)
	if state != "empty" {
		request := gateSelecting(t, h)
		if state == "leased" {
			reply, err := h.Reply(request.ToBytes())
			if err != nil {
				t.Fatal(err)
			}
			gateACK(t, reply, db)
		}
	}
	return h, db
}

func checkHandlerFuzzInput(t *testing.T, h *Handler, db *gateStore, data []byte) *Response {
	t.Helper()
	beforeCalls := db.calls
	beforeBindings := append([]lease.Binding(nil), db.bindings...)
	request, parseErr := protocol.Parse(data)
	reply, err := h.Reply(data)
	if parseErr != nil {
		if reply != nil || db.calls != beforeCalls || !reflect.DeepEqual(db.bindings, beforeBindings) {
			t.Fatal("malformed packet replied or changed durable state")
		}
		return nil
	}
	if reply == nil {
		return nil
	}
	if err != nil {
		t.Fatalf("reply with error: %v", err)
	}
	if len(reply.Packet) > protocol.MaxPacketSize {
		t.Fatal("oversized reply")
	}
	p, err := protocol.Parse(reply.Packet)
	if err != nil {
		t.Fatalf("invalid reply: %v", err)
	}
	if p.MessageType() == dhcpv4.MessageTypeAck {
		if request.MessageType() == dhcpv4.MessageTypeInform {
			if db.calls != beforeCalls || !reflect.DeepEqual(db.bindings, beforeBindings) {
				t.Fatal("INFORM changed durable state")
			}
		} else if db.calls <= beforeCalls || len(db.bindings) != 1 || db.bindings[0].State != lease.Leased {
			t.Fatal("ACK without a new durable commit")
		}
	}
	return reply
}

// Guard the fuzz fixtures themselves: a reset to an empty engine must not turn
// successful lease transitions back into vacuous no-reply checks.
func TestHandlerFuzzStateTransitions(t *testing.T) {
	seeds := handlerFuzzSeeds(t)
	for _, tc := range []struct {
		state, form string
		wantState   lease.State
		wantReply   bool
		wantWrite   bool
	}{
		{"offered", "selecting", lease.Leased, true, true},
		{"leased", "reboot", lease.Leased, true, true},
		{"leased", "renewal", lease.Leased, true, true},
		{"leased", "release", "", false, true},
		{"offered", "decline", lease.Quarantined, false, true},
		{"leased", "decline", lease.Quarantined, false, true},
		{"leased", "inform", lease.Leased, true, false},
	} {
		t.Run(tc.state+"/"+tc.form, func(t *testing.T) {
			h, db := handlerFuzzState(t, tc.state)
			before := db.calls
			reply := checkHandlerFuzzInput(t, h, db, seeds[tc.form])
			if (reply != nil) != tc.wantReply || (db.calls > before) != tc.wantWrite {
				t.Fatalf("transition not exercised: reply=%v writes=%d", reply, db.calls-before)
			}
			if reply != nil {
				packet, err := protocol.Parse(reply.Packet)
				if err != nil || packet.MessageType() != dhcpv4.MessageTypeAck {
					t.Fatal("successful transition did not ACK")
				}
			}
			if tc.wantState == "" {
				if len(db.bindings) != 0 {
					t.Fatal("release did not remove binding")
				}
			} else if len(db.bindings) != 1 || db.bindings[0].State != tc.wantState {
				t.Fatalf("wrong resulting state: %+v", db.bindings)
			}
		})
	}
}
