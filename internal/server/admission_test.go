package server

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4"
)

func TestAdmissionFloodPreservesCommittedRenewal(t *testing.T) {
	h, db := gateHandler(t)
	selecting := gateSelecting(t, h)
	reply, err := h.Reply(selecting.ToBytes())
	if err != nil {
		t.Fatal(err)
	}
	gateACK(t, reply, db)
	// Pin a depleted aggregate bucket in the future: no wall-clock timing in
	// this regression. Rotating IDs and forged renewal fields cannot refill it.
	h.admission.general = bucket{last: time.Now().Add(time.Hour)}
	for i := range 1000 {
		for _, kind := range []dhcpv4.MessageType{dhcpv4.MessageTypeDiscover, dhcpv4.MessageTypeRequest} {
			p := gatePacket(t, fmt.Sprintf("rotation-%d", i), kind)
			if kind == dhcpv4.MessageTypeRequest {
				p.ClientIPAddr = net.ParseIP("192.0.2.10")
			}
			if reply, err := h.Reply(p.ToBytes()); err != nil || reply != nil {
				t.Fatalf("unowned flood bypassed admission: %v, %v", reply, err)
			}
		}
	}
	renewal := gatePacket(t, "owner", dhcpv4.MessageTypeRequest)
	renewal.ClientIPAddr = net.ParseIP("192.0.2.10")
	reply, err = h.Reply(renewal.ToBytes())
	if err != nil {
		t.Fatal(err)
	}
	gateACK(t, reply, db)
	// Reserved capacity is bounded too; a client knowing a lease identity must
	// not get unlimited disk commits or replies.
	h.admission.renewal = bucket{last: time.Now().Add(time.Hour)}
	before := db.calls
	if reply, err := h.Reply(renewal.ToBytes()); err != nil || reply != nil || db.calls != before {
		t.Fatalf("renewal exceeded its bound: %v, %v", reply, err)
	}
}

func TestAdmissionRefill(t *testing.T) {
	var a admission
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for range AdmissionBurst {
		if !a.allow(now, false) {
			t.Fatal("initial burst rejected")
		}
	}
	if a.allow(now, false) {
		t.Fatal("burst exceeded")
	}
	if !a.allow(now.Add(time.Second/AdmissionRate), false) {
		t.Fatal("no refill")
	}
	if a.allow(now.Add(time.Second/AdmissionRate), false) {
		t.Fatal("refill exceeded")
	}
	if !a.allow(now, true) {
		t.Fatal("no reserved renewal capacity")
	}
}
