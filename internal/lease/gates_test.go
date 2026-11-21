package lease

import (
	"errors"
	"log/slog"
	"net/netip"
	"testing"
	"time"
)

func TestGateRestartReservations(t *testing.T) {
	for _, state := range []State{Leased, Quarantined} {
		for _, shift := range []struct {
			name string
			by   time.Duration
		}{
			{"clock_forward", 365 * 24 * time.Hour},
			{"clock_backward", -24 * time.Hour},
		} {
			t.Run(string(state)+"/"+shift.name, func(t *testing.T) {
				started := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
				now := started.Add(shift.by)
				address := netip.MustParseAddr("192.0.2.10")
				db := &memoryStore{}
				cfg := Config{
					Instance:        "one",
					Start:           address,
					End:             address,
					OfferDuration:   time.Minute,
					LeaseDuration:   time.Hour,
					DeclineDuration: time.Hour,
				}
				recovered := []Binding{{
					Instance: "one",
					Address:  address,
					Client:   "owner",
					Hardware: "mac",
					State:    state,
					Started:  started,
					Duration: time.Hour,
				}}
				engine, err := New(db, slog.Default(), func() time.Time { return now }, cfg, recovered)
				if err != nil {
					t.Fatal(err)
				}
				assertReserved := func() {
					t.Helper()
					if _, err := engine.Offer("other", "mac-other", 1, address); !errors.Is(err, ErrExhausted) {
						t.Fatalf("recovered %s reused early: %v", state, err)
					}
				}
				assertReserved()
				now = now.Add(time.Hour - time.Nanosecond)
				assertReserved()
				// Another restart re-establishes the full hold, rather than trusting Started.
				engine, err = New(db, slog.Default(), func() time.Time { return now }, cfg, recovered)
				if err != nil {
					t.Fatal(err)
				}
				now = now.Add(time.Hour - time.Nanosecond)
				assertReserved()
				now = now.Add(time.Nanosecond)
				binding, err := engine.Offer("other", "mac-other", 1, address)
				if err != nil || binding.Address != address {
					t.Fatalf("address not reusable at hold deadline: %+v %v", binding, err)
				}
				if len(db.bindings) != 0 {
					t.Fatal("expired recovery record not removed durably")
				}
			})
		}
	}
}
