package main

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"testing"
	"time"

	"dhcpv4-served/internal/lease"
)

type idleStore struct {
	bindings []lease.Binding
	fail     bool
	writes   int
}

func (s *idleStore) Save(bindings []lease.Binding) error {
	if s.fail {
		return errors.New("injected idle commit failure")
	}
	s.writes++
	s.bindings = append([]lease.Binding(nil), bindings...)
	return nil
}

func idleLease(t *testing.T, state lease.State, recovered bool) (*lease.Engine, *idleStore, *time.Time, time.Time) {
	t.Helper()
	now := time.Now()
	db := &idleStore{}
	// Expiry just after a sweep exercises the full interval before the next one.
	duration := time.Minute + time.Nanosecond
	cfg := lease.Config{
		Instance:        "idle",
		Start:           netip.MustParseAddr("192.0.2.10"),
		End:             netip.MustParseAddr("192.0.2.10"),
		OfferDuration:   time.Minute,
		LeaseDuration:   duration,
		DeclineDuration: duration,
	}
	engine, err := lease.New(db, slog.Default(), func() time.Time { return now }, cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	binding, err := engine.Offer("client", "mac", 1, netip.Addr{})
	if err != nil {
		t.Fatal(err)
	}
	if state == lease.Leased {
		if _, ok, err := engine.Grant("client", binding.Address, 1); !ok || err != nil {
			t.Fatal(ok, err)
		}
	} else if ok, err := engine.Decline("client", binding.Address); !ok || err != nil {
		t.Fatal(ok, err)
	}
	if recovered {
		// An old wall-clock timestamp must not shorten the recovered local hold.
		now = now.Add(24 * time.Hour)
		engine, err = lease.New(db, slog.Default(), func() time.Time { return now }, cfg, db.bindings)
		if err != nil {
			t.Fatal(err)
		}
	}
	return engine, db, &now, now.Add(duration)
}

func TestServeIdleExpiry(t *testing.T) {
	for _, state := range []lease.State{lease.Leased, lease.Quarantined} {
		for _, recovered := range []bool{false, true} {
			name := string(state) + "/fresh"
			if recovered {
				name = string(state) + "/recovered"
			}
			t.Run(name, func(t *testing.T) {
				engine, db, now, expiry := idleLease(t, state, recovered)
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				atExpiry := false
				err := serve(ctx, engine, func() time.Time { return *now }, func(deadline time.Time) error {
					if now.Before(expiry) && len(db.bindings) != 1 {
						t.Fatal("sweep removed a live safety hold")
					}
					if now.Equal(expiry) {
						atExpiry = true
					}
					if !now.Before(expiry.Add(time.Minute)) && len(db.bindings) != 0 {
						t.Fatal("idle worker did not persist expiry within 60 seconds")
					}
					if len(db.bindings) == 0 {
						cancel()
						return nil
					}
					if !deadline.After(*now) || deadline.Sub(*now) > 100*time.Millisecond {
						t.Fatalf("invalid idle read deadline: %v at %v", deadline, *now)
					}
					// Simulate a read timeout without sending a packet. Also stop at
					// exact expiry to cover the deadline boundary without sleeping.
					if now.Before(expiry) && deadline.After(expiry) {
						*now = expiry
					} else {
						*now = deadline
					}
					return nil
				})
				if err != nil || !atExpiry || db.writes != 2 {
					t.Fatalf("idle expiry: err=%v exact-expiry=%v commits=%d", err, atExpiry, db.writes)
				}
			})
		}
	}
}

func TestServeStopsOnIdleSweepFailure(t *testing.T) {
	for _, state := range []lease.State{lease.Leased, lease.Quarantined} {
		t.Run(string(state), func(t *testing.T) {
			engine, db, now, expiry := idleLease(t, state, true)
			db.fail = true
			err := serve(context.Background(), engine, func() time.Time { return *now }, func(deadline time.Time) error {
				if !now.Before(expiry.Add(time.Minute)) {
					t.Fatal("worker continued after the failed idle commit was due")
				}
				if !deadline.After(*now) {
					t.Fatal("idle loop did not advance")
				}
				*now = deadline
				return nil
			})
			if !errors.Is(err, lease.ErrStorage) || len(db.bindings) != 1 || db.writes != 1 {
				t.Fatalf("failed idle commit: err=%v bindings=%v commits=%d", err, db.bindings, db.writes)
			}
			db.fail = false
			if _, err := engine.Offer("other", "mac2", 2, netip.Addr{}); !errors.Is(err, lease.ErrStorage) {
				t.Fatalf("allocation resumed after uncertain expiry: %v", err)
			}
		})
	}
}
