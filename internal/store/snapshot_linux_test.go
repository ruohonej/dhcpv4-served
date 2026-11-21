package store

import (
	"errors"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"dhcpv4-served/internal/lease"
)

func TestSnapshotRecoveryAndIdentity(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	s, initial, err := OpenSnapshot(dir, "a", "network-a")
	if err != nil || len(initial) != 0 {
		t.Fatal(err)
	}
	b := []lease.Binding{{
		Instance: "a",
		Address:  netip.MustParseAddr("192.0.2.10"),
		Client:   "id",
		Hardware: "mac",
		State:    lease.Leased,
		Started:  time.Now(),
		Duration: time.Hour,
	}}
	if err = s.Save(b); err != nil {
		t.Fatal(err)
	}
	if _, _, err = OpenSnapshot(dir, "a", "network-a"); err == nil {
		t.Fatal("second lock acquired")
	}
	s.Close()
	if _, _, err = OpenSnapshot(dir, "a", "network-b"); err == nil {
		t.Fatal("accepted wrong network")
	}
	s, got, err := OpenSnapshot(dir, "a", "network-a")
	if err != nil || len(got) != 1 || got[0].Address != b[0].Address {
		t.Fatalf("recovery: %v %v", got, err)
	}
	s.Close()
	if err = os.WriteFile(filepath.Join(dir, "leases.json"), []byte(`{"version":1,"unknown":1}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err = OpenSnapshot(dir, "a", "network-a"); err == nil {
		t.Fatal("accepted corrupt snapshot")
	}
}

// Exercise expiry across real snapshot close/reopen boundaries without client
// traffic. A restart before cleanup must reconstruct the entire safety hold.
func TestIdleSweepSnapshotRecovery(t *testing.T) {
	for _, state := range []lease.State{lease.Leased, lease.Quarantined} {
		t.Run(string(state), func(t *testing.T) {
			dir := t.TempDir()
			if err := os.Chmod(dir, 0700); err != nil {
				t.Fatal(err)
			}
			now := time.Now()
			cfg := lease.Config{
				Instance:        "a",
				Start:           netip.MustParseAddr("192.0.2.10"),
				End:             netip.MustParseAddr("192.0.2.10"),
				OfferDuration:   time.Minute,
				LeaseDuration:   time.Minute,
				DeclineDuration: time.Minute,
			}
			open := func() (*SnapshotStore, *lease.Engine) {
				s, records, err := OpenSnapshot(dir, "a", "network-a")
				if err != nil {
					t.Fatal(err)
				}
				e, err := lease.New(s, slog.Default(), func() time.Time { return now }, cfg, records)
				if err != nil {
					t.Fatal(err)
				}
				return s, e
			}
			s, e := open()
			b, err := e.Offer("id", "mac", 1, netip.Addr{})
			if err != nil {
				t.Fatal(err)
			}
			if state == lease.Leased {
				if _, ok, err := e.Grant("id", b.Address, 1); !ok || err != nil {
					t.Fatal(ok, err)
				}
			} else if ok, err := e.Decline("id", b.Address); !ok || err != nil {
				t.Fatal(ok, err)
			}
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			now = now.Add(24 * time.Hour)
			s, e = open()
			now = now.Add(time.Minute - time.Nanosecond)
			if err := e.Sweep(); err != nil {
				t.Fatal(err)
			}
			if _, err := e.Offer("other", "mac2", 2, netip.Addr{}); !errors.Is(err, lease.ErrExhausted) {
				t.Fatalf("early reuse: %v", err)
			}
			now = now.Add(time.Nanosecond)
			if err := e.Sweep(); err != nil {
				t.Fatal(err)
			}
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			s, e = open()
			defer s.Close()
			if _, err := e.Offer("other", "mac2", 2, netip.Addr{}); err != nil {
				t.Fatalf("expired record survived reload: %v", err)
			}
		})
	}
}
