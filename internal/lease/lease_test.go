package lease

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"testing"
	"time"
)

var errDisk = errors.New("disk")

type memoryStore struct {
	bindings []Binding
	fail     bool
}

func (s *memoryStore) Save(b []Binding) error {
	if s.fail {
		return errDisk
	}
	s.bindings = append([]Binding(nil), b...)
	return nil
}

func TestAllocationOwnershipAndRecovery(t *testing.T) {
	now := time.Now()
	store := &memoryStore{}
	cfg := Config{
		Instance:        "one",
		Start:           netip.MustParseAddr("192.0.2.10"),
		End:             netip.MustParseAddr("192.0.2.11"),
		OfferDuration:   time.Minute,
		LeaseDuration:   time.Hour,
		DeclineDuration: time.Minute,
	}
	e, err := New(store, slog.Default(), func() time.Time { return now }, cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	a, err := e.Offer("a", "mac-a", 1, cfg.End)
	if err != nil || a.Address != cfg.End {
		t.Fatalf("offer: %+v %v", a, err)
	}
	now = now.Add(30 * time.Second)
	again, _ := e.Offer("a", "mac-a", 1, netip.Addr{})
	if again.Address != a.Address || again.Started != a.Started {
		t.Fatal("offer extended")
	}
	if _, ok, _ := e.Grant("b", a.Address, 1); ok {
		t.Fatal("wrong owner granted")
	}
	if _, ok, _ := e.Grant("a", a.Address, 2); ok {
		t.Fatal("wrong transaction granted")
	}
	if _, ok, err := e.Grant("a", a.Address, 1); err != nil || !ok {
		t.Fatal("grant failed", err)
	}
	b, err := e.Offer("b", "mac-b", 2, cfg.End)
	if err != nil || b.Address != cfg.Start {
		t.Fatalf("competing offer: %+v %v", b, err)
	}
	if _, err = e.Offer("c", "mac-c", 3, netip.Addr{}); !errors.Is(err, ErrExhausted) {
		t.Fatal("expected exhaustion", err)
	}
	if ok, _ := e.Decline("b", a.Address); ok {
		t.Fatal("wrong owner declined")
	}
	if ok, err := e.Decline("b", b.Address); !ok || err != nil {
		t.Fatal("decline failed", err)
	}
	now = now.Add(24 * time.Hour)
	recovered, err := New(store, slog.Default(), func() time.Time { return now }, cfg, store.bindings)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = recovered.Offer("c", "mac-c", 3, netip.Addr{}); !errors.Is(err, ErrExhausted) {
		t.Fatal("recovery did not reserve", err)
	}
	now = now.Add(time.Minute)
	c, err := recovered.Offer("c", "mac-c", 3, netip.Addr{})
	if err != nil || c.Address != cfg.Start {
		t.Fatal("quarantine not reclaimed", err)
	}
}

func TestStorageFailureStopsAllocation(t *testing.T) {
	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, nil))
	s := &memoryStore{}
	cfg := Config{
		Instance:        "x",
		Start:           netip.MustParseAddr("192.0.2.1"),
		End:             netip.MustParseAddr("192.0.2.1"),
		OfferDuration:   time.Second,
		LeaseDuration:   time.Hour,
		DeclineDuration: time.Minute,
	}
	e, err := New(s, logger, time.Now, cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := e.Offer("a", "mac", 1, netip.Addr{})
	if _, err := e.Offer("", "mac", 1, netip.Addr{}); !errors.Is(err, ErrInvalidIdentity) {
		t.Fatalf("expected invalid identity, got %v", err)
	}
	if logs.Len() != 0 {
		t.Fatalf("expected identity rejection to remain silent, got %s", logs.String())
	}
	s.fail = true
	if _, ok, err := e.Grant("a", b.Address, 1); ok || !errors.Is(err, ErrStorage) || !errors.Is(err, errDisk) {
		t.Fatal("failed commit accepted", err)
	}
	if _, err := e.Offer("b", "mac", 2, netip.Addr{}); !errors.Is(err, ErrStorage) {
		t.Fatal("engine did not fail closed", err)
	}
	if bytes.Count(logs.Bytes(), []byte("\n")) != 1 || !bytes.Contains(logs.Bytes(), []byte("state.failed")) {
		t.Fatalf("expected one persistence failure log, got %s", logs.String())
	}
}

func TestNewRequiresDependencies(t *testing.T) {
	for _, tt := range []struct {
		name   string
		store  Store
		logger *slog.Logger
		now    func() time.Time
		want   string
	}{
		{"store", nil, slog.Default(), time.Now, "lease: store is required"},
		{"logger", &memoryStore{}, nil, time.Now, "lease: logger is required"},
		{"clock", &memoryStore{}, slog.Default(), nil, "lease: clock is required"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				if got := recover(); got != tt.want {
					t.Fatalf("expected panic %q, got %v", tt.want, got)
				}
			}()
			_, _ = New(tt.store, tt.logger, tt.now, Config{}, nil)
		})
	}
}

func TestNewReturnsValidationErrors(t *testing.T) {
	valid := Config{
		Instance:        "test",
		Start:           netip.MustParseAddr("192.0.2.10"),
		End:             netip.MustParseAddr("192.0.2.11"),
		OfferDuration:   time.Minute,
		LeaseDuration:   time.Hour,
		DeclineDuration: time.Minute,
	}
	for _, tt := range []struct {
		name      string
		configure func(*Config)
		recovered []Binding
		want      error
	}{
		{"missing instance", func(cfg *Config) { cfg.Instance = "" }, nil, ErrInvalidConfig},
		{"invalid pool", func(cfg *Config) { cfg.Start = netip.Addr{} }, nil, ErrInvalidConfig},
		{"invalid duration", func(cfg *Config) { cfg.LeaseDuration = 0 }, nil, ErrInvalidConfig},
		{"invalid recovered state", func(cfg *Config) {}, []Binding{{Instance: "other"}}, ErrInvalidBinding},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cfg := valid
			tt.configure(&cfg)
			engine, err := New(&memoryStore{}, slog.Default(), time.Now, cfg, tt.recovered)
			if engine != nil || !errors.Is(err, tt.want) {
				t.Fatalf("expected %v, got engine=%v error=%v", tt.want, engine, err)
			}
		})
	}
}

func TestIdleSweepDurableExpiryAndRecovery(t *testing.T) {
	for _, state := range []State{Leased, Quarantined} {
		t.Run(string(state), func(t *testing.T) {
			now := time.Now()
			s := &memoryStore{}
			cfg := Config{
				Instance:        "x",
				Start:           netip.MustParseAddr("192.0.2.1"),
				End:             netip.MustParseAddr("192.0.2.1"),
				OfferDuration:   time.Minute,
				LeaseDuration:   time.Minute,
				DeclineDuration: time.Minute,
			}
			e, err := New(s, slog.Default(), func() time.Time { return now }, cfg, nil)
			if err != nil {
				t.Fatal(err)
			}
			b, err := e.Offer("a", "mac", 1, netip.Addr{})
			if err != nil {
				t.Fatal(err)
			}
			if state == Leased {
				if _, ok, err := e.Grant("a", b.Address, 1); !ok || err != nil {
					t.Fatal(ok, err)
				}
			} else if ok, err := e.Decline("a", b.Address); !ok || err != nil {
				t.Fatal(ok, err)
			}
			now = now.Add(time.Minute - time.Nanosecond)
			if err := e.Sweep(); err != nil || len(s.bindings) != 1 {
				t.Fatalf("early sweep: %v, %d", err, len(s.bindings))
			}
			// A restart before cleanup reserves the full recorded duration, even
			// when the wall clock has jumped far beyond the original start.
			now = now.Add(24 * time.Hour)
			recovered, err := New(s, slog.Default(), func() time.Time { return now }, cfg, s.bindings)
			if err != nil {
				t.Fatal(err)
			}
			if err := recovered.Sweep(); err != nil || len(s.bindings) != 1 {
				t.Fatalf("recovery sweep: %v", err)
			}
			now = now.Add(time.Minute)
			if err := recovered.Sweep(); err != nil || len(s.bindings) != 0 {
				t.Fatalf("expiry sweep: %v, %d", err, len(s.bindings))
			}
			reloaded, err := New(s, slog.Default(), func() time.Time { return now }, cfg, s.bindings)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := reloaded.Offer("b", "mac-b", 2, netip.Addr{}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestIdleSweepFailurePoisonsEngine(t *testing.T) {
	for _, state := range []State{Leased, Quarantined} {
		t.Run(string(state), func(t *testing.T) {
			now := time.Now()
			s := &memoryStore{}
			cfg := Config{
				Instance:        "x",
				Start:           netip.MustParseAddr("192.0.2.1"),
				End:             netip.MustParseAddr("192.0.2.1"),
				OfferDuration:   time.Minute,
				LeaseDuration:   time.Minute,
				DeclineDuration: time.Minute,
			}
			e, _ := New(s, slog.Default(), func() time.Time { return now }, cfg, nil)
			b, _ := e.Offer("a", "mac", 1, netip.Addr{})
			if state == Leased {
				_, _, _ = e.Grant("a", b.Address, 1)
			} else {
				_, _ = e.Decline("a", b.Address)
			}
			now = now.Add(time.Minute)
			s.fail = true
			if err := e.Sweep(); !errors.Is(err, ErrStorage) {
				t.Fatal(err)
			}
			s.fail = false
			if _, err := e.Offer("b", "mac-b", 2, netip.Addr{}); !errors.Is(err, ErrStorage) {
				t.Fatal("engine reused address after failed sweep", err)
			}
			if len(s.bindings) != 1 {
				t.Fatal("failed sweep changed durable state")
			}
		})
	}
}

func TestAggregateOfferBoundPreservesLease(t *testing.T) {
	now := time.Now()
	cfg := Config{
		Instance:        "bounded",
		Start:           netip.MustParseAddr("192.0.2.1"),
		End:             netip.MustParseAddr("192.0.3.254"),
		OfferDuration:   time.Minute,
		LeaseDuration:   time.Hour,
		DeclineDuration: time.Minute,
	}
	e, err := New(&memoryStore{}, slog.Default(), func() time.Time { return now }, cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	owner, err := e.Offer("owner", "mac", 1, netip.Addr{})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok, err := e.Grant("owner", owner.Address, 1); !ok || err != nil {
		t.Fatalf("grant: %v", err)
	}
	for i := range MaxOutstandingOffers {
		if _, err := e.Offer(fmt.Sprint(i), "mac", 1, netip.Addr{}); err != nil {
			t.Fatal(err)
		}
	}
	for i := range 1000 {
		if _, err := e.Offer(fmt.Sprint("rotated-", i), "mac", 1, netip.Addr{}); !errors.Is(err, ErrExhausted) {
			t.Fatalf("offer bound: %v", err)
		}
	}
	if len(e.bindings) != MaxOutstandingOffers+1 {
		t.Fatal("transient state grew beyond bound")
	}
	if !e.OwnsLease("owner", owner.Address) || e.OwnsLease("other", owner.Address) {
		t.Fatal("invalid ownership hint")
	}
	if _, ok, err := e.Renew("owner", owner.Address); !ok || err != nil {
		t.Fatalf("renewal denied: %v", err)
	}
	now = now.Add(2 * time.Minute)
	if _, err := e.Offer("after-expiry", "mac", 2, netip.Addr{}); err != nil {
		t.Fatalf("expired offers retain capacity: %v", err)
	}
}
