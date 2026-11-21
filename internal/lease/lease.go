// Package lease implements serialized, per-instance DHCP address ownership.
package lease

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/netip"
	"slices"
	"sync"
	"time"
)

// State identifies whether an address is offered, leased, or quarantined.
type State string

const (
	Offered     State = "offered"
	Leased      State = "leased"
	Quarantined State = "quarantined"
)

var (
	ErrExhausted       = errors.New("address pool exhausted")
	ErrSync            = errors.New("snapshot sync failed")
	ErrStorage         = errors.New("lease storage unavailable")
	ErrInvalidConfig   = errors.New("invalid lease configuration")
	ErrInvalidBinding  = errors.New("invalid recovered binding")
	ErrInvalidIdentity = errors.New("invalid identity")
)

// MaxOutstandingOffers caps transient holds independently of client identity.
const MaxOutstandingOffers = 128

const maxDuration = 365 * 24 * time.Hour

func validIdentity(client, hardware string) bool {
	return len(client) > 0 && len(client) <= 2050 && len(hardware) > 0 && len(hardware) <= 32
}

// Binding records an address hold and the client that owns it.
type Binding struct {
	Instance    string        `json:"instance"`
	Address     netip.Addr    `json:"address"`
	Client      string        `json:"client"`
	Hardware    string        `json:"hardware"`
	State       State         `json:"state"`
	Transaction uint32        `json:"transaction,omitempty"`
	Started     time.Time     `json:"started"`
	Duration    time.Duration `json:"duration"`

	// deadline uses the local clock and is reconstructed when state is loaded.
	deadline time.Time
}

// Store must atomically commit the entire durable state or return an error.
type Store interface {
	Save([]Binding) error
}

// Config supplies the address pool and hold durations.
type Config struct {
	Instance        string
	Start           netip.Addr
	End             netip.Addr
	Excluded        map[netip.Addr]bool
	OfferDuration   time.Duration
	LeaseDuration   time.Duration
	DeclineDuration time.Duration
}

// Engine serializes address ownership changes for one instance.
type Engine struct {
	mu       sync.Mutex
	store    Store
	logger   *slog.Logger
	now      func() time.Time
	cfg      Config
	bindings map[netip.Addr]Binding
	failed   bool
}

// New validates configuration and recovered state. Missing dependencies are
// programmer errors; invalid configuration and persisted data return errors.
func New(
	store Store,
	logger *slog.Logger,
	now func() time.Time,
	cfg Config,
	recovered []Binding,
) (*Engine, error) {
	if store == nil {
		panic("lease: store is required")
	}
	if logger == nil {
		panic("lease: logger is required")
	}
	if now == nil {
		panic("lease: clock is required")
	}
	if cfg.Instance == "" || !cfg.Start.Is4() || !cfg.End.Is4() || cfg.Start.Compare(cfg.End) > 0 {
		return nil, ErrInvalidConfig
	}
	for _, duration := range []time.Duration{cfg.OfferDuration, cfg.LeaseDuration, cfg.DeclineDuration} {
		if duration <= 0 || duration > maxDuration {
			return nil, ErrInvalidConfig
		}
	}
	cfg.Excluded = maps.Clone(cfg.Excluded)

	e := &Engine{
		store:    store,
		logger:   logger,
		now:      now,
		cfg:      cfg,
		bindings: make(map[netip.Addr]Binding),
	}
	clients := map[string]bool{}
	current := now()
	for _, binding := range recovered {
		if binding.Instance != cfg.Instance || !e.eligible(binding.Address) {
			return nil, ErrInvalidBinding
		}
		if !validIdentity(binding.Client, binding.Hardware) || binding.Started.IsZero() {
			return nil, ErrInvalidBinding
		}
		if binding.Duration <= 0 || binding.Duration > maxDuration {
			return nil, ErrInvalidBinding
		}
		if binding.State != Leased && binding.State != Quarantined {
			return nil, ErrInvalidBinding
		}
		if _, ok := e.bindings[binding.Address]; ok {
			return nil, fmt.Errorf("%w: duplicate address", ErrInvalidBinding)
		}
		if binding.State == Leased && clients[binding.Client] {
			return nil, fmt.Errorf("%w: duplicate client", ErrInvalidBinding)
		}
		if binding.State == Leased {
			clients[binding.Client] = true
		}
		binding.deadline = current.Add(binding.Duration)
		e.bindings[binding.Address] = binding
	}
	return e, nil
}

// PoolUsedPercent reports held eligible addresses, including offers and quarantine.
func (e *Engine) PoolUsedPercent() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	start, end := e.cfg.Start.As4(), e.cfg.End.As4()
	capacity := int64(binary.BigEndian.Uint32(end[:])) - int64(binary.BigEndian.Uint32(start[:])) + 1
	for addr, excluded := range e.cfg.Excluded {
		if excluded && addr.Compare(e.cfg.Start) >= 0 && addr.Compare(e.cfg.End) <= 0 {
			capacity--
		}
	}
	if capacity == 0 {
		return 100
	}
	return int(int64(len(e.bindings)) * 100 / capacity)
}

func (e *Engine) eligible(address netip.Addr) bool {
	return address.Is4() && address.Compare(e.cfg.Start) >= 0 && address.Compare(e.cfg.End) <= 0 && !e.cfg.Excluded[address]
}

func (e *Engine) commit(next map[netip.Addr]Binding) error {
	// Offers are transient; only leases and quarantines survive a restart.
	durable := make([]Binding, 0, len(next))
	for _, binding := range next {
		if binding.State != Offered {
			durable = append(durable, binding)
		}
	}
	slices.SortFunc(durable, func(a, b Binding) int {
		return a.Address.Compare(b.Address)
	})
	if err := e.store.Save(durable); err != nil {
		e.failed = true
		reason := "write"
		if errors.Is(err, ErrSync) {
			reason = "sync"
		}
		e.logger.Error("state.failed", "reason", reason, "result", "stopped", "count", 1)
		return fmt.Errorf("commit lease state: %w: %w", ErrStorage, err)
	}
	e.bindings = next
	return nil
}

func (e *Engine) expire() error {
	if e.failed {
		return ErrStorage
	}

	next := maps.Clone(e.bindings)
	durable := false
	changed := false
	now := e.now()
	for address, binding := range next {
		if now.Before(binding.deadline) {
			continue
		}
		delete(next, address)
		changed = true
		durable = durable || binding.State != Offered
	}

	if durable {
		return e.commit(next)
	}
	if changed {
		e.bindings = next
	}
	return nil
}

// Sweep removes expired holds, committing durable removals before reuse.
// A failed commit permanently disables this engine until it is restarted.
func (e *Engine) Sweep() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.expire()
}

// Offer preserves an existing hold's original deadline on retransmission.
func (e *Engine) Offer(client, hardware string, xid uint32, requested netip.Addr) (Binding, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if !validIdentity(client, hardware) {
		return Binding{}, ErrInvalidIdentity
	}
	if err := e.expire(); err != nil {
		return Binding{}, err
	}

	for _, binding := range e.bindings {
		if binding.Client == client && (binding.State == Leased || binding.State == Offered) {
			if binding.State == Offered {
				binding.Transaction = xid
				e.bindings[binding.Address] = binding
			}
			return binding, nil
		}
	}

	offers := 0
	for _, binding := range e.bindings {
		if binding.State == Offered {
			offers++
		}
	}
	if offers >= MaxOutstandingOffers {
		return Binding{}, ErrExhausted
	}

	address := requested
	if !e.eligible(address) {
		address = netip.Addr{}
	} else if _, ok := e.bindings[address]; ok {
		address = netip.Addr{}
	}
	if !address.IsValid() {
		for candidate := e.cfg.Start; candidate.IsValid() && candidate.Compare(e.cfg.End) <= 0; candidate = candidate.Next() {
			if !e.eligible(candidate) {
				continue
			}
			if _, occupied := e.bindings[candidate]; !occupied {
				address = candidate
				break
			}
		}
	}
	if !address.IsValid() {
		return Binding{}, ErrExhausted
	}

	now := e.now()
	binding := Binding{
		Instance:    e.cfg.Instance,
		Address:     address,
		Client:      client,
		Hardware:    hardware,
		State:       Offered,
		Transaction: xid,
		Started:     now,
		Duration:    e.cfg.OfferDuration,
		deadline:    now.Add(e.cfg.OfferDuration),
	}
	e.bindings[address] = binding
	return binding, nil
}

// Grant commits a matching offer or existing lease before returning success.
func (e *Engine) Grant(client string, address netip.Addr, xid uint32) (Binding, bool, error) {
	return e.grant(client, address, xid, false)
}

// Renew requires a committed lease, never an outstanding offer.
func (e *Engine) Renew(client string, address netip.Addr) (Binding, bool, error) {
	return e.grant(client, address, 0, true)
}

// Evidence reports whether the client has a live lease and whether the address
// is held by a different client. Offers do not establish known lease ownership.
func (e *Engine) Evidence(client string, address netip.Addr) (known, other bool, err error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if err = e.expire(); err != nil {
		return
	}
	for _, binding := range e.bindings {
		if binding.State == Leased && binding.Client == client {
			known = true
		}
		if binding.Address == address && binding.State == Leased && binding.Client != client {
			other = true
		}
	}
	return
}

func (e *Engine) grant(client string, address netip.Addr, xid uint32, leaseOnly bool) (Binding, bool, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := e.expire(); err != nil {
		return Binding{}, false, err
	}
	binding, ok := e.bindings[address]
	if !ok || binding.Client != client {
		return Binding{}, false, nil
	}
	if binding.State != Leased && (leaseOnly || binding.State != Offered || binding.Transaction != xid) {
		return Binding{}, false, nil
	}

	now := e.now()
	binding.State = Leased
	binding.Transaction = 0
	binding.Started = now
	binding.Duration = e.cfg.LeaseDuration
	binding.deadline = now.Add(binding.Duration)

	next := maps.Clone(e.bindings)
	next[address] = binding
	if err := e.commit(next); err != nil {
		return Binding{}, false, err
	}
	return binding, true, nil
}

// DropOffer releases a hold when a client selects another server.
func (e *Engine) DropOffer(client string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := e.expire(); err != nil {
		return err
	}
	maps.DeleteFunc(e.bindings, func(_ netip.Addr, binding Binding) bool {
		return binding.Client == client && binding.State == Offered
	})
	return nil
}

// Release removes only a binding owned by the caller.
func (e *Engine) Release(client string, address netip.Addr) (bool, error) {
	return e.remove(client, address, false)
}

// Decline quarantines only a binding owned by the caller.
func (e *Engine) Decline(client string, address netip.Addr) (bool, error) {
	return e.remove(client, address, true)
}

func (e *Engine) remove(client string, address netip.Addr, decline bool) (bool, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := e.expire(); err != nil {
		return false, err
	}
	binding, ok := e.bindings[address]
	if !ok || binding.Client != client {
		return false, nil
	}
	if binding.State != Leased && (!decline || binding.State != Offered) {
		return false, nil
	}

	next := maps.Clone(e.bindings)
	if decline {
		now := e.now()
		binding.State = Quarantined
		binding.Started = now
		binding.Duration = e.cfg.DeclineDuration
		binding.deadline = now.Add(binding.Duration)
		binding.Transaction = 0
		next[address] = binding
	} else {
		delete(next, address)
	}
	if err := e.commit(next); err != nil {
		return false, err
	}
	return true, nil
}

// OwnsLease checks live committed ownership without scanning or mutating state.
// It is only an admission hint; Renew still rechecks ownership and durability.
func (e *Engine) OwnsLease(client string, address netip.Addr) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	binding, ok := e.bindings[address]
	return !e.failed && ok && binding.Client == client && binding.State == Leased && e.now().Before(binding.deadline)
}
