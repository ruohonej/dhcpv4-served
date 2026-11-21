package server

import (
	"sync"
	"time"
)

// AdmissionRate and AdmissionBurst bound expensive handler work and replies per
// worker. The separate, equally bounded renewal bucket is selected by committed
// ownership, never by an untrusted request's message type alone. Parsing remains
// bounded by protocol.MaxPacketSize and the production loop has no work queue.
const AdmissionRate = 100
const AdmissionBurst = 100

type admission struct {
	mu               sync.Mutex
	general, renewal bucket
}

type bucket struct {
	last   time.Time
	tokens float64
}

func (a *admission) allow(now time.Time, renewal bool) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	b := &a.general
	if renewal {
		b = &a.renewal
	}
	if b.last.IsZero() {
		b.tokens = AdmissionBurst
		b.last = now
	}
	if elapsed := now.Sub(b.last).Seconds(); elapsed > 0 {
		b.tokens = min(float64(AdmissionBurst), b.tokens+elapsed*AdmissionRate)
		b.last = now
	}
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}
