// Package events records bounded operational metadata for one serial DHCP worker.
package events

import (
	"context"
	"io"
	"log/slog"
	"os"
	"regexp"
	"time"
)

var (
	interfaceName = regexp.MustCompile(`^[a-zA-Z0-9_.-]{1,15}$`)
	revision      = regexp.MustCompile(`^([0-9a-f]{40}|[0-9a-f]{64})$`)
)

// Counter is a fixed bucket. Packet data never becomes a reason or a key.
type Counter int

const (
	Malformed Counter = iota
	SourcePort
	Ingress
	Policy
	Admission
	Exhausted
	Sent
)

var buckets = [...]struct {
	id, reason, result string
	level              slog.Level
}{
	Malformed:  {"packet.rejected", "malformed", "dropped", slog.LevelWarn},
	SourcePort: {"packet.rejected", "source_port", "dropped", slog.LevelWarn},
	Ingress:    {"packet.rejected", "ingress", "dropped", slog.LevelWarn},
	Policy:     {"packet.rejected", "policy", "dropped", slog.LevelWarn},
	Admission:  {"packet.rejected", "admission", "dropped", slog.LevelWarn},
	Exhausted:  {"pool.pressure", "exhausted", "unavailable", slog.LevelWarn},
	Sent:       {"reply.sent", "sent", "success", slog.LevelInfo},
}

type Recorder struct {
	log                             *slog.Logger
	sink                            *delivery
	next                            time.Time
	counts                          [len(buckets)]uint64
	degraded                        bool
	firstExhaustion, lastExhaustion time.Time
	now                             func() time.Time
}

// NewWorker wires inherited descriptors and starts a writer for each redirected sink.
func NewWorker(iface, sha string, primary, fallback *os.File, now func() time.Time) *Recorder {
	primaryWriter, redirectPrimary := workerOutput(primary)
	fallbackWriter, redirectFallback := workerOutput(fallback)
	recorder := New(iface, sha, primaryWriter, fallbackWriter, now)
	if redirectPrimary {
		recorder.sink.primaryQueue = startWriter(recorder.sink.writePrimary)
	}
	if redirectFallback {
		recorder.sink.fallbackQueue = startWriter(recorder.sink.writeFallback)
	}
	return recorder
}

// Close finishes queued output at worker exit, up to a shared deadline.
func (r *Recorder) Close() { r.sink.close() }

func New(iface, sha string, primary, fallback io.Writer, now func() time.Time) *Recorder {
	if !interfaceName.MatchString(iface) {
		iface = "unknown"
	}
	if !revision.MatchString(sha) {
		sha = "unknown"
	}
	if primary == nil || fallback == nil || now == nil {
		panic("events: outputs and clock are required")
	}
	sink := &delivery{primary: primary, fallback: fallback, now: now}
	handler := slog.NewJSONHandler(sink, &slog.HandlerOptions{ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
		switch a.Key {
		case slog.TimeKey:
			return slog.Time("timestamp", now().UTC())
		case slog.MessageKey:
			a.Key = "event_id"
		case slog.LevelKey:
			a.Key = "severity"
		}
		return a
	}})
	log := slog.New(handler).With("schema_version", 1, "instance", iface, "interface", iface, "build_sha", sha)
	return &Recorder{log: log, sink: sink, now: now, next: now().Add(time.Minute)}
}

// Logger is shared with the lease engine for its single terminal state.failed event.
func (r *Recorder) Logger() *slog.Logger { return r.log }

func (r *Recorder) Count(c Counter) {
	r.counts[c]++
	if c == Exhausted {
		now := r.now()
		if r.lastExhaustion.IsZero() || now.Sub(r.lastExhaustion) > time.Minute {
			r.firstExhaustion = now
		}
		r.lastExhaustion = now
	}
}

func (r *Recorder) Ready(lab bool) {
	r.degraded = lab
	if lab {
		r.protection()
	}
	r.log.Info("worker.ready", "reason", "checks_passed", "result", "serving", "count", 1)
}

func (r *Recorder) protection() {
	r.log.Warn("security.degraded", "reason", "explicit_lab", "result", "degraded", "count", 1, "suppressed_count", 0)
}

// Tick runs even on read timeouts. Missed windows never cause catch-up bursts.
func (r *Recorder) Tick(now time.Time, usage func() int) {
	if now.Before(r.next) {
		return
	}
	window := now.Sub(r.next.Add(-time.Minute))
	r.next = now.Add(time.Minute)
	var rejected uint64
	for i, count := range r.counts {
		if count == 0 {
			continue
		}
		b := buckets[i]
		if b.id == "packet.rejected" {
			rejected += count
		}
		r.log.Log(context.Background(), b.level, b.id, "reason", b.reason, "result", b.result, "count", count,
			"suppressed_count", count-1, "window_ms", window.Milliseconds())
		r.counts[i] = 0
	}
	if r.degraded {
		r.protection()
	}
	// A successful local write cannot attest persistence or central receipt.
	protection := "strict"
	if r.degraded {
		protection = "degraded"
	}
	r.log.Info("worker.heartbeat", "reason", "interval", "result", "serving", "count", 1,
		"pool_used_percent", usage(), "exhaustion_ms", r.exhaustionDuration(now).Milliseconds(), "protection", protection,
		"rejected_per_second", float64(rejected)/window.Seconds(), "rejected_count", rejected, "window_ms", window.Milliseconds(), "suppressed_count", 0)
}

func (r *Recorder) exhaustionDuration(now time.Time) time.Duration {
	if r.lastExhaustion.IsZero() || now.Sub(r.lastExhaustion) > time.Minute {
		return 0
	}
	return r.lastExhaustion.Sub(r.firstExhaustion)
}
