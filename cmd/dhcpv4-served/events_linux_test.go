package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4"

	"dhcpv4-served/internal/events"
	"dhcpv4-served/internal/lease"
	"dhcpv4-served/internal/server"
)

// Exercise the production receive decision and send accounting without a socket,
// using the #37 malformed / rotating-identity mix and a deterministic clock.
func TestWorkerFloodEvents(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	now := start
	clock := func() time.Time { return now }
	var output bytes.Buffer
	sha := strings.Repeat("a", 40)
	audit := events.New("lan10", sha, &output, io.Discard, clock)
	ip := netip.MustParseAddr
	engine, err := lease.New(&idleStore{}, audit.Logger(), clock, lease.Config{
		Instance: "lan10", Start: ip("192.0.2.10"), End: ip("192.0.2.137"),
		OfferDuration: time.Minute, LeaseDuration: time.Hour, DeclineDuration: time.Minute,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	handler := server.New(engine, clock, server.Config{OnReject: audit.Count,
		Server: ip("192.0.2.1"), Subnet: netip.MustParsePrefix("192.0.2.0/24"), LeaseDuration: time.Hour})
	id := []byte("secret-client-0000")
	packet, err := dhcpv4.New(dhcpv4.WithHwAddr(net.HardwareAddr{2, 0, 0, 0, 0, 1}),
		dhcpv4.WithMessageType(dhcpv4.MessageTypeDiscover), dhcpv4.WithGeneric(dhcpv4.OptionClientIdentifier, id))
	if err != nil {
		t.Fatal(err)
	}
	valid := packet.ToBytes()
	offset := bytes.Index(valid, id)
	if offset < 0 {
		t.Fatal("missing fixture identifier")
	}
	// An incomplete option at the end of the options field.
	malformed := append(bytes.Clone(valid[:offset+len(id)]), 53, 3, 1)
	sends := 0
	send := func(*server.Response) error { sends++; return nil }
	audit.Ready(true)
	for i := range 60000 {
		now = start.Add(time.Duration(i) * time.Millisecond)
		audit.Tick(now, engine.PoolUsedPercent)
		data := malformed
		if i%2 == 1 {
			binary.BigEndian.PutUint32(valid[offset+len(id)-4:], uint32(i))
			data = valid
		}
		if err := processPacket(handler, audit, data, send); err != nil {
			t.Fatal(err)
		}
	}
	now = start.Add(time.Minute)
	audit.Tick(now, engine.PoolUsedPercent)
	if bytes.Contains(output.Bytes(), []byte("secret-client")) || bytes.Contains(output.Bytes(), []byte("192.0.2.")) ||
		bytes.Contains(output.Bytes(), []byte("02:00:00")) {
		t.Fatal("client metadata in output")
	}
	lines := bytes.Split(bytes.TrimSpace(output.Bytes()), []byte("\n"))
	if len(lines) > 20+10*60+1 {
		t.Fatalf("%d events during flood", len(lines))
	}
	summary := map[string]int{}
	markers := map[string]int{}
	for _, line := range lines {
		var event struct {
			Version                                       int `json:"schema_version"`
			Timestamp                                     time.Time
			ID                                            string `json:"event_id"`
			SHA                                           string `json:"build_sha"`
			Reason, Severity, Instance, Interface, Result string
			Count                                         int
			Suppressed                                    int `json:"suppressed_count"`
			Rejected                                      int `json:"rejected_count"`
			Usage                                         int `json:"pool_used_percent"`
			Protection                                    string
		}
		if err := json.Unmarshal(line, &event); err != nil {
			t.Fatal(err)
		}
		if len(line)+1 > 2048 || event.Version != 1 || event.Timestamp.Location() != time.UTC ||
			event.Timestamp.IsZero() || event.Instance != "lan10" || event.Interface != "lan10" ||
			event.SHA != sha || event.Result == "" || event.Severity == "" || event.Reason == "" {
			t.Fatalf("invalid event %s", line)
		}
		markers[event.ID]++
		switch event.ID {
		case "packet.rejected", "reply.sent", "pool.pressure":
			if summary[event.Reason] != 0 || event.Count < 1 || event.Suppressed != event.Count-1 {
				t.Fatalf("invalid summary %s", line)
			}
			summary[event.Reason] = event.Count
		case "worker.heartbeat":
			if event.Usage != 100 || event.Rejected != summary["malformed"]+summary["admission"] || event.Protection != "degraded" {
				t.Fatalf("invalid heartbeat %s", line)
			}
		}
	}
	if summary["malformed"] != 30000 || sends != 128 || summary["sent"] != sends || summary["admission"] == 0 ||
		summary["exhausted"] == 0 || summary["sent"]+summary["admission"]+summary["exhausted"] != 30000 ||
		markers["worker.ready"] != 1 || markers["security.degraded"] != 2 || markers["worker.heartbeat"] != 1 {
		t.Fatalf("summaries=%v, events=%v, sent=%d", summary, markers, sends)
	}
}
