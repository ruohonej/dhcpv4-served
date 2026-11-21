package events

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

type failedOutput struct{ err error }

func (w failedOutput) Write([]byte) (int, error) { return 0, w.err }

func TestLocalDeliveryFaults(t *testing.T) {
	for _, fault := range []string{"full journal queue", "unavailable journal", "disk full", "short write"} {
		t.Run(fault, func(t *testing.T) {
			var primary io.Writer
			switch fault {
			case "disk full":
				primary = failedOutput{unix.ENOSPC}
			case "short write":
				primary = failedOutput{}
			default:
				pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
				if err != nil {
					t.Fatal(err)
				}
				socket := os.NewFile(uintptr(pair[0]), "worker-journal")
				defer socket.Close()
				primary, _ = workerOutput(socket)
				if fault == "unavailable journal" {
					unix.Close(pair[1])
				} else {
					defer unix.Close(pair[1])
					// Fill the kernel queue until even the smallest nonblocking write fails.
					data := make([]byte, 4096)
					for _, p := range [][]byte{data, data[:1]} {
						for {
							if _, err = primary.Write(p); err != nil {
								break
							}
						}
						if err != unix.EAGAIN {
							t.Fatal(err)
						}
					}
				}
			}
			now := time.Now()
			var fallback, restored bytes.Buffer
			r := New(strings.Repeat("secret\n", 1000), "invalid-build", primary, &fallback, func() time.Time { return now })
			r.Ready(true)
			for range 1000 {
				r.Count(Malformed)
			}
			now = now.Add(time.Minute)
			r.Tick(now, func() int { return 0 })
			r.Logger().Error("state.failed", "reason", "write", "result", "stopped", "count", 1)
			lines := bytes.Split(bytes.TrimSpace(fallback.Bytes()), []byte("\n"))
			if len(lines) != 3 || r.sink.writeFailures.Load() != 6 {
				t.Fatalf("fallbacks %d, failed deliveries %d", len(lines), r.sink.writeFailures.Load())
			}
			for _, line := range lines {
				var e map[string]any
				if err := json.Unmarshal(line, &e); err != nil || e["audit_delivery"] != "unknown" || e["instance"] != "unknown" ||
					e["interface"] != "unknown" || e["build_sha"] != "unknown" || len(line)+1 > 2048 {
					t.Fatalf("invalid fallback %q (%v)", line, err)
				}
			}
			if !bytes.Contains(lines[2], []byte("state.failed")) {
				t.Fatal("terminal fallback suppressed")
			}
			r.sink.primary = &restored
			now = now.Add(time.Minute)
			r.Tick(now, func() int { return 0 })
			if !bytes.Contains(restored.Bytes(), []byte(`"delivery_failures":6`)) ||
				!bytes.Contains(restored.Bytes(), []byte(`"delivery_write_failures":6`)) ||
				!bytes.Contains(restored.Bytes(), []byte(`"protection":"degraded"`)) || r.sink.reportedWrites != 6 {
				t.Fatalf("failed delivery accounting after recovery: %s", &restored)
			}
		})
	}
}
