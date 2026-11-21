package store

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4"

	"dhcpv4-served/internal/events"
	"dhcpv4-served/internal/lease"
	"dhcpv4-served/internal/server"
)

var errFault = errors.New("injected I/O failure")

type faultFile struct {
	snapshotFile
	stage string
}

func (f faultFile) Write(b []byte) (int, error) {
	switch f.stage {
	case "write":
		return 0, errFault
	case "short-write":
		return len(b) / 2, nil
	}
	return f.snapshotFile.Write(b)
}

func (f faultFile) Sync() error {
	if f.stage == "file-sync" || f.stage == "directory-sync" {
		return errFault
	}
	return f.snapshotFile.Sync()
}

func (f faultFile) Close() error {
	err := f.snapshotFile.Close()
	if f.stage == "close" {
		return errFault
	}
	return err
}

func TestSnapshotFaultSuppressesACKAndReservesRecovery(t *testing.T) {
	for _, mode := range []string{"grant", "renewal"} {
		for _, stage := range []string{"temp-create", "write", "short-write", "file-sync", "close", "rename", "directory-sync"} {
			t.Run(mode+"/"+stage, func(t *testing.T) {
				dir := t.TempDir()
				if err := os.Chmod(dir, 0700); err != nil {
					t.Fatal(err)
				}
				db, recovered, err := OpenSnapshot(dir, "test", "network")
				if err != nil {
					t.Fatal(err)
				}
				addr := netip.MustParseAddr("192.0.2.10")
				cfg := lease.Config{
					Instance:        "test",
					Start:           addr,
					End:             addr,
					OfferDuration:   time.Minute,
					LeaseDuration:   time.Hour,
					DeclineDuration: time.Minute,
				}
				var logs bytes.Buffer
				audit := events.New("test", "", &logs, io.Discard, time.Now)
				engine, err := lease.New(db, audit.Logger(), time.Now, cfg, recovered)
				if err != nil {
					t.Fatal(err)
				}
				h := server.New(engine, time.Now, server.Config{
					Server:        netip.MustParseAddr("192.0.2.1"),
					Subnet:        netip.MustParsePrefix("192.0.2.0/24"),
					LeaseDuration: time.Hour,
				})
				packet := func(kind dhcpv4.MessageType) *dhcpv4.DHCPv4 {
					p, e := dhcpv4.New(
						dhcpv4.WithHwAddr(net.HardwareAddr{2, 0, 0, 0, 0, 1}),
						dhcpv4.WithMessageType(kind),
						dhcpv4.WithGeneric(dhcpv4.OptionClientIdentifier, []byte("owner")),
					)
					if e != nil {
						t.Fatal(e)
					}
					return p
				}
				discover := packet(dhcpv4.MessageTypeDiscover)
				offer, err := h.Reply(discover.ToBytes())
				if err != nil || offer == nil {
					t.Fatalf("offer: %v", err)
				}
				req := packet(dhcpv4.MessageTypeRequest)
				req.TransactionID = discover.TransactionID
				req.UpdateOption(dhcpv4.OptRequestedIPAddress(net.IP(addr.AsSlice())))
				req.UpdateOption(dhcpv4.OptServerIdentifier(net.ParseIP("192.0.2.1")))
				if mode == "renewal" {
					ack, err := h.Reply(req.ToBytes())
					if err != nil || ack == nil {
						t.Fatalf("initial grant: %v", err)
					}
				}
				ops := defaultSnapshotOps()
				db.ops.createTemp = func(dir, pattern string) (snapshotFile, error) {
					if stage == "temp-create" {
						return nil, errFault
					}
					f, err := ops.createTemp(dir, pattern)
					if err != nil {
						return nil, err
					}
					fileStage := stage
					if fileStage == "directory-sync" {
						fileStage = ""
					}
					return faultFile{f, fileStage}, nil
				}
				db.ops.rename = func(a, b string) error {
					if stage == "rename" {
						return errFault
					}
					return ops.rename(a, b)
				}
				db.ops.openDir = func(dir string) (snapshotFile, error) {
					f, err := ops.openDir(dir)
					if err != nil {
						return nil, err
					}
					return faultFile{f, stage}, nil
				}
				request := req
				if mode == "renewal" {
					request = packet(dhcpv4.MessageTypeRequest)
					request.ClientIPAddr = net.IP(addr.AsSlice())
				}
				reply, err := h.Reply(request.ToBytes())
				if reply != nil || !errors.Is(err, lease.ErrStorage) {
					t.Fatalf("failed renewal: %v %v", reply, err)
				}
				cause := errFault
				if stage == "short-write" {
					cause = io.ErrShortWrite
				}
				if !errors.Is(err, cause) {
					t.Fatalf("storage failure lost its cause %v: %v", cause, err)
				}
				db.ops = ops
				reply, err = h.Reply(request.ToBytes())
				if reply != nil || !errors.Is(err, lease.ErrStorage) {
					t.Fatalf("engine revived: %v %v", reply, err)
				}
				wantReason := "write"
				if stage == "file-sync" || stage == "directory-sync" {
					wantReason = "sync"
				}
				var event struct {
					ID             string `json:"event_id"`
					Reason, Result string
				}
				if err := json.Unmarshal(logs.Bytes(), &event); err != nil || event.ID != "state.failed" ||
					event.Reason != wantReason || event.Result != "stopped" || bytes.Contains(logs.Bytes(), []byte(errFault.Error())) {
					t.Fatalf("want one redacted terminal %s event, got %q", wantReason, logs.Bytes())
				}
				if err := db.Close(); err != nil {
					t.Fatal(err)
				}
				db, recovered, err = OpenSnapshot(dir, "test", "network")
				if err != nil {
					t.Fatal(err)
				}
				defer db.Close()
				engine, err = lease.New(db, slog.Default(), time.Now, cfg, recovered)
				if err != nil {
					t.Fatal(err)
				}
				_, err = engine.Offer("competitor", "other", 1, addr)
				if mode == "renewal" || stage == "directory-sync" {
					if !errors.Is(err, lease.ErrExhausted) {
						t.Fatalf("recovery reused reserved address: %v", err)
					}
				} else if err != nil {
					t.Fatalf("uncommitted offer remained reserved: %v", err)
				}
			})
		}
	}
}
