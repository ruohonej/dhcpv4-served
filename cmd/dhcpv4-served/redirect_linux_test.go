package main

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"golang.org/x/sys/unix"

	"dhcpv4-served/internal/events"
	"dhcpv4-served/internal/lease"
	"dhcpv4-served/internal/server"
)

func TestWorkerWithBlockedOrBrokenOutput(t *testing.T) {
	for _, fault := range []string{"blocked stderr", "closed stderr", "blocked stdout fallback"} {
		t.Run(fault, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestRedirectedWorkerChild$")
			cmd.Env = append(os.Environ(), "DHCP_TEST_REDIRECT="+fault)
			cmd.Stderr = workerTestPipe(t, fault != "blocked stderr")
			if fault == "blocked stdout fallback" {
				cmd.Stdout = workerTestPipe(t, false)
			} else {
				output, err := os.CreateTemp(t.TempDir(), "worker-*.log")
				if err != nil {
					t.Fatal(err)
				}
				defer output.Close()
				cmd.Stdout = output
			}
			if err := cmd.Run(); err != nil {
				t.Fatalf("worker should send a reply and exit even with %s: %v", fault, err)
			}
			if fault != "blocked stdout fallback" {
				output := cmd.Stdout.(*os.File)
				logs, err := os.ReadFile(output.Name())
				if err != nil || !strings.Contains(string(logs), `"audit_delivery":"unknown"`) {
					t.Fatalf("expected the failure to reach the fallback output: %q, %v", logs, err)
				}
			}
		})
	}
}

// A full pipe keeps its reader open throughout the child run and never drains.
func workerTestPipe(t *testing.T, closeReader bool) *os.File {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { w.Close() })
	if closeReader {
		r.Close()
		return w
	}
	t.Cleanup(func() { r.Close() })
	fd := int(w.Fd())
	if err := unix.SetNonblock(fd, true); err != nil {
		t.Fatal(err)
	}
	for _, data := range [][]byte{make([]byte, 4096), {0}} {
		for {
			if _, err := unix.Write(fd, data); err != nil {
				if err != unix.EAGAIN {
					t.Fatal(err)
				}
				break
			}
		}
	}
	if err := unix.SetNonblock(fd, false); err != nil {
		t.Fatal(err)
	}
	return w
}

func TestRedirectedWorkerChild(t *testing.T) {
	fault := os.Getenv("DHCP_TEST_REDIRECT")
	if fault == "" {
		return
	}
	// The testing harness prints PASS to stdout after this test. Exit here
	// so only the production recorder writes to the inherited test pipes.
	if redirectedWorkerReply(fault) != nil {
		os.Exit(1)
	}
	os.Exit(0)
}

func redirectedWorkerReply(fault string) error {
	audit := events.NewWorker("lan10", "", os.Stderr, os.Stdout, time.Now)
	defer audit.Close()
	ip := netip.MustParseAddr
	engine, err := lease.New(&idleStore{}, audit.Logger(), time.Now, lease.Config{
		Instance: "lan10", Start: ip("192.0.2.10"), End: ip("192.0.2.11"),
		OfferDuration: time.Minute, LeaseDuration: time.Hour, DeclineDuration: time.Minute,
	}, nil)
	if err != nil {
		return err
	}
	handler := server.New(engine, time.Now, server.Config{
		OnReject: audit.Count, Server: ip("192.0.2.1"),
		Subnet: netip.MustParsePrefix("192.0.2.0/24"), LeaseDuration: time.Hour,
	})
	packet, err := dhcpv4.New(dhcpv4.WithHwAddr(net.HardwareAddr{2, 0, 0, 0, 0, 1}),
		dhcpv4.WithMessageType(dhcpv4.MessageTypeDiscover))
	if err != nil {
		return err
	}
	client, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(netip.MustParseAddrPort("127.0.0.1:0")))
	if err != nil {
		return err
	}
	defer client.Close()
	sender, err := net.DialUDP("udp4", nil, client.LocalAddr().(*net.UDPAddr))
	if err != nil {
		return err
	}
	defer sender.Close()

	audit.Ready(false)
	// Force queue overflow with synthetic events, without waiting for the
	// production minute cadence. A ready event alone could only test enqueue.
	if fault == "blocked stderr" {
		for range 64 {
			audit.Logger().Info("test.event", "reason", "fixture", "result", "test", "count", 1)
		}
	}
	if err := processPacket(handler, audit, packet.ToBytes(), func(response *server.Response) error {
		_, err := sender.Write(response.Packet)
		return err
	}); err != nil {
		return err
	}
	if err := client.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		return err
	}
	buf := make([]byte, 1500)
	n, err := client.Read(buf)
	if err != nil {
		return err
	}
	reply, err := dhcpv4.FromBytes(buf[:n])
	if err != nil {
		return err
	}
	if reply.MessageType() != dhcpv4.MessageTypeOffer {
		return fmt.Errorf("expected DHCPOFFER, got %s", reply.MessageType())
	}
	return nil
}
