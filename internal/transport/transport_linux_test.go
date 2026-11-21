package transport

import (
	"encoding/binary"
	"errors"
	"net"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func pktinfo(index uint32) []byte {
	b := make([]byte, unix.CmsgSpace(unix.SizeofInet4Pktinfo))
	// Build the platform ABI header without depending on pointer casts.
	h := unix.Cmsghdr{Level: unix.IPPROTO_IP, Type: unix.IP_PKTINFO}
	h.SetLen(unix.CmsgLen(unix.SizeofInet4Pktinfo))
	if unix.SizeofCmsghdr == 16 {
		binary.NativeEndian.PutUint64(b, uint64(h.Len))
		binary.NativeEndian.PutUint32(b[8:], uint32(h.Level))
		binary.NativeEndian.PutUint32(b[12:], uint32(h.Type))
	} else {
		binary.NativeEndian.PutUint32(b, uint32(h.Len))
		binary.NativeEndian.PutUint32(b[4:], uint32(h.Level))
		binary.NativeEndian.PutUint32(b[8:], uint32(h.Type))
	}
	binary.NativeEndian.PutUint32(b[unix.CmsgLen(0):], index)
	return b
}

func TestMetadata(t *testing.T) {
	for _, tc := range []struct {
		name  string
		data  []byte
		flags int
		valid bool
	}{
		{"correct", pktinfo(10), 0, true},
		{"missing", nil, 0, false},
		{"wrong-interface", pktinfo(20), 0, false},
		{"truncated-packet", pktinfo(10), unix.MSG_TRUNC, false},
		{"truncated-control", pktinfo(10), unix.MSG_CTRUNC, false},
		{"duplicate", append(pktinfo(10), pktinfo(10)...), 0, false},
		{"short-control", []byte{1, 2, 3}, 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := CheckMetadata(tc.data, tc.flags, 10)
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v err=%v", tc.valid, err)
			}
			if !tc.valid && !errors.Is(err, ErrInvalidPacket) {
				t.Fatalf("expected invalid-packet sentinel, got %v", err)
			}
		})
	}
}

func TestNewRequiresSocket(t *testing.T) {
	defer func() {
		if got := recover(); got != "transport: UDP socket is required" {
			t.Fatalf("expected missing-socket panic, got %v", got)
		}
	}()
	New(nil, Link{})
}

func TestReadErrors(t *testing.T) {
	for _, tt := range []struct {
		name    string
		send    bool
		wantErr error
	}{
		{"timeout", false, os.ErrDeadlineExceeded},
		{"wrong source port", true, ErrInvalidPacket},
	} {
		t.Run(tt.name, func(t *testing.T) {
			udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			defer udp.Close()
			deadline := time.Now().Add(-time.Second)
			if tt.send {
				deadline = time.Now().Add(time.Second)
				if _, err := udp.WriteToUDP([]byte("invalid"), udp.LocalAddr().(*net.UDPAddr)); err != nil {
					t.Fatal(err)
				}
			}
			if err := udp.SetReadDeadline(deadline); err != nil {
				t.Fatal(err)
			}
			_, err = New(udp, Link{}).Read(make([]byte, 64))
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("expected %v, got %v", tt.wantErr, err)
			}
			if !tt.send {
				var netErr net.Error
				if !errors.As(err, &netErr) || !netErr.Timeout() {
					t.Fatalf("wrapped error lost network timeout: %v", err)
				}
			}
		})
	}
}

func TestLinkSnapshotsCannotBeRetargeted(t *testing.T) {
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	monitor := &Monitor{link: Link{Name: "original", MAC: net.HardwareAddr{2, 0, 0, 0, 0, 1}}}
	link := monitor.Link()
	conn := New(udp, link)
	link.Name = "replacement"
	link.MAC[0] = 4
	if monitor.Link().Name != "original" || monitor.Link().MAC[0] != 2 ||
		conn.link.Name != "original" || conn.link.MAC[0] != 2 {
		t.Fatal("caller mutation retargeted an established link identity")
	}
}
