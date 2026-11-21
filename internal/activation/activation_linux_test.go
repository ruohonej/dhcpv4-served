package activation

import (
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestActivationChild(t *testing.T) {
	if os.Getenv("ACTIVATION_CHILD") != "1" {
		return
	}
	os.Setenv("LISTEN_PID", strconv.Itoa(os.Getpid()))
	if os.Getenv("BAD_PID") == "1" {
		os.Setenv("LISTEN_PID", "0")
	}
	c, err := Adopt("lo")
	if c != nil {
		c.Close()
	}
	if err == nil || !strings.Contains(err.Error(), os.Getenv("EXPECTED_ERROR")) {
		t.Fatalf("unexpected activation result: %v", err)
	}
}

func TestRejectActivation(t *testing.T) {
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero})
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	u, err := udp.File()
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	a, b := os.NewFile(uintptr(pair[0]), "unix"), os.NewFile(uintptr(pair[1]), "unix-peer")
	defer a.Close()
	defer b.Close()
	tcp, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4zero})
	if err != nil {
		t.Fatal(err)
	}
	defer tcp.Close()
	tf, err := tcp.File()
	if err != nil {
		t.Fatal(err)
	}
	defer tf.Close()
	for _, tc := range []struct {
		name                       string
		file                       *os.File
		count, names, badpid, want string
	}{
		{"wrong-pid", u, "1", "dhcp", "1", "exactly one"},
		{"extra-descriptors", u, "2", "dhcp", "0", "exactly one"},
		{"wrong-name", u, "1", "wrong", "0", "exactly one"},
		{"wrong-port", u, "1", "dhcp", "0", "IPv4 wildcard UDP port 67"},
		{"wrong-family", a, "1", "dhcp", "0", "IPv4 wildcard UDP port 67"},
		{"wrong-type", tf, "1", "dhcp", "0", "datagram socket"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmd := exec.Command(os.Args[0], "-test.run=^TestActivationChild$")
			cmd.Env = append(
				os.Environ(),
				"ACTIVATION_CHILD=1",
				"LISTEN_FDS="+tc.count,
				"LISTEN_FDNAMES="+tc.names,
				"BAD_PID="+tc.badpid,
				"EXPECTED_ERROR="+tc.want,
			)
			cmd.ExtraFiles = []*os.File{tc.file}
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("%v: %s", err, out)
			}
		})
	}
}
