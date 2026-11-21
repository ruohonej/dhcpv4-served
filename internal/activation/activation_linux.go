// Package activation adopts the single systemd-provided DHCP socket.
package activation

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"

	"golang.org/x/sys/unix"
)

var ErrDevice = errors.New("socket device mismatch")

// Adopt takes ownership of fd 3. It never opens a replacement listener.
func Adopt(device string) (*net.UDPConn, error) {
	pid, err := strconv.Atoi(os.Getenv("LISTEN_PID"))
	if err != nil || pid != os.Getpid() || os.Getenv("LISTEN_FDS") != "1" || os.Getenv("LISTEN_FDNAMES") != "dhcp" {
		return nil, fmt.Errorf("require exactly one activated socket named dhcp for this PID")
	}
	for _, key := range []string{"LISTEN_PID", "LISTEN_FDS", "LISTEN_FDNAMES"} {
		if err := os.Unsetenv(key); err != nil {
			return nil, fmt.Errorf("clear activation environment: %w", err)
		}
	}

	// systemd passes activated descriptors starting at fd 3.
	file := os.NewFile(3, "dhcp")
	if file == nil {
		return nil, fmt.Errorf("missing fd 3")
	}
	defer func() { _ = file.Close() }()
	unix.CloseOnExec(3)

	socketType, err := unix.GetsockoptInt(3, unix.SOL_SOCKET, unix.SO_TYPE)
	if err != nil || socketType != unix.SOCK_DGRAM {
		return nil, fmt.Errorf("fd 3 must be a datagram socket: %v", err)
	}

	socketAddr, err := unix.Getsockname(3)
	addr, ok := socketAddr.(*unix.SockaddrInet4)
	if err != nil || !ok || addr.Port != 67 || addr.Addr != [4]byte{} {
		return nil, fmt.Errorf("fd 3 must be an IPv4 wildcard UDP port 67 socket")
	}

	protocol, err := unix.GetsockoptInt(3, unix.SOL_SOCKET, unix.SO_PROTOCOL)
	if err != nil || protocol != unix.IPPROTO_UDP {
		return nil, fmt.Errorf("fd 3 must use UDP")
	}

	boundDevice, err := unix.GetsockoptString(3, unix.SOL_SOCKET, unix.SO_BINDTODEVICE)
	if err != nil || boundDevice != device {
		return nil, fmt.Errorf("%w: socket device %q does not match %q: %v", ErrDevice, boundDevice, device, err)
	}

	broadcast, err := unix.GetsockoptInt(3, unix.SOL_SOCKET, unix.SO_BROADCAST)
	if err != nil || broadcast != 1 {
		return nil, fmt.Errorf("socket must have broadcast enabled")
	}

	if _, err := unix.Getpeername(3); err == nil {
		return nil, fmt.Errorf("activated socket must not be connected")
	}
	if err := unix.SetsockoptInt(3, unix.IPPROTO_IP, unix.IP_PKTINFO, 1); err != nil {
		return nil, fmt.Errorf("enable packet metadata: %w", err)
	}

	// FilePacketConn duplicates fd; the deferred Close releases the original.
	conn, err := net.FilePacketConn(file)
	if err != nil {
		return nil, err
	}
	udp, ok := conn.(*net.UDPConn)
	if !ok {
		return nil, errors.Join(fmt.Errorf("activated socket is not UDP"), conn.Close())
	}
	return udp, nil
}
