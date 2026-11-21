// Package transport handles inherited UDP traffic and replies to a validated Linux link.
package transport

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"time"

	"golang.org/x/net/ipv4"
	"golang.org/x/sys/unix"
)

// ErrInvalidPacket identifies datagrams rejected before DHCP processing.
var ErrInvalidPacket = errors.New("invalid DHCP datagram")

// ErrLink identifies a serving-time change in the validated link identity.
var ErrLink = errors.New("invalid serving link")

var ErrSourcePort = fmt.Errorf("%w: unexpected DHCP source port", ErrInvalidPacket)

// Conn pairs an activated UDP socket with its validated interface identity.
type Conn struct {
	udp    *net.UDPConn
	packet *ipv4.PacketConn
	link   Link
}

// New wraps the activated UDP socket; it does not create a listener.
func New(udp *net.UDPConn, link Link) *Conn {
	if udp == nil {
		panic("transport: UDP socket is required")
	}
	link.MAC = slices.Clone(link.MAC)
	return &Conn{
		udp:    udp,
		packet: ipv4.NewPacketConn(udp),
		link:   link,
	}
}

func (c *Conn) Read(buf []byte) (int, error) {
	oob := make([]byte, unix.CmsgSpace(unix.SizeofInet4Pktinfo))
	n, oobSize, flags, sender, err := c.udp.ReadMsgUDP(buf, oob)
	if err != nil {
		return 0, fmt.Errorf("read UDP datagram: %w", err)
	}
	if sender.Port != 68 {
		return 0, ErrSourcePort
	}
	if err := CheckMetadata(oob[:oobSize], flags, c.link.Index); err != nil {
		return 0, fmt.Errorf("check packet metadata: %w", err)
	}
	if err := c.link.Validate(); err != nil {
		return 0, fmt.Errorf("validate ingress link: %w: %w", ErrLink, err)
	}
	return n, nil
}

// CheckMetadata requires one intact packet-info record for the expected interface.
func CheckMetadata(oob []byte, flags, index int) error {
	if flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 {
		return fmt.Errorf("%w: truncated packet or metadata", ErrInvalidPacket)
	}
	messages, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		return fmt.Errorf("%w: parse packet metadata: %w", ErrInvalidPacket, err)
	}

	count := 0
	for _, message := range messages {
		if message.Header.Level != unix.IPPROTO_IP || message.Header.Type != unix.IP_PKTINFO {
			continue
		}
		if len(message.Data) != unix.SizeofInet4Pktinfo || int(binary.NativeEndian.Uint32(message.Data[:4])) != index {
			return fmt.Errorf("%w: wrong ingress interface or invalid packet metadata", ErrInvalidPacket)
		}
		count++
	}
	if count != 1 {
		return fmt.Errorf("%w: require exactly one ingress interface metadata record", ErrInvalidPacket)
	}
	return nil
}

// Send selects the configured link and source address on the activated socket.
func (c *Conn) Send(data []byte, dst netip.Addr) error {
	if err := c.link.Validate(); err != nil {
		return fmt.Errorf("validate reply link: %w: %w", ErrLink, err)
	}
	if err := c.udp.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
		return fmt.Errorf("set reply deadline: %w", err)
	}
	metadata := &ipv4.ControlMessage{
		IfIndex: c.link.Index,
		Src:     net.IP(c.link.IP.AsSlice()),
	}
	destination := &net.UDPAddr{
		IP:   net.IP(dst.AsSlice()),
		Port: 68,
	}
	n, err := c.packet.WriteTo(data, metadata, destination)
	if err != nil {
		return fmt.Errorf("write UDP reply: %w", err)
	}
	if n != len(data) {
		return fmt.Errorf("short UDP write")
	}
	return nil
}
