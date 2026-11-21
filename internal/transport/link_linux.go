package transport

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// Link captures the interface identity that must remain stable while serving.
type Link struct {
	Name   string
	Index  int
	IP     netip.Addr
	Subnet netip.Prefix
	MAC    net.HardwareAddr
}

var ErrAddressCount = errors.New("require exactly one IPv4 address")

// Discover obtains the server IP, subnet and Ethernet identity using route
// netlink. Ambiguous multi-address links fail closed rather than choosing an IP.
func Discover(name string) (Link, error) {
	conn, err := netlink.Dial(unix.NETLINK_ROUTE, nil)
	if err != nil {
		return Link{}, err
	}
	defer func() { _ = conn.Close() }()
	if err := conn.SetDeadline(time.Now().Add(time.Second)); err != nil {
		return Link{}, err
	}

	messages, err := conn.Execute(netlink.Message{
		Header: netlink.Header{
			Type:  unix.RTM_GETLINK,
			Flags: netlink.Request | netlink.Dump,
		},
		Data: make([]byte, 16), // Empty ifinfomsg requests all links.
	})
	if err != nil {
		return Link{}, err
	}
	link := Link{Name: name}
	for _, message := range messages {
		if message.Header.Type != unix.RTM_NEWLINK {
			continue
		}
		candidate, up, err := decodeLink(message.Data)
		if err != nil {
			return Link{}, err
		}
		if candidate.Name != name {
			continue
		}
		if !up || len(candidate.MAC) != 6 {
			return Link{}, fmt.Errorf("require an up Ethernet link: %s", name)
		}
		link = candidate
		break
	}
	if link.Index == 0 {
		return Link{}, fmt.Errorf("interface %q not found", name)
	}

	data := make([]byte, 8) // ifaddrmsg selects IPv4 addresses.
	data[0] = unix.AF_INET
	messages, err = conn.Execute(netlink.Message{
		Header: netlink.Header{
			Type:  unix.RTM_GETADDR,
			Flags: netlink.Request | netlink.Dump,
		},
		Data: data,
	})
	if err != nil {
		return Link{}, err
	}

	count := 0
	for _, message := range messages {
		if message.Header.Type != unix.RTM_NEWADDR {
			continue
		}
		ip, subnet, index, err := decodeAddress(message.Data)
		if err != nil {
			return Link{}, err
		}
		if index != link.Index || !ip.IsValid() {
			continue
		}
		link.IP = ip
		link.Subnet = subnet
		count++
	}
	if count != 1 {
		return Link{}, fmt.Errorf("%w on %s, got %d", ErrAddressCount, name, count)
	}
	return link, nil
}

func decodeLink(data []byte) (Link, bool, error) {
	if len(data) < 16 {
		return Link{}, false, fmt.Errorf("short netlink link message")
	}
	link := Link{Index: int(binary.NativeEndian.Uint32(data[4:8]))}
	attributes, err := netlink.UnmarshalAttributes(data[16:])
	if err != nil {
		return link, false, err
	}
	for _, attr := range attributes {
		switch attr.Type {
		case unix.IFLA_IFNAME:
			link.Name = strings.TrimRight(string(attr.Data), "\x00")
		case unix.IFLA_ADDRESS:
			link.MAC = append(net.HardwareAddr(nil), attr.Data...)
		}
	}
	flags := binary.NativeEndian.Uint32(data[8:12])       // #nosec G602 -- length checked above
	hardwareType := binary.NativeEndian.Uint16(data[2:4]) // #nosec G602 -- length checked above
	upEthernet := flags&unix.IFF_UP != 0 && hardwareType == unix.ARPHRD_ETHER
	return link, upEthernet, nil
}

func decodeAddress(data []byte) (netip.Addr, netip.Prefix, int, error) {
	if len(data) < 8 {
		return netip.Addr{}, netip.Prefix{}, 0, fmt.Errorf("short netlink address message")
	}
	index := int(binary.NativeEndian.Uint32(data[4:8]))
	if data[0] != unix.AF_INET {
		return netip.Addr{}, netip.Prefix{}, index, nil
	}
	attributes, err := netlink.UnmarshalAttributes(data[8:])
	if err != nil {
		return netip.Addr{}, netip.Prefix{}, index, err
	}
	var ip netip.Addr
	for _, attr := range attributes {
		if attr.Type != unix.IFA_LOCAL {
			continue
		}
		if len(attr.Data) != 4 {
			return ip, netip.Prefix{}, index, fmt.Errorf("invalid IPv4 address attribute")
		}
		ip = netip.AddrFrom4([4]byte(attr.Data))
	}
	if !ip.IsValid() || data[1] > 32 {
		return ip, netip.Prefix{}, index, fmt.Errorf("invalid IPv4 address/prefix")
	}
	return ip, netip.PrefixFrom(ip, int(data[1])).Masked(), index, nil
}

func (link Link) Validate() error {
	current, err := Discover(link.Name)
	if err != nil {
		return err
	}
	if current.Index != link.Index || current.IP != link.IP || current.Subnet != link.Subnet {
		return fmt.Errorf("link identity/address changed on %s", link.Name)
	}
	if !bytes.Equal(current.MAC, link.MAC) {
		return fmt.Errorf("link identity/address changed on %s", link.Name)
	}
	return nil
}

// Monitor owns the subscription and the exact snapshot used by transport.
// Checks drain queued events synchronously: a replacement with identical attributes
// must still terminate this worker, even before an asynchronous watcher could run.
type Monitor struct {
	link Link
	conn *netlink.Conn
}

func OpenMonitor(name string) (*Monitor, error) {
	// Subscribe before discovery so changes during the snapshot cannot be missed.
	conn, err := netlink.Dial(unix.NETLINK_ROUTE, &netlink.Config{
		Groups: unix.RTMGRP_LINK | unix.RTMGRP_IPV4_IFADDR,
	})
	if err != nil {
		return nil, err
	}
	link, err := Discover(name)
	if err != nil {
		return nil, errors.Join(err, conn.Close())
	}
	monitor := &Monitor{
		link: link,
		conn: conn,
	}
	if err := monitor.Check(); err != nil {
		return nil, errors.Join(err, conn.Close())
	}
	return monitor, nil
}

func (m *Monitor) Close() error {
	return m.conn.Close()
}

// Link returns a copy of the original identity used for every monitor check.
func (m *Monitor) Link() Link {
	link := m.link
	link.MAC = slices.Clone(link.MAC)
	return link
}

// Check fails closed on receive errors (including ENOBUFS), overrun, malformed
// events, or any event for the original index. Never enable NETLINK_NO_ENOBUFS.
// A timeout only marks the end of the current queue; revalidate the snapshot too.
func (m *Monitor) Check() error {
	for {
		if err := m.conn.SetReadDeadline(time.Now().Add(time.Millisecond)); err != nil {
			return err
		}
		messages, err := m.conn.Receive()
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				return m.link.Validate()
			}
			return err
		}
		if err := checkLinkEvents(messages, m.link.Index); err != nil {
			return err
		}
	}
}

func checkLinkEvents(messages []netlink.Message, originalIndex int) error {
	for _, message := range messages {
		var index int
		switch message.Header.Type {
		case unix.RTM_NEWLINK, unix.RTM_DELLINK:
			if len(message.Data) < 16 {
				return fmt.Errorf("short link event")
			}
			index = int(binary.NativeEndian.Uint32(message.Data[4:8]))
		case unix.RTM_NEWADDR, unix.RTM_DELADDR:
			if len(message.Data) < 8 {
				return fmt.Errorf("short address event")
			}
			index = int(binary.NativeEndian.Uint32(message.Data[4:8]))
		case unix.NLMSG_OVERRUN:
			return fmt.Errorf("link monitor lost events")
		default:
			return fmt.Errorf("unexpected link monitor message %d", message.Header.Type)
		}
		if index == originalIndex {
			return fmt.Errorf("link/address changed; restart required")
		}
	}
	return nil
}
