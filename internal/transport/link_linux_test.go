package transport

import (
	"encoding/binary"
	"net/netip"
	"testing"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

func TestNetlinkDiscoveryDecoding(t *testing.T) {
	h := make([]byte, 16)
	binary.NativeEndian.PutUint16(h[2:], unix.ARPHRD_ETHER)
	binary.NativeEndian.PutUint32(h[4:], 10)
	binary.NativeEndian.PutUint32(h[8:], unix.IFF_UP)
	a, err := netlink.MarshalAttributes([]netlink.Attribute{
		{Type: unix.IFLA_IFNAME, Data: []byte("lan10\x00")},
		{Type: unix.IFLA_ADDRESS, Data: []byte{2, 0, 0, 0, 0, 1}},
	})
	if err != nil {
		t.Fatal(err)
	}
	l, up, err := decodeLink(append(h, a...))
	if err != nil || !up || l.Name != "lan10" || l.Index != 10 || len(l.MAC) != 6 {
		t.Fatalf("link=%+v up=%v err=%v", l, up, err)
	}
	h = make([]byte, 8)
	h[0] = unix.AF_INET
	h[1] = 24
	binary.NativeEndian.PutUint32(h[4:], 10)
	a, err = netlink.MarshalAttributes([]netlink.Attribute{{Type: unix.IFA_LOCAL, Data: []byte{192, 168, 10, 1}}})
	if err != nil {
		t.Fatal(err)
	}
	ip, subnet, index, err := decodeAddress(append(h, a...))
	if err != nil || ip != netip.MustParseAddr("192.168.10.1") || subnet != netip.MustParsePrefix("192.168.10.0/24") || index != 10 {
		t.Fatalf("ip=%s subnet=%s index=%d err=%v", ip, subnet, index, err)
	}
	if _, _, err := decodeLink(h[:3]); err == nil {
		t.Fatal("accepted truncated link message")
	}
	if _, _, _, err := decodeAddress(h[:3]); err == nil {
		t.Fatal("accepted truncated address message")
	}
	h[1] = 33
	if _, _, _, err := decodeAddress(append(h, a...)); err == nil {
		t.Fatal("accepted invalid prefix")
	}
}

func TestMonitorRejectsReplacementAndLostEvents(t *testing.T) {
	event := func(typ netlink.HeaderType, index int) netlink.Message {
		data := make([]byte, 16)
		binary.NativeEndian.PutUint32(data[4:], uint32(index))
		return netlink.Message{Header: netlink.Header{Type: typ}, Data: data}
	}
	for name, msgs := range map[string][]netlink.Message{
		"rapid-replacement":              {event(unix.RTM_DELLINK, 10), event(unix.RTM_NEWLINK, 11)},
		"index-reuse-identical-snapshot": {event(unix.RTM_DELLINK, 10), event(unix.RTM_NEWLINK, 10)},
		"address-replaced":               {event(unix.RTM_DELADDR, 10), event(unix.RTM_NEWADDR, 10)},
		"overrun":                        {{Header: netlink.Header{Type: unix.NLMSG_OVERRUN}}},
		"truncated":                      {{Header: netlink.Header{Type: unix.RTM_NEWLINK}}},
		"unexpected":                     {{Header: netlink.Header{Type: 999}}},
	} {
		t.Run(name, func(t *testing.T) {
			if err := checkLinkEvents(msgs, 10); err == nil {
				t.Fatal("accepted invalid monitor history")
			}
		})
	}
	if err := checkLinkEvents([]netlink.Message{event(unix.RTM_NEWLINK, 20)}, 10); err != nil {
		t.Fatal(err)
	}
}
