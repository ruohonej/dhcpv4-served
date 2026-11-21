// Package hostservices snapshots systemd's upstream servers before sandboxing.
package hostservices

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/varlink/go/v2/varlink"
	"golang.org/x/sys/unix"
)

const resolveSocket = "/run/systemd/resolve/io.systemd.Resolve"
const maxReplySize = 1 << 20

type dnsServer struct {
	Family  int   `json:"family"`
	Address []int `json:"address"`
	Port    int   `json:"port"`
}

type dnsReply struct {
	Configuration []struct {
		IfIndex      int    `json:"ifindex"`
		Delegate     string `json:"delegate"`
		DefaultRoute *bool  `json:"defaultRoute"`
		DNSOverTLS   string `json:"dnsOverTLS"`
		Scopes       []struct {
			DNSOverTLS string `json:"dnsOverTLS"`
		} `json:"scopes"`
		Servers []dnsServer `json:"servers"`
	} `json:"configuration"`
}

// Discover queries resolved's Varlink socket before sandboxing.
func Discover() []netip.Addr {
	dns, _ := discoverDNS(resolveSocket)
	return dns
}

func discoverDNS(socket string) ([]netip.Addr, error) {
	conn, err := net.DialTimeout("unix", socket, time.Second)
	if err != nil {
		return nil, err
	}
	client := varlink.NewClient(conn, varlink.ClientConfig{MaxFrameSize: maxReplySize - 1})
	defer func() { _ = client.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	var reply dnsReply
	if err := client.Invoke(ctx, "io.systemd.Resolve.DumpDNSConfiguration", struct{}{}, &reply); err != nil {
		return nil, fmt.Errorf("query resolved over varlink: %w", err)
	}
	var servers []dnsServer
	for _, config := range reply.Configuration {
		// A missing defaultRoute is valid for the global scope. For a link or
		// delegate it is ambiguous, so do not advertise that scope.
		// DHCP option 6 cannot tell clients to use DNS-over-TLS. Delegates
		// can report the effective mode only in their nested scopes.
		strictTLS := config.DNSOverTLS == "yes"
		for _, scope := range config.Scopes {
			strictTLS = strictTLS || scope.DNSOverTLS == "yes"
		}
		if strictTLS {
			continue
		}
		if config.DefaultRoute != nil && !*config.DefaultRoute {
			continue
		}
		if config.DefaultRoute == nil && (config.IfIndex != 0 || config.Delegate != "") {
			continue
		}
		servers = append(servers, config.Servers...)
	}
	return addresses(servers), nil
}

func addresses(servers []dnsServer) []netip.Addr {
	var dns []netip.Addr
	seen := make(map[netip.Addr]bool)
	for _, s := range servers {
		// DHCP option 6 has no port field. Go's []byte JSON decoder accepts base64,
		// while Varlink encodes IPv4 addresses as arrays of integers.
		if s.Family != unix.AF_INET || len(s.Address) != 4 || (s.Port != 0 && s.Port != 53) {
			continue
		}
		var raw [4]byte
		valid := true
		for i, value := range s.Address {
			if value < 0 || value > 255 {
				valid = false
				break
			}
			raw[i] = byte(value)
		}
		if !valid {
			continue
		}
		addr := netip.AddrFrom4(raw)
		if !addr.IsGlobalUnicast() || addr.IsLinkLocalUnicast() || seen[addr] {
			continue
		}
		dns = append(dns, addr)
		seen[addr] = true
		if len(dns) == 63 {
			break
		}
	}
	return dns
}
