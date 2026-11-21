package hostservices

import (
	"bufio"
	"fmt"
	"net"
	"net/netip"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestAddresses(t *testing.T) {
	input := []dnsServer{
		{Family: unix.AF_INET, Address: []int{1, 1, 1, 1}},
		{Family: unix.AF_INET, Address: []int{1, 1, 1, 1}, Port: 53},
		{Family: unix.AF_INET, Address: []int{127, 0, 0, 53}},
		{Family: unix.AF_INET, Address: []int{169, 254, 1, 1}},
		{Family: unix.AF_INET, Address: []int{8, 8, 8, 8}, Port: 853},
		{Family: unix.AF_INET6, Address: make([]int, 16)},
		{Family: unix.AF_INET, Address: []int{1, 2, 3, 256}},
	}
	dns := addresses(input)
	if !reflect.DeepEqual(dns, []netip.Addr{netip.MustParseAddr("1.1.1.1")}) {
		t.Fatalf("dns %v", dns)
	}
}

func TestDiscoverDNSVarlink(t *testing.T) {
	for _, tc := range []struct {
		name, reply string
		want        []netip.Addr
		failure     bool
	}{
		{"configured", `{"parameters":{"configuration":[{"servers":[{"family":2,"address":[1,1,1,1],"port":53}]},{"servers":[{"family":2,"address":[8,8,8,8],"port":0}]}]}}`, []netip.Addr{netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("8.8.8.8")}, false},
		{"split DNS", `{"parameters":{"configuration":[{"servers":[{"family":2,"address":[1,1,1,1],"port":53}]},{"ifindex":5,"defaultRoute":false,"servers":[{"family":2,"address":[10,0,0,53],"port":53}]},{"ifindex":6,"defaultRoute":true,"servers":[{"family":2,"address":[8,8,8,8],"port":53}]},{"ifindex":7,"servers":[{"family":2,"address":[10,0,1,53],"port":53}]},{"delegate":"vpn","servers":[{"family":2,"address":[10,0,2,53],"port":53}]}]}}`, []netip.Addr{netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("8.8.8.8")}, false},
		{"strict TLS", `{"parameters":{"configuration":[{"dnsOverTLS":"yes","servers":[{"family":2,"address":[9,9,9,9],"port":53}]},{"ifindex":2,"defaultRoute":true,"dnsOverTLS":"yes","servers":[{"family":2,"address":[1,0,0,1],"port":53}]},{"delegate":"network","defaultRoute":true,"scopes":[{"dnsOverTLS":"yes"}],"servers":[{"family":2,"address":[10,0,0,53],"port":53}]},{"ifindex":3,"defaultRoute":true,"dnsOverTLS":"no","servers":[{"family":2,"address":[1,1,1,1],"port":53}]},{"ifindex":4,"defaultRoute":true,"dnsOverTLS":"opportunistic","servers":[{"family":2,"address":[8,8,8,8],"port":53}]}]}}`, []netip.Addr{netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("8.8.8.8")}, false},
		{"only strict TLS", `{"parameters":{"configuration":[{"dnsOverTLS":"yes","servers":[{"family":2,"address":[9,9,9,9],"port":53}]}]}}`, nil, false},
		{"empty", `{"parameters":{"configuration":[]}}`, nil, false},
		{"error", `{"error":"org.varlink.service.MethodNotFound"}`, nil, true},
		{"stream", `{"parameters":{},"continues":true}`, nil, true},
		{"malformed", `{`, nil, true},
		{"oversized", strings.Repeat(" ", maxReplySize+1), nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "resolve")
			listener, err := net.Listen("unix", path)
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			received := make(chan string, 1)
			go func() {
				c, e := listener.Accept()
				if e != nil {
					received <- "accept failed"
					return
				}
				defer c.Close()
				request, _ := bufio.NewReader(c).ReadString(0)
				received <- request
				_, _ = fmt.Fprint(c, tc.reply+"\x00")
			}()
			got, err := discoverDNS(path)
			if (err != nil) != tc.failure || !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got %v, err %v", got, err)
			}
			if request := <-received; request != "{\"method\":\"io.systemd.Resolve.DumpDNSConfiguration\",\"parameters\":{}}\x00" {
				t.Fatalf("request %q", request)
			}
		})
	}
}

func TestDiscoverDNSTimeout(t *testing.T) {
	path := filepath.Join(t.TempDir(), "resolve")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()
		reader := bufio.NewReader(conn)
		if _, err := reader.ReadString(0); err != nil {
			return
		}
		// Do not reply; wait for the timed-out client to close its connection.
		_, _ = reader.ReadByte()
	}()
	start := time.Now()
	_, err = discoverDNS(path)
	if err == nil {
		t.Fatal("lookup unexpectedly succeeded")
	}
	if elapsed := time.Since(start); elapsed > 4*time.Second {
		t.Fatalf("lookup took %v", elapsed)
	}
	<-done
}
