package config

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const valid = `pool:
  start: 192.168.10.100
  end: 192.168.10.200
excluded_addresses: [192.168.10.101]
router: 192.168.10.1
dns_servers: [192.168.10.1]
lease_duration: 12h
offer_duration: 60s
decline_duration: 10m
authoritative: false
`

func TestLoad(t *testing.T) {
	cases := []struct {
		name, body string
		ok         bool
	}{
		{"valid", valid, true},
		{"unknown", valid + "unknown: value\n", false},
		{"duplicate", valid + "router: 192.168.10.2\n", false},
		{"multiple documents", valid + "---\nid: other\n", false},
		{"removed server setting", valid + "server_ip: 192.168.10.1\n", false},
		{"removed interface setting", valid + "interface: lan10\n", false},
		{"removed subnet setting", valid + "subnet: 192.168.10.0/24\n", false},
		{"removed state setting", valid + "lease_file: /var/lib/leases.json\n", false},
		{"removed id setting", valid + "id: lan10\n", false},
		{"bad pool", strings.Replace(valid, "192.168.10.200", "192.168.10.1", 1), false},
		{"bad duration", strings.Replace(valid, "12h", "0s", 1), false},
		{"duplicate excluded", strings.Replace(valid, "[192.168.10.101]", "[192.168.10.101, 192.168.10.101]", 1), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "test.yaml")
			if err := os.WriteFile(p, []byte(tc.body), 0600); err != nil {
				t.Fatal(err)
			}
			_, err := Load(p)
			if (err == nil) != tc.ok {
				t.Fatalf("error %v", err)
			}
		})
	}
}

func TestValidateMultiple(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config")
	os.WriteFile(p, []byte(valid), 0600)
	c, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateMultiple([]Config{c, c}); err == nil {
		t.Fatal("accepted duplicate instances")
	}
}

func TestValidateLink(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config")
	if err := os.WriteFile(p, []byte(valid), 0600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	server := netip.MustParseAddr("192.168.10.1")
	if err := c.ValidateLink(server, netip.MustParsePrefix("192.168.10.0/24")); err != nil {
		t.Fatal(err)
	}
	for _, prefix := range []string{"192.168.11.0/24", "192.168.10.0/25", "192.168.10.0/31"} {
		if err := c.ValidateLink(server, netip.MustParsePrefix(prefix)); err == nil {
			t.Fatalf("accepted incompatible link %s", prefix)
		}
	}
	c.Router = netip.MustParseAddr("192.168.11.1")
	if err := c.ValidateLink(server, netip.MustParsePrefix("192.168.10.0/24")); err == nil {
		t.Fatal("accepted off-subnet router")
	}
}
