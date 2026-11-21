package config

import (
	"encoding/hex"
	"net/netip"
	"testing"

	"gopkg.in/yaml.v3"
)

func parseNode(t *testing.T, s string) yaml.Node {
	t.Helper()
	var n yaml.Node
	if err := yaml.Unmarshal([]byte(s), &n); err != nil {
		t.Fatal(err)
	}
	return *n.Content[0]
}

func TestEachOptionEncoding(t *testing.T) {
	samples := map[string]string{
		"bool":      "true",
		"u8":        "42",
		"u16":       "1024",
		"u32":       "3600",
		"i32":       "-3600",
		"node":      "8",
		"text":      "example.test",
		"hex":       "010203",
		"ip":        "192.0.2.1",
		"ips":       "[192.0.2.1, 192.0.2.2]",
		"ips_empty": "[]",
		"pairs":     "[[192.0.2.0, 255.255.255.0]]",
		"routes":    "[[192.0.2.0, 192.0.2.1]]",
		"plateaus":  "[68, 576, 1500]",
	}
	seen := map[byte]string{}
	for name, spec := range optionSpecs {
		t.Run(name, func(t *testing.T) {
			if previous, exists := seen[spec.code]; exists {
				t.Fatalf("duplicate code with %s", previous)
			}
			seen[spec.code] = name
			sample, ok := samples[spec.kind]
			if !ok {
				t.Fatal("missing kind", spec.kind)
			}
			if _, err := encodeOption(spec, parseNode(t, sample)); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestOptionValidationAndEncoding(t *testing.T) {
	tests := []struct {
		name, value, want string
		ok                bool
	}{
		{"time_offset", "-3600", "fffff1f0", true},
		{"routers", "[192.0.2.1, 192.0.2.2]", "c0000201c0000202", true},
		{"ip_forwarding", "false", "00", true},
		{"ip_forwarding", "null", "", false},
		{"policy_filters", "[[192.0.2.0, 255.255.255.0]]", "c0000200ffffff00", true},
		{"netbios_node_type", "3", "", false},
		{"default_ip_ttl", "0", "", false},
		{"interface_mtu", "67", "", false},
		{"path_mtu_plateau_table", "[1500, 576]", "", false},
		{"static_routes", "[[0.0.0.0, 192.0.2.1]]", "", false},
		{"domain_name", "\"\"", "", false},
		{"vendor_specific_information", "nothex", "", false},
		{"time_servers", "[]", "", false},
		{"mobile_ip_home_agents", "[]", "", true},
	}
	for _, tc := range tests {
		t.Run(tc.name+tc.value, func(t *testing.T) {
			got, err := encodeOption(optionSpecs[tc.name], parseNode(t, tc.value))
			if (err == nil) != tc.ok {
				t.Fatalf("got %v", err)
			}
			if tc.ok && hex.EncodeToString(got) != tc.want {
				t.Fatalf("got %x want %s", got, tc.want)
			}
		})
	}
	c := Config{Options: map[string]yaml.Node{"message_type": parseNode(t, "1")}}
	if _, err := c.EncodedOptions(); err == nil {
		t.Fatal("accepted protocol-managed option")
	}
}

func TestOptionsLinkConstraints(t *testing.T) {
	p := Pool{Start: netip.MustParseAddr("192.0.2.10"), End: netip.MustParseAddr("192.0.2.30")}
	c := Config{
		Pool: p,
		Options: map[string]yaml.Node{
			"routers":           parseNode(t, "[192.0.2.11]"),
			"broadcast_address": parseNode(t, "192.0.2.255"),
		},
	}
	c.LeaseDuration = 3600000000000
	c.OfferDuration = 60000000000
	c.DeclineDuration = 60000000000
	if err := c.ValidateLink(netip.MustParseAddr("192.0.2.1"), netip.MustParsePrefix("192.0.2.0/24")); err != nil {
		t.Fatal(err)
	}
	c.Router = netip.MustParseAddr("192.0.2.1")
	if err := c.Validate(); err == nil {
		t.Fatal("accepted conflicting router settings")
	}
	c.Router = netip.Addr{}
	c.Options["broadcast_address"] = parseNode(t, "192.0.2.127")
	if err := c.ValidateLink(netip.MustParseAddr("192.0.2.1"), netip.MustParsePrefix("192.0.2.0/24")); err == nil {
		t.Fatal("accepted wrong broadcast")
	}
}
