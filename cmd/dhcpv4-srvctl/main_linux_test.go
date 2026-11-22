package main

import (
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"dhcpv4-served/internal/config"
	"gopkg.in/yaml.v3"
)

func TestRefreshPreservesOperatorSettings(t *testing.T) {
	old, err := config.Default(netip.MustParseAddr("192.168.10.1"), netip.MustParsePrefix("192.168.10.0/24"), []netip.Addr{netip.MustParseAddr("192.0.2.53")})
	if err != nil {
		t.Fatal(err)
	}
	old.Authoritative = true
	old.Router = netip.MustParseAddr("192.168.10.254")
	old.Pool.Start = netip.MustParseAddr("192.168.10.100")
	old.Pool.End = netip.MustParseAddr("192.168.10.200")
	old.LeaseDuration = 24 * time.Hour
	old.Excluded = []netip.Addr{netip.MustParseAddr("192.168.10.110")}
	old.Options = map[string]yaml.Node{"domain_name": {Kind: yaml.ScalarNode, Tag: "!!str", Value: "example.org"}}
	got := refreshedConfig(old, nil, errors.New("unavailable"))
	if got.Router != old.Router || got.Pool != old.Pool || len(got.DNS) != 1 || got.DNS[0] != old.DNS[0] || !got.Authoritative || got.LeaseDuration != old.LeaseDuration || len(got.Excluded) != 1 || got.Options["domain_name"].Value != "example.org" {
		t.Fatalf("unexpected refreshed configuration: %+v", got)
	}
	if err := got.ValidateLink(netip.MustParseAddr("192.168.10.2"), netip.MustParsePrefix("192.168.10.0/24")); err != nil {
		t.Fatal(err)
	}
	got.Excluded = []netip.Addr{netip.MustParseAddr("192.168.11.10")}
	if err := got.ValidateLink(netip.MustParseAddr("192.168.10.2"), netip.MustParsePrefix("192.168.10.0/24")); err == nil {
		t.Fatal("accepted incompatible exclusion")
	}
	old.Router = netip.Addr{}
	old.Options["routers"] = yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq", Content: []*yaml.Node{{Kind: yaml.ScalarNode, Tag: "!!str", Value: "192.168.10.3"}}}
	got = refreshedConfig(old, nil, nil)
	if len(got.DNS) != 0 {
		t.Fatal("successful empty discovery retained DNS")
	}
	if got.Router.IsValid() || got.Options["routers"].Content[0].Value != "192.168.10.3" {
		t.Fatal("explicit routers were not preserved")
	}
	delete(old.Options, "routers")
	got = refreshedConfig(old, []netip.Addr{netip.MustParseAddr("198.51.100.53")}, nil)
	if got.Router.IsValid() || got.DNS[0] != netip.MustParseAddr("198.51.100.53") {
		t.Fatal("refresh changed omitted router or failed to update DNS")
	}
}

func TestRefreshResolvesOptionAliases(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	input := "pool:\n  start: 192.168.10.100\n  end: 192.168.10.200\nrouter: &gateway 192.168.10.1\nlease_duration: 12h\noffer_duration: 60s\ndecline_duration: 10m\noptions:\n  ntp_servers: [*gateway]\n"
	if err := os.WriteFile(path, []byte(input), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	for name, node := range cfg.Options {
		cfg.Options[name] = resolveAliases(node)
	}
	data, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := config.Load(path); err != nil {
		t.Fatalf("reloading refreshed configuration: %v\n%s", err, data)
	}
}

func TestDefaultConfigRoundTrip(t *testing.T) {
	cfg, err := config.Default(netip.MustParseAddr("192.168.10.1"), netip.MustParsePrefix("192.168.10.0/24"), nil)
	if err != nil {
		t.Fatal(err)
	}
	data, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := config.Load(path); err != nil {
		t.Fatalf("generated YAML invalid: %v\n%s", err, data)
	}
}

func TestWorkerAccess(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "srvctl-access-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("test"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if err := checkWorkerAccess(path, true); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	if err := checkWorkerAccess(path, true); err == nil {
		t.Fatal("accepted unreadable configuration")
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0711); err != nil {
		t.Fatal(err)
	}
	if err := checkWorkerAccess(path, true); err == nil {
		t.Fatal("accepted inaccessible directory")
	}
}
