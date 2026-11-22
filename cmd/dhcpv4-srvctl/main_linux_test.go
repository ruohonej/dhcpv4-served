package main

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"dhcpv4-served/internal/config"
	"gopkg.in/yaml.v3"
)

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
