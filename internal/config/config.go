// Package config loads and validates one or more administrator-owned configurations.
package config

import (
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Pool is an inclusive range of addresses available for allocation.
type Pool struct {
	Start netip.Addr `yaml:"start"`
	End   netip.Addr `yaml:"end"`
}

// Config contains DHCP settings. Pool and exclusion policy, offer/decline
// duration, and authoritative mode are local server policies (RFC 2131
// §§4.3.1–4.3.3), not configurable packet options. Durations must be whole
// seconds between one second and 365 days. See optionSpecs for RFC references
// and the accepted values in the options mapping. The subnet mask (option 1,
// RFC 2132 §3.3) is derived from the interface and cannot be set here.
type Config struct {
	Options  map[string]yaml.Node `yaml:"options"`
	Pool     Pool                 `yaml:"pool"`
	Excluded []netip.Addr         `yaml:"excluded_addresses"`

	// Router supplies option 3 (RFC 2132 §3.5). It cannot be combined with
	// options.routers; every configured router is excluded from allocation.
	Router netip.Addr `yaml:"router"`

	// DNS supplies the ordered option 6 server list (RFC 2132 §3.8).
	DNS []netip.Addr `yaml:"dns_servers"`

	// LeaseDuration supplies option 51 (RFC 2132 §9.2); options 58 and 59
	// use 1/2 and 7/8 of it (RFC 2132 §§9.11–9.12, RFC 2131 §4.4.5).
	LeaseDuration   time.Duration `yaml:"lease_duration"`
	OfferDuration   time.Duration `yaml:"offer_duration"`
	DeclineDuration time.Duration `yaml:"decline_duration"`
	Authoritative   bool          `yaml:"authoritative"`
}

func Load(path string) (Config, error) {
	file, err := os.Open(path) // #nosec G304 -- administrator-selected configuration path
	if err != nil {
		return Config{}, fmt.Errorf("open configuration: %w", err)
	}
	defer func() { _ = file.Close() }()
	return loadFile(file)
}

func loadFile(file *os.File) (Config, error) {
	info, err := file.Stat()
	if err != nil {
		return Config{}, fmt.Errorf("inspect configuration: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() > 1<<20 {
		return Config{}, fmt.Errorf("configuration must be a regular file no larger than 1 MiB")
	}
	decoder := yaml.NewDecoder(io.LimitReader(file, 1<<20))
	decoder.KnownFields(true)
	var cfg Config
	if err := decoder.Decode(&cfg); err != nil {
		return cfg, fmt.Errorf("decode configuration: %w", err)
	}

	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return cfg, fmt.Errorf("configuration must contain one YAML document")
	}
	if err := cfg.Validate(); err != nil {
		return cfg, fmt.Errorf("validate configuration: %w", err)
	}
	return cfg, nil
}

func (cfg Config) Validate() error {
	if _, err := cfg.EncodedOptions(); err != nil {
		return err
	}
	if _, ok := cfg.Options["routers"]; ok && cfg.Router.IsValid() {
		return fmt.Errorf("router and options.routers cannot both be set")
	}

	usable := func(addr netip.Addr) bool {
		return addr.Is4() && addr.IsGlobalUnicast()
	}
	if !usable(cfg.Pool.Start) || !usable(cfg.Pool.End) || cfg.Pool.Start.Compare(cfg.Pool.End) > 0 {
		return fmt.Errorf("invalid pool")
	}
	if cfg.Router.IsValid() && !usable(cfg.Router) {
		return fmt.Errorf("invalid router")
	}

	if len(cfg.DNS) > 63 {
		return fmt.Errorf("at most 63 DNS addresses")
	}
	for _, addr := range cfg.DNS {
		if !addr.Is4() || !addr.IsGlobalUnicast() {
			return fmt.Errorf("invalid DNS address")
		}
	}

	seen := map[netip.Addr]bool{}
	for _, addr := range cfg.Excluded {
		if !usable(addr) || addr.Compare(cfg.Pool.Start) < 0 || addr.Compare(cfg.Pool.End) > 0 || seen[addr] {
			return fmt.Errorf("invalid or duplicate excluded address")
		}
		seen[addr] = true
	}

	for _, duration := range []time.Duration{cfg.LeaseDuration, cfg.OfferDuration, cfg.DeclineDuration} {
		if duration < time.Second || duration > 365*24*time.Hour || duration%time.Second != 0 {
			return fmt.Errorf("durations must be whole seconds between 1s and 365d")
		}
	}

	return nil
}

// ValidateLink checks link-dependent constraints after live interface discovery.
func (cfg Config) ValidateLink(server netip.Addr, subnet netip.Prefix) error {
	if err := cfg.Validate(); err != nil {
		return err
	}

	canonicalIPv4 := subnet.IsValid() && subnet.Addr().Is4() && subnet == subnet.Masked()
	if !canonicalIPv4 || subnet.Bits() < 1 || subnet.Bits() > 30 {
		return fmt.Errorf("link must use an IPv4 /1 through /30 subnet")
	}
	// Set the host bits to obtain the subnet's broadcast address.
	broadcastBytes := subnet.Addr().As4()
	mask := net.CIDRMask(subnet.Bits(), net.IPv4len*8)
	for i := range broadcastBytes {
		broadcastBytes[i] |= ^mask[i]
	}
	broadcast := netip.AddrFrom4(broadcastBytes)
	usable := func(addr netip.Addr) bool {
		if !addr.Is4() || !addr.IsGlobalUnicast() || !subnet.Contains(addr) {
			return false
		}
		return addr != subnet.Addr() && addr != broadcast
	}
	if !usable(server) || !usable(cfg.Pool.Start) || !usable(cfg.Pool.End) {
		return fmt.Errorf("server and pool must be usable addresses on the interface subnet")
	}
	if cfg.Router.IsValid() && !usable(cfg.Router) {
		return fmt.Errorf("router must be a usable address on the interface subnet")
	}

	if node, ok := cfg.Options["routers"]; ok {
		var routers []netip.Addr
		if err := node.Decode(&routers); err != nil {
			return err
		}
		for _, addr := range routers {
			if !usable(addr) {
				return fmt.Errorf("router must be a usable address on the interface subnet")
			}
		}
	}

	if node, ok := cfg.Options["broadcast_address"]; ok {
		var address netip.Addr
		if err := node.Decode(&address); err != nil {
			return err
		}
		if address != broadcast {
			return fmt.Errorf("broadcast address must match the interface subnet")
		}
	}

	return nil
}

// ValidateMultiple checks static pool overlap; interface and subnet checks require live links.
func ValidateMultiple(configs []Config) error {
	for i, cfg := range configs {
		if err := cfg.Validate(); err != nil {
			return err
		}
		for _, other := range configs[:i] {
			if cfg.Pool.Start.Compare(other.Pool.End) <= 0 && other.Pool.Start.Compare(cfg.Pool.End) <= 0 {
				return fmt.Errorf("address pools overlap")
			}
		}
	}
	return nil
}
