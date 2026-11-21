package config

import (
	"fmt"
	"net"
	"net/netip"
	"time"
)

// Default builds the no-file policy from the selected link. Resolver addresses
// are snapshots obtained by the caller before the worker enters its sandbox.
func Default(server netip.Addr, subnet netip.Prefix, dns []netip.Addr) (Config, error) {
	if !subnet.IsValid() || !subnet.Addr().Is4() || subnet != subnet.Masked() || subnet.Bits() < 1 || subnet.Bits() > 30 {
		return Config{}, fmt.Errorf("link must use an IPv4 /1 through /30 subnet")
	}
	// These blocks cannot safely be allocated to clients, even when both
	// endpoints of a broad pool happen to pass IsGlobalUnicast.
	for _, block := range []string{"0.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/4", "240.0.0.0/4"} {
		if subnet.Overlaps(netip.MustParsePrefix(block)) {
			return Config{}, fmt.Errorf("default pool overlaps unusable IPv4 block %s", block)
		}
	}
	last := subnet.Addr().As4()
	mask := net.CIDRMask(subnet.Bits(), 32)
	for i := range last {
		last[i] |= ^mask[i]
	}
	broadcast := netip.AddrFrom4(last)
	cfg := Config{Pool: Pool{Start: subnet.Addr().Next(), End: broadcast.Prev()}, Router: server,
		DNS: dns, LeaseDuration: 12 * time.Hour, OfferDuration: time.Minute, DeclineDuration: 10 * time.Minute}
	if err := cfg.ValidateLink(server, subnet); err != nil {
		return Config{}, err
	}
	if cfg.Pool.Start == cfg.Pool.End && cfg.Pool.Start == server {
		return Config{}, fmt.Errorf("no addresses available in default pool")
	}
	return cfg, nil
}
