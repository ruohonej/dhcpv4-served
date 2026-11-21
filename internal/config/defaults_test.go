package config

import (
	"net/netip"
	"testing"
	"time"
)

func TestDefault(t *testing.T) {
	cases := []struct {
		ip, prefix, start, end string
		fail                   bool
	}{
		{"192.168.5.10", "192.168.5.0/24", "192.168.5.1", "192.168.5.254", false},
		{"192.168.5.1", "192.168.5.0/30", "192.168.5.1", "192.168.5.2", false},
		{"192.168.5.1", "192.168.5.0/31", "", "", true},
		{"192.168.5.0", "192.168.5.0/24", "", "", true},
		{"192.168.5.1", "192.168.5.1/24", "", "", true},
		{"128.0.0.1", "128.0.0.0/1", "", "", true},
		{"1.0.0.1", "0.0.0.0/1", "", "", true},
		{"240.0.0.1", "240.0.0.0/8", "", "", true},
		{"169.254.0.1", "169.254.0.0/16", "", "", true},
		{"192.0.2.1", "192.0.2.0/24", "192.0.2.1", "192.0.2.254", false},
	}
	for _, tc := range cases {
		t.Run(tc.prefix+"_"+tc.ip, func(t *testing.T) {
			server, subnet := netip.MustParseAddr(tc.ip), netip.MustParsePrefix(tc.prefix)
			cfg, err := Default(server, subnet, []netip.Addr{netip.MustParseAddr("1.1.1.1")})
			if (err != nil) != tc.fail {
				t.Fatalf("Default error: %v", err)
			}
			if tc.fail {
				return
			}
			if cfg.Pool.Start.String() != tc.start || cfg.Pool.End.String() != tc.end || cfg.Router != server || cfg.LeaseDuration != 12*time.Hour || cfg.OfferDuration != time.Minute || cfg.DeclineDuration != 10*time.Minute {
				t.Fatalf("unexpected defaults: %+v", cfg)
			}
			opts, err := cfg.EncodedOptions()
			if err != nil || len(opts) != 0 || len(cfg.DNS) != 1 || cfg.DNS[0] != netip.MustParseAddr("1.1.1.1") {
				t.Fatalf("unexpected default options or DNS: %v, %v, %v", opts, cfg.DNS, err)
			}
		})
	}
}
