package config

import (
	"cmp"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
	"unicode/utf8"

	"gopkg.in/yaml.v3"
)

type optionSpec struct {
	code byte
	kind string
	min  int64
	max  int64
}

// The YAML "options" mapping uses the names below. IPs means a nonempty,
// ordered list of IPv4 addresses; IP means one IPv4 address; text means 1–1024
// printable ASCII characters; bool means true or false; u8/u16/u32 are unsigned
// integers. Address and pair lists are limited to 1024 encoded bytes. Numbers
// are encoded in network byte order. Unknown and protocol-managed codes cannot
// be configured.
//
// Options are included in OFFER and ACK (including INFORM ACK), subject to the
// client's parameter request list and maximum message size. Without a request
// list, all configured options that fit are eligible. Oversized options are
// omitted. Long options are split according to RFC 3396 §§4, 6.
//
// For example:
//
//	options:
//	  routers: [192.168.10.1, 192.168.10.2]
//	  domain_name: example.test
//	  ntp_servers: [192.168.10.1]
//	  static_routes: [[192.0.2.0, 192.168.10.1]]
//
// The TFTP and bootfile names are sent as
// DHCP options; BOOTP and overloaded reply fields are not implemented. Vendor
// information is sent uniformly, without selecting by vendor class.
//
// Pad/end, requested address, overload, message type, server identifier,
// parameter request list, message, maximum message size, vendor class and client
// identifier are managed by protocol handling or unsupported (RFC 2132 §§3.1–3.2,
// 9.1, 9.3, 9.6–9.10, 9.13–9.14). RFC 6842 §3 requires echoing client ID.
var optionSpecs = map[string]optionSpec{
	// RFC 2132 §3.4: signed 32-bit UTC offset in seconds.
	"time_offset": {code: 2, kind: "i32", min: -2147483648, max: 2147483647},
	// RFC 2132 §3.5: IPs on the interface subnet.
	"routers": {code: 3, kind: "ips"},
	// RFC 2132 §3.6: IPs.
	"time_servers": {code: 4, kind: "ips"},
	// RFC 2132 §3.7: IPs.
	"name_servers": {code: 5, kind: "ips"},
	// RFC 2132 §3.9: IPs.
	"log_servers": {code: 7, kind: "ips"},
	// RFC 2132 §3.10: IPs.
	"cookie_servers": {code: 8, kind: "ips"},
	// RFC 2132 §3.11: IPs.
	"lpr_servers": {code: 9, kind: "ips"},
	// RFC 2132 §3.12: IPs.
	"impress_servers": {code: 10, kind: "ips"},
	// RFC 2132 §3.13: IPs.
	"resource_location_servers": {code: 11, kind: "ips"},
	// RFC 2132 §3.14: text.
	"host_name": {code: 12, kind: "text"},
	// RFC 2132 §3.15: u16, 512-octet blocks.
	"boot_file_size": {code: 13, kind: "u16", max: 65535},
	// RFC 2132 §3.16: text.
	"merit_dump_file": {code: 14, kind: "text"},
	// RFC 2132 §3.17: text.
	"domain_name": {code: 15, kind: "text"},
	// RFC 2132 §3.18: IP.
	"swap_server": {code: 16, kind: "ip"},
	// RFC 2132 §3.19: text.
	"root_path": {code: 17, kind: "text"},
	// RFC 2132 §3.20: text.
	"extensions_path": {code: 18, kind: "text"},
	// RFC 2132 §4.1: bool.
	"ip_forwarding": {code: 19, kind: "bool"},
	// RFC 2132 §4.2: bool.
	"non_local_source_routing": {code: 20, kind: "bool"},
	// RFC 2132 §4.3: nonempty list of `[address, mask]` IPv4 pairs.
	"policy_filters": {code: 21, kind: "pairs"},
	// RFC 2132 §4.4: u16, 576–65535.
	"maximum_datagram_reassembly_size": {code: 22, kind: "u16", min: 576, max: 65535},
	// RFC 2132 §4.5: u8, 1–255.
	"default_ip_ttl": {code: 23, kind: "u8", min: 1, max: 255},
	// RFC 2132 §4.6: u32, seconds.
	"path_mtu_aging_timeout": {code: 24, kind: "u32", max: 4294967295},
	// RFC 2132 §4.7: increasing u16 list, each at least 68.
	"path_mtu_plateau_table": {code: 25, kind: "plateaus"},
	// RFC 2132 §5.1: u16, 68–65535.
	"interface_mtu": {code: 26, kind: "u16", min: 68, max: 65535},
	// RFC 2132 §5.2: bool.
	"all_subnets_local": {code: 27, kind: "bool"},
	// RFC 2132 §5.3: IP, must match the discovered subnet.
	"broadcast_address": {code: 28, kind: "ip"},
	// RFC 2132 §5.4: bool.
	"perform_mask_discovery": {code: 29, kind: "bool"},
	// RFC 2132 §5.5: bool.
	"mask_supplier": {code: 30, kind: "bool"},
	// RFC 2132 §5.6: bool.
	"perform_router_discovery": {code: 31, kind: "bool"},
	// RFC 2132 §5.7: IP.
	"router_solicitation_address": {code: 32, kind: "ip"},
	// RFC 2132 §5.8: nonempty list of `[destination, router]` IPv4 pairs; default route forbidden.
	"static_routes": {code: 33, kind: "routes"},
	// RFC 2132 §6.1: bool.
	"trailer_encapsulation": {code: 34, kind: "bool"},
	// RFC 2132 §6.2: u32, seconds.
	"arp_cache_timeout": {code: 35, kind: "u32", max: 4294967295},
	// RFC 2132 §6.3: bool.
	"ethernet_encapsulation": {code: 36, kind: "bool"},
	// RFC 2132 §7.1: u8, 1–255.
	"default_tcp_ttl": {code: 37, kind: "u8", min: 1, max: 255},
	// RFC 2132 §7.2: u32, seconds.
	"tcp_keepalive_interval": {code: 38, kind: "u32", max: 4294967295},
	// RFC 2132 §7.3: bool.
	"tcp_keepalive_garbage": {code: 39, kind: "bool"},
	// RFC 2132 §8.1: text.
	"nis_domain": {code: 40, kind: "text"},
	// RFC 2132 §8.2: IPs.
	"nis_servers": {code: 41, kind: "ips"},
	// RFC 2132 §8.3: IPs.
	"ntp_servers": {code: 42, kind: "ips"},
	// RFC 2132 §8.4: hex string representing 1–1024 bytes.
	"vendor_specific_information": {code: 43, kind: "hex"},
	// RFC 2132 §8.5: IPs.
	"netbios_name_servers": {code: 44, kind: "ips"},
	// RFC 2132 §8.6: IPs.
	"netbios_datagram_servers": {code: 45, kind: "ips"},
	// RFC 2132 §8.7: 1, 2, 4 or 8.
	"netbios_node_type": {code: 46, kind: "node"},
	// RFC 2132 §8.8: text.
	"netbios_scope": {code: 47, kind: "text"},
	// RFC 2132 §8.9: IPs.
	"x_font_servers": {code: 48, kind: "ips"},
	// RFC 2132 §8.10: IPs.
	"x_display_managers": {code: 49, kind: "ips"},
	// RFC 2132 §8.11: text.
	"nis_plus_domain": {code: 64, kind: "text"},
	// RFC 2132 §8.12: IPs.
	"nis_plus_servers": {code: 65, kind: "ips"},
	// RFC 2132 §9.4: text.
	"tftp_server_name": {code: 66, kind: "text"},
	// RFC 2132 §9.5: text.
	"bootfile_name": {code: 67, kind: "text"},
	// RFC 2132 §8.13: IPs; empty list is permitted.
	"mobile_ip_home_agents": {code: 68, kind: "ips_empty"},
	// RFC 2132 §8.14: IPs.
	"smtp_servers": {code: 69, kind: "ips"},
	// RFC 2132 §8.15: IPs.
	"pop3_servers": {code: 70, kind: "ips"},
	// RFC 2132 §8.16: IPs.
	"nntp_servers": {code: 71, kind: "ips"},
	// RFC 2132 §8.17: IPs.
	"www_servers": {code: 72, kind: "ips"},
	// RFC 2132 §8.18: IPs.
	"finger_servers": {code: 73, kind: "ips"},
	// RFC 2132 §8.19: IPs.
	"irc_servers": {code: 74, kind: "ips"},
	// RFC 2132 §8.20: IPs.
	"streettalk_servers": {code: 75, kind: "ips"},
	// RFC 2132 §8.21: IPs.
	"streettalk_directory_servers": {code: 76, kind: "ips"},
}

// EncodedOptions validates and encodes named settings in deterministic code order.
func (cfg Config) EncodedOptions() ([]EncodedOption, error) {
	options := make([]EncodedOption, 0, len(cfg.Options))
	for name, node := range cfg.Options {
		spec, ok := optionSpecs[name]
		if !ok {
			return nil, fmt.Errorf("unknown DHCP option %q", name)
		}
		value, err := encodeOption(spec, node)
		if err != nil {
			return nil, fmt.Errorf("option %s: %w", name, err)
		}
		options = append(options, EncodedOption{Code: spec.code, Value: value})
	}
	slices.SortFunc(options, func(a, b EncodedOption) int {
		return cmp.Compare(a.Code, b.Code)
	})
	return options, nil
}

// EncodedOption contains a DHCP option code and its validated wire-format value.
type EncodedOption struct {
	Code  byte
	Value []byte
}

func encodeOption(spec optionSpec, node yaml.Node) ([]byte, error) {
	if node.Tag == "!!null" {
		return nil, fmt.Errorf("option value cannot be null")
	}
	switch spec.kind {
	case "bool":
		var enabled bool
		if err := node.Decode(&enabled); err != nil {
			return nil, err
		}
		if enabled {
			return []byte{1}, nil
		}
		return []byte{0}, nil

	case "u8", "u16", "u32", "i32", "node":
		var value int64
		if err := node.Decode(&value); err != nil {
			return nil, err
		}
		if spec.kind == "node" {
			if value != 1 && value != 2 && value != 4 && value != 8 {
				return nil, fmt.Errorf("node type must be 1, 2, 4 or 8")
			}
		} else if value < spec.min || value > spec.max {
			return nil, fmt.Errorf("number outside %d..%d", spec.min, spec.max)
		}

		// Signed i32 values use the same network-order bits as uint32 values.
		switch spec.kind {
		case "u8", "node":
			return []byte{byte(value)}, nil // #nosec G115 -- range checked above
		case "u16":
			return binary.BigEndian.AppendUint16(nil, uint16(value)), nil // #nosec G115 -- range checked above
		default:
			return binary.BigEndian.AppendUint32(nil, uint32(value)), nil // #nosec G115 -- checked range; signed i32 uses two's-complement bits
		}

	case "text", "hex":
		var text string
		if err := node.Decode(&text); err != nil {
			return nil, err
		}
		if spec.kind == "hex" {
			encoded, err := hex.DecodeString(text)
			if err != nil || len(encoded) == 0 || len(encoded) > 1024 {
				return nil, fmt.Errorf("expected 1..1024 bytes of hexadecimal")
			}
			return encoded, nil
		}
		if len(text) == 0 || len(text) > 1024 || !utf8.ValidString(text) {
			return nil, fmt.Errorf("expected 1..1024 ASCII characters")
		}
		for _, char := range text {
			if char < 32 || char > 126 {
				return nil, fmt.Errorf("expected printable ASCII")
			}
		}
		return []byte(text), nil

	case "ip":
		var addr netip.Addr
		if err := node.Decode(&addr); err != nil {
			return nil, err
		}
		if !addr.Is4() {
			return nil, fmt.Errorf("expected IPv4 address")
		}
		if spec.code == 16 && !addr.IsGlobalUnicast() {
			return nil, fmt.Errorf("swap server must be a usable IPv4 address")
		}
		return addr.AsSlice(), nil

	case "ips", "ips_empty":
		var addresses []netip.Addr
		if err := node.Decode(&addresses); err != nil {
			return nil, err
		}
		if len(addresses) > 256 || (len(addresses) == 0 && spec.kind == "ips") {
			return nil, fmt.Errorf("expected 1..256 IPv4 addresses")
		}
		encoded := make([]byte, 0, net.IPv4len*len(addresses))
		for _, addr := range addresses {
			if !addr.Is4() || !addr.IsGlobalUnicast() {
				return nil, fmt.Errorf("expected usable IPv4 addresses")
			}
			encoded = append(encoded, addr.AsSlice()...)
		}
		return encoded, nil

	case "pairs", "routes":
		var pairs [][]netip.Addr
		if err := node.Decode(&pairs); err != nil {
			return nil, err
		}
		if len(pairs) == 0 || len(pairs) > 128 {
			return nil, fmt.Errorf("expected 1..128 address pairs")
		}
		var encoded []byte
		for _, pair := range pairs {
			if len(pair) != 2 || !pair[0].Is4() || !pair[1].Is4() {
				return nil, fmt.Errorf("each entry must contain two IPv4 addresses")
			}
			if spec.kind == "routes" && (pair[0].IsUnspecified() || !pair[1].IsGlobalUnicast()) {
				return nil, fmt.Errorf("static route requires a nonzero destination and usable router")
			}
			encoded = append(encoded, pair[0].AsSlice()...)
			encoded = append(encoded, pair[1].AsSlice()...)
		}
		return encoded, nil

	case "plateaus":
		var sizes []uint16
		if err := node.Decode(&sizes); err != nil {
			return nil, err
		}
		if len(sizes) == 0 || len(sizes) > 512 {
			return nil, fmt.Errorf("expected 1..512 MTU values")
		}
		var encoded []byte
		var previous uint16
		for _, value := range sizes {
			if value < 68 || (previous != 0 && value <= previous) {
				return nil, fmt.Errorf("MTU values must be at least 68 and strictly increasing")
			}
			encoded = binary.BigEndian.AppendUint16(encoded, value)
			previous = value
		}
		return encoded, nil
	}
	return nil, fmt.Errorf("unsupported option encoding %s", strings.TrimSpace(spec.kind))
}
