// Package protocol validates untrusted DHCP encodings before protocol decisions.
package protocol

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/insomniacslk/dhcp/dhcpv4"
)

// ErrMalformedPacket identifies an expected rejection of untrusted packet data.
var ErrMalformedPacket = errors.New("malformed DHCP packet")

const (
	MaxPacketSize   = 1500
	MaxClientIDSize = 1024

	// DHCP options follow the 236-byte BOOTP header and 4-byte magic cookie.
	optionsOffset = 240
)

// Parse applies RFC 3396 concatenation in options, file, sname order. The pinned
// library concatenates the main options but does not decode overloaded fields.
// The library decodes each field; this adapter validates and normalizes them.
func Parse(data []byte) (*dhcpv4.DHCPv4, error) {
	if len(data) < optionsOffset || len(data) > MaxPacketSize {
		return nil, fmt.Errorf("%w: DHCP packet size outside 240..%d", ErrMalformedPacket, MaxPacketSize)
	}
	packet, err := dhcpv4.FromBytes(data)
	if err != nil {
		return nil, fmt.Errorf("parse DHCP packet: %w: %w", ErrMalformedPacket, err)
	}

	options := packet.Options
	if overload, ok := options[52]; ok {
		if len(overload) != 1 || overload[0] < 1 || overload[0] > 3 {
			return nil, fmt.Errorf("%w: invalid option overload", ErrMalformedPacket)
		}
		// Overload bit 1 selects file; bit 2 selects sname (RFC 2132 §9.3).
		if overload[0]&1 != 0 {
			if err := collectOverloaded(options, data[108:236]); err != nil {
				return nil, fmt.Errorf("collect boot file options: %w", err)
			}
			packet.BootFileName = ""
		}
		if overload[0]&2 != 0 {
			if err := collectOverloaded(options, data[44:108]); err != nil {
				return nil, fmt.Errorf("collect server name options: %w", err)
			}
			packet.ServerHostName = ""
		}
	}

	for code, size := range map[byte]int{
		53: 1, // DHCP message type.
		50: 4, // Requested IP address.
		54: 4, // Server identifier.
		57: 2, // Maximum message size.
	} {
		if value, ok := options[code]; ok && len(value) != size {
			return nil, fmt.Errorf("%w: invalid option %d length", ErrMalformedPacket, code)
		}
	}
	if len(options[53]) != 1 {
		return nil, fmt.Errorf("%w: missing message type", ErrMalformedPacket)
	}
	if id, ok := options[61]; ok && (len(id) < 2 || len(id) > MaxClientIDSize) {
		return nil, fmt.Errorf("%w: invalid client identifier length", ErrMalformedPacket)
	}
	if size, ok := options[57]; ok && binary.BigEndian.Uint16(size) < 576 {
		return nil, fmt.Errorf("%w: maximum message size below 576", ErrMalformedPacket)
	}

	// Overloaded data has become ordinary options. Re-serialization must not
	// advertise fields which the library serializer does not populate as options.
	delete(options, 52)
	return packet, nil
}

func collectOverloaded(options dhcpv4.Options, data []byte) error {
	field := make(dhcpv4.Options)
	if err := field.FromBytes(data); err != nil {
		return fmt.Errorf("%w: parse overloaded options: %w", ErrMalformedPacket, err)
	}
	if _, ok := field[52]; ok {
		return fmt.Errorf("%w: nested overload", ErrMalformedPacket)
	}
	for code, value := range field {
		options[code] = append(options[code], value...)
	}
	return nil
}
