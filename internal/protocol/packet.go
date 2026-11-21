// Package protocol validates untrusted DHCP encodings before protocol decisions.
package protocol

import (
	"bytes"
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
// Keep the library for packet decoding and serialization; normalize options here.
func Parse(data []byte) (*dhcpv4.DHCPv4, error) {
	if len(data) < optionsOffset || len(data) > MaxPacketSize {
		return nil, fmt.Errorf("%w: DHCP packet size outside 240..%d", ErrMalformedPacket, MaxPacketSize)
	}
	packet, err := dhcpv4.FromBytes(data)
	if err != nil {
		return nil, fmt.Errorf("parse DHCP packet: %w: %w", ErrMalformedPacket, err)
	}

	options := make(dhcpv4.Options)
	if err := collect(options, data[optionsOffset:], true); err != nil {
		return nil, fmt.Errorf("collect main options: %w", err)
	}
	if overload, ok := options[52]; ok {
		if len(overload) != 1 || overload[0] < 1 || overload[0] > 3 {
			return nil, fmt.Errorf("%w: invalid option overload", ErrMalformedPacket)
		}
		// Overload bit 1 selects file; bit 2 selects sname (RFC 2132 §9.3).
		if overload[0]&1 != 0 {
			if err := collect(options, data[108:236], false); err != nil {
				return nil, fmt.Errorf("collect boot file options: %w", err)
			}
			packet.BootFileName = ""
		}
		if overload[0]&2 != 0 {
			if err := collect(options, data[44:108], false); err != nil {
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
	packet.Options = options
	return packet, nil
}

func collect(options dhcpv4.Options, data []byte, mainOptions bool) error {
	for i := 0; i < len(data); {
		code := data[i]
		i++
		if code == 0 {
			continue
		}
		if code == 255 {
			if len(bytes.Trim(data[i:], "\x00")) != 0 {
				return fmt.Errorf("%w: non-padding bytes after END", ErrMalformedPacket)
			}
			return nil
		}
		if i == len(data) {
			return fmt.Errorf("%w: missing option length", ErrMalformedPacket)
		}

		length := int(data[i])
		i++
		if length > len(data)-i {
			return fmt.Errorf("%w: truncated option", ErrMalformedPacket)
		}

		_, seen := options[code]
		if code == 52 && (!mainOptions || seen) {
			return fmt.Errorf("%w: nested or repeated overload", ErrMalformedPacket)
		}
		options[code] = append(options[code], data[i:i+length]...)
		i += length
	}
	return fmt.Errorf("%w: missing END", ErrMalformedPacket)
}
