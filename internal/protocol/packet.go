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

// Parse validates the library-decoded packet before protocol decisions.
func Parse(data []byte) (*dhcpv4.DHCPv4, error) {
	if len(data) < optionsOffset || len(data) > MaxPacketSize {
		return nil, fmt.Errorf("%w: DHCP packet size outside 240..%d", ErrMalformedPacket, MaxPacketSize)
	}
	packet, err := dhcpv4.FromBytes(data)
	if err != nil {
		return nil, fmt.Errorf("parse DHCP packet: %w: %w", ErrMalformedPacket, err)
	}

	options := packet.Options
	if _, ok := options[52]; ok {
		return nil, fmt.Errorf("%w: option overload is unsupported", ErrMalformedPacket)
	}

	for code, size := range map[byte]int{
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

	return packet, nil
}
