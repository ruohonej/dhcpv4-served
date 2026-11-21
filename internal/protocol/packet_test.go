package protocol

import (
	"bytes"
	"errors"
	"testing"

	"github.com/insomniacslk/dhcp/dhcpv4"
)

func wire(t *testing.T, options []byte) []byte {
	t.Helper()
	p, err := dhcpv4.New(dhcpv4.WithMessageType(dhcpv4.MessageTypeDiscover))
	if err != nil {
		t.Fatal(err)
	}
	return append(p.ToBytes()[:240:240], options...)
}

func TestConcatenationAndOverload(t *testing.T) {
	for _, overload := range []byte{1, 2, 3} {
		t.Run(string(rune('0'+overload)), func(t *testing.T) {
			data := wire(t, []byte{53, 1, 1, 0, 52, 1, overload, 61, 2, 1, 'a', 0, 61, 1, 'b', 255})
			expected := []byte{1, 'a', 'b'}
			if overload&1 != 0 {
				copy(data[108:236], []byte{61, 1, 'c', 255})
				expected = append(expected, 'c')
			}
			if overload&2 != 0 {
				copy(data[44:108], []byte{61, 1, 'd', 255})
				expected = append(expected, 'd')
			}
			// Establish the pinned library's limitation separately from our adapter.
			raw, err := dhcpv4.FromBytes(data)
			if err != nil || !bytes.Equal(raw.Options[61], []byte{1, 'a', 'b'}) {
				t.Fatalf("library main concatenation: %v", err)
			}
			p, err := Parse(data)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(p.Options[61], expected) {
				t.Fatalf("identity %x want %x", p.Options[61], expected)
			}
			round, err := Parse(p.ToBytes())
			if err != nil || !bytes.Equal(round.Options[61], expected) {
				t.Fatalf("round trip: %v", err)
			}
			if _, ok := p.Options[52]; ok {
				t.Fatal("retained overload after normalization")
			}
		})
	}
}

func TestLibraryLongOptionRoundTrip(t *testing.T) {
	p, err := Parse(wire(t, []byte{53, 1, 1, 255}))
	if err != nil {
		t.Fatal(err)
	}
	id := bytes.Repeat([]byte{42}, 600)
	p.Options[61] = id
	data := p.ToBytes()
	// The serializer must split into multiple TLVs, and our boundary recombines.
	q, err := Parse(data)
	if err != nil || !bytes.Equal(q.Options[61], id) {
		t.Fatalf("long option round trip: %v", err)
	}
}

func TestMalformedOptions(t *testing.T) {
	cases := map[string][]byte{
		"no-end":                    {53, 1, 1},
		"no-length":                 {53},
		"truncated":                 {53, 4, 1, 255},
		"repeated-message-type":     {53, 1, 1, 53, 1, 3, 255},
		"empty-id":                  {53, 1, 1, 61, 0, 255},
		"short-id":                  {53, 1, 1, 61, 1, 1, 255},
		"invalid-overload":          {53, 1, 1, 52, 1, 4, 255},
		"empty-then-valid-overload": {53, 1, 1, 52, 0, 52, 1, 1, 255},
		"duplicate-overload":        {53, 1, 1, 52, 1, 1, 52, 1, 2, 255},
		"missing-message-type":      {61, 2, 1, 2, 255},
		"short-address":             {53, 1, 1, 50, 3, 1, 2, 3, 255},
		"small-message-size":        {53, 1, 1, 57, 2, 0, 1, 255},
		"after-end":                 {53, 1, 1, 255, 61, 2, 1, 2},
	}
	for name, opts := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse(wire(t, opts)); !errors.Is(err, ErrMalformedPacket) {
				t.Fatalf("expected malformed-packet sentinel: %v", err)
			}
		})
	}
	for name, field := range map[string][]byte{"nested": {52, 1, 1, 255}, "missing-end": {}, "truncated": {61, 255, 1}} {
		t.Run(name, func(t *testing.T) {
			data := wire(t, []byte{53, 1, 1, 52, 1, 1, 255})
			copy(data[108:236], field)
			if _, err := Parse(data); !errors.Is(err, ErrMalformedPacket) {
				t.Fatalf("expected malformed-packet sentinel: %v", err)
			}
		})
	}
	data := wire(t, []byte{53, 1, 1, 255})
	data = append(data, make([]byte, MaxPacketSize)...)
	if _, err := Parse(data); err == nil {
		t.Fatal("accepted oversized packet")
	}
	p, _ := Parse(wire(t, []byte{53, 1, 1, 255}))
	p.Options[61] = bytes.Repeat([]byte{1}, MaxClientIDSize+1)
	if _, err := Parse(p.ToBytes()); err == nil {
		t.Fatal("accepted oversized identity")
	}
}

func FuzzParse(f *testing.F) {
	p, err := dhcpv4.New(dhcpv4.WithMessageType(dhcpv4.MessageTypeDiscover))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(p.ToBytes())
	f.Add([]byte{})
	base := p.ToBytes()[:240:240]
	f.Add(append(append([]byte(nil), base...), 53, 4, 1, 255))           // truncated option
	f.Add(append(append([]byte(nil), base...), 53, 1, 1, 52, 1, 4, 255)) // invalid overload
	p.Options[61] = bytes.Repeat([]byte{1}, MaxClientIDSize)
	f.Add(p.ToBytes())
	f.Fuzz(func(t *testing.T, data []byte) {
		p, err := Parse(data)
		if err != nil {
			if !errors.Is(err, ErrMalformedPacket) {
				t.Fatalf("packet rejection lost its sentinel: %v", err)
			}
			return
		}
		q, err := Parse(p.ToBytes())
		if err != nil {
			t.Fatalf("accepted packet failed normalized round trip: %v", err)
		}
		if !bytes.Equal(q.Options[61], p.Options[61]) {
			t.Fatal("identity changed on round trip")
		}
	})
}
