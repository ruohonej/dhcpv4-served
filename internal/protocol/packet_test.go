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

func TestConcatenation(t *testing.T) {
	data := wire(t, []byte{53, 1, 1, 61, 2, 1, 'a', 61, 1, 'b', 255})
	p, err := Parse(data)
	if err != nil || !bytes.Equal(p.Options[61], []byte{1, 'a', 'b'}) {
		t.Fatalf("main option concatenation: %v", err)
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
		"no-end":                {53, 1, 1},
		"no-length":             {53},
		"truncated":             {53, 4, 1, 255},
		"repeated-message-type": {53, 1, 1, 53, 1, 3, 255},
		"empty-id":              {53, 1, 1, 61, 0, 255},
		"short-id":              {53, 1, 1, 61, 1, 1, 255},
		"invalid-overload":      {53, 1, 1, 52, 1, 4, 255},
		"overload-file":         {53, 1, 1, 52, 1, 1, 255},
		"overload-sname":        {53, 1, 1, 52, 1, 2, 255},
		"overload-both":         {53, 1, 1, 52, 1, 3, 255},
		"overload-empty":        {53, 1, 1, 52, 0, 255},
		"duplicate-overload":    {53, 1, 1, 52, 1, 1, 52, 1, 2, 255},
		"missing-message-type":  {61, 2, 1, 2, 255},
		"short-address":         {53, 1, 1, 50, 3, 1, 2, 3, 255},
		"small-message-size":    {53, 1, 1, 57, 2, 0, 1, 255},
	}
	for name, opts := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse(wire(t, opts)); !errors.Is(err, ErrMalformedPacket) {
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

func TestLibraryOptionTolerance(t *testing.T) {
	cases := []struct {
		name    string
		options []byte
		wantID  []byte
	}{
		{"main-after-end", []byte{53, 1, 1, 255, 61, 2, 1, 2}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data := wire(t, tc.options)
			p, err := Parse(data)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(p.Options[61], tc.wantID) {
				t.Fatalf("client identifier %x, want %x", p.Options[61], tc.wantID)
			}
		})
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
