// Package server connects validated DHCP messages to the lease engine.
package server

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/iana"

	"dhcpv4-served/internal/config"
	"dhcpv4-served/internal/events"
	"dhcpv4-served/internal/lease"
	"dhcpv4-served/internal/protocol"
)

// Config contains validated response settings for one interface.
type Config struct {
	// OnReject counts discarded requests in the worker. Legitimate no-reply operations are excluded.
	OnReject      func(events.Counter)
	Server        netip.Addr
	Subnet        netip.Prefix
	LeaseDuration time.Duration
	Router        netip.Addr
	DNS           []netip.Addr
	Authoritative bool
	Options       []config.EncodedOption
}

// Handler applies protocol decisions to one interface's lease engine.
type Handler struct {
	leases    *lease.Engine
	now       func() time.Time
	cfg       Config
	admission admission
}

// New binds validated settings to the lease engine and clock for this interface.
func New(leases *lease.Engine, now func() time.Time, cfg Config) *Handler {
	if leases == nil {
		panic("server: lease engine is required")
	}
	if now == nil {
		panic("server: clock is required")
	}
	cfg.DNS = slices.Clone(cfg.DNS)
	cfg.Options = slices.Clone(cfg.Options)
	for i := range cfg.Options {
		cfg.Options[i].Value = slices.Clone(cfg.Options[i].Value)
	}
	return &Handler{leases: leases, now: now, cfg: cfg}
}

// Response contains a serialized DHCP reply and its destination address.
type Response struct {
	Packet      []byte
	Destination netip.Addr
}

func (h *Handler) reject(reason events.Counter) (*Response, error) {
	if h.cfg.OnReject != nil {
		h.cfg.OnReject(reason)
	}
	return nil, nil
}

// Reply returns nil for requests that should be ignored or need no reply.
func (h *Handler) Reply(data []byte) (*Response, error) {
	packet, err := protocol.Parse(data)
	if err != nil {
		return nil, fmt.Errorf("parse request: %w", err)
	}
	if packet.OpCode != dhcpv4.OpcodeBootRequest || packet.HWType != iana.HWTypeEthernet {
		return h.reject(events.Policy)
	}
	if len(packet.ClientHWAddr) != 6 || packet.ClientHWAddr[0]&1 != 0 {
		return h.reject(events.Policy)
	}
	if bytes.Equal(packet.ClientHWAddr, make([]byte, 6)) {
		return h.reject(events.Policy)
	}
	// Relayed packets and reserved flag bits are unsupported.
	if !packet.GatewayIPAddr.Equal(net.IPv4zero) || packet.HopCount != 0 || packet.Flags&0x7fff != 0 {
		return h.reject(events.Policy)
	}

	limit := 576
	if size, ok := packet.Options[57]; ok {
		limit = int(binary.BigEndian.Uint16(size))
	}
	limit = min(limit, protocol.MaxPacketSize)

	clientID := "h:" + hex.EncodeToString(packet.ClientHWAddr)
	if raw, ok := packet.Options[61]; ok {
		clientID = "i:" + hex.EncodeToString(raw)
	}
	transactionID := binary.BigEndian.Uint32(packet.TransactionID[:])
	// Invalid slices become zero addresses; Unmap normalizes IPv4-mapped values.
	clientIP, _ := netip.AddrFromSlice(packet.ClientIPAddr)
	clientIP = clientIP.Unmap()
	unspecifiedClientIP := clientIP == netip.IPv4Unspecified()
	requestedIP, _ := netip.AddrFromSlice(packet.RequestedIPAddress())
	requestedIP = requestedIP.Unmap()
	serverID, _ := netip.AddrFromSlice(packet.ServerIdentifier())
	serverID = serverID.Unmap()
	hasRequestedIP := requestedIP.IsValid()
	hasServerID := serverID.IsValid()

	// Reserve capacity only for requests that match a live committed lease.
	// Merely setting ciaddr or rotating identifiers cannot select this bucket.
	renewal := packet.MessageType() == dhcpv4.MessageTypeRequest && !hasServerID &&
		((!unspecifiedClientIP && !hasRequestedIP && h.leases.OwnsLease(clientID, clientIP)) ||
			(unspecifiedClientIP && hasRequestedIP && h.leases.OwnsLease(clientID, requestedIP)))
	if !h.admission.allow(h.now(), renewal) {
		return h.reject(events.Admission)
	}

	// Check that mandatory options fit before any durable state transition.
	switch packet.MessageType() {
	case dhcpv4.MessageTypeDiscover, dhcpv4.MessageTypeRequest, dhcpv4.MessageTypeInform:
		probe, err := dhcpv4.NewReplyFromRequest(packet,
			dhcpv4.WithMessageType(dhcpv4.MessageTypeAck),
			dhcpv4.WithOption(dhcpv4.OptServerIdentifier(net.IP(h.cfg.Server.AsSlice()))),
			dhcpv4.WithNetmask(net.CIDRMask(h.cfg.Subnet.Bits(), 32)),
			dhcpv4.WithLeaseTime(uint32(h.cfg.LeaseDuration/time.Second)), // #nosec G115 -- validated whole seconds <= 365 days
			dhcpv4.WithOption(dhcpv4.OptRenewTimeValue(h.cfg.LeaseDuration/2)),
			dhcpv4.WithOption(dhcpv4.OptRebindingTimeValue(h.cfg.LeaseDuration*7/8)),
		)
		if err != nil {
			return nil, fmt.Errorf("build reply probe: %w", err)
		}
		if len(probe.ToBytes()) > limit {
			return h.reject(events.Policy)
		}
	}

	var binding lease.Binding
	var accepted bool
	replyType := dhcpv4.MessageTypeAck
	switch packet.MessageType() {
	case dhcpv4.MessageTypeDiscover:
		if !unspecifiedClientIP || hasServerID {
			return h.reject(events.Policy)
		}
		replyType = dhcpv4.MessageTypeOffer
		binding, err = h.leases.Offer(clientID, packet.ClientHWAddr.String(), transactionID, requestedIP)
		if errors.Is(err, lease.ErrExhausted) {
			return nil, fmt.Errorf("offer lease: %w", err)
		}
	case dhcpv4.MessageTypeRequest:
		switch {
		case unspecifiedClientIP && hasServerID && hasRequestedIP: // SELECTING.
			if serverID != h.cfg.Server {
				if err := h.leases.DropOffer(clientID); err != nil {
					return nil, fmt.Errorf("drop unselected offer: %w", err)
				}
				return nil, nil
			}
			binding, accepted, err = h.leases.Grant(clientID, requestedIP, transactionID)
		case unspecifiedClientIP && !hasServerID && hasRequestedIP: // INIT-REBOOT.
			binding, accepted, err = h.leases.Renew(clientID, requestedIP)
			if err == nil && !accepted && h.cfg.Authoritative {
				known, _, evidenceErr := h.leases.Evidence(clientID, requestedIP)
				if evidenceErr != nil {
					return nil, fmt.Errorf("check lease evidence: %w", evidenceErr)
				}
				if !h.cfg.Subnet.Contains(requestedIP) || known {
					replyType = dhcpv4.MessageTypeNak
					accepted = true
				}
			}
		case !unspecifiedClientIP && !hasServerID && !hasRequestedIP: // RENEWING/REBINDING.
			binding, accepted, err = h.leases.Renew(clientID, clientIP)
		default:
			return h.reject(events.Policy)
		}
		if err == nil && !accepted {
			return h.reject(events.Policy)
		}
	case dhcpv4.MessageTypeRelease:
		if unspecifiedClientIP || hasRequestedIP || !hasServerID || serverID != h.cfg.Server {
			return h.reject(events.Policy)
		}
		accepted, err = h.leases.Release(clientID, clientIP)
		if err != nil {
			return nil, fmt.Errorf("release lease: %w", err)
		}
		if !accepted {
			return h.reject(events.Policy)
		}
		return nil, nil
	case dhcpv4.MessageTypeDecline:
		if !unspecifiedClientIP || !hasServerID || serverID != h.cfg.Server || !hasRequestedIP {
			return h.reject(events.Policy)
		}
		accepted, err = h.leases.Decline(clientID, requestedIP)
		if err != nil {
			return nil, fmt.Errorf("decline lease: %w", err)
		}
		if !accepted {
			return h.reject(events.Policy)
		}
		return nil, nil
	case dhcpv4.MessageTypeInform:
		if unspecifiedClientIP || hasRequestedIP || hasServerID {
			return h.reject(events.Policy)
		}
	default:
		return h.reject(events.Policy)
	}
	if err != nil {
		return nil, fmt.Errorf("update lease state: %w", err)
	}

	modifiers := []dhcpv4.Modifier{
		dhcpv4.WithMessageType(replyType),
		dhcpv4.WithClientIP(packet.ClientIPAddr),
		dhcpv4.WithOption(dhcpv4.OptServerIdentifier(net.IP(h.cfg.Server.AsSlice()))),
	}
	if replyType != dhcpv4.MessageTypeNak {
		modifiers = append(modifiers, dhcpv4.WithNetmask(net.CIDRMask(h.cfg.Subnet.Bits(), 32)))
	}
	if packet.MessageType() != dhcpv4.MessageTypeInform && replyType != dhcpv4.MessageTypeNak {
		modifiers = append(modifiers,
			dhcpv4.WithYourIP(net.IP(binding.Address.AsSlice())),
			dhcpv4.WithLeaseTime(uint32(h.cfg.LeaseDuration/time.Second)), // #nosec G115 -- validated whole seconds <= 365 days
			dhcpv4.WithOption(dhcpv4.OptRenewTimeValue(h.cfg.LeaseDuration/2)),
			dhcpv4.WithOption(dhcpv4.OptRebindingTimeValue(h.cfg.LeaseDuration*7/8)),
		)
	}
	reply, err := dhcpv4.NewReplyFromRequest(packet, modifiers...)
	if err != nil {
		return nil, fmt.Errorf("build reply: %w", err)
	}
	if replyType != dhcpv4.MessageTypeNak {
		h.addRequestedOptions(reply, packet, limit)
	}

	destination := clientIP
	if unspecifiedClientIP || replyType == dhcpv4.MessageTypeNak {
		destination = netip.MustParseAddr("255.255.255.255")
	}
	return &Response{
		Packet:      reply.ToBytes(),
		Destination: destination,
	}, nil
}

// addRequestedOptions omits optional settings that exceed the client's size limit.
func (h *Handler) addRequestedOptions(reply, packet *dhcpv4.DHCPv4, limit int) {
	requested := packet.Options[55]
	wants := func(code byte) bool {
		return len(requested) == 0 || slices.Contains(requested, code)
	}
	if h.cfg.Router.IsValid() && wants(3) {
		reply.UpdateOption(dhcpv4.OptRouter(net.IP(h.cfg.Router.AsSlice())))
		if len(reply.ToBytes()) > limit {
			reply.Options.Del(dhcpv4.OptionRouter)
		}
	}
	if len(h.cfg.DNS) > 0 && wants(6) {
		ips := make([]net.IP, 0, len(h.cfg.DNS))
		for _, address := range h.cfg.DNS {
			ips = append(ips, net.IP(address.AsSlice()))
		}
		reply.UpdateOption(dhcpv4.OptDNS(ips...))
		if len(reply.ToBytes()) > limit {
			reply.Options.Del(dhcpv4.OptionDomainNameServer)
		}
	}
	for _, option := range h.cfg.Options {
		if !wants(option.Code) {
			continue
		}
		code := dhcpv4.GenericOptionCode(option.Code)
		reply.UpdateOption(dhcpv4.OptGeneric(code, option.Value))
		if len(reply.ToBytes()) > limit {
			reply.Options.Del(code)
		}
	}
}
