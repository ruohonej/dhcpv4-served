# Technical specification

`dhcpv4-served` serves one directly connected IPv4 subnet per worker. The systemd instance name selects the interface, YAML file and private state directory. Each worker has its own pool, lease ownership, socket and link monitor. The host provisions the interface, addresses, routes and any services advertised in replies. The implementation supports Ethernet and VLAN links. Relays, multiple subnets per interface, DHCPv6, static reservations, live reload, and shared lease storage are outside its scope.

## Configuration and startup

`dhcpv4-served validate FILE...` accepts one YAML document per regular file (up to 1 MiB), rejects unknown fields, and checks for overlapping pools across the supplied files. It can run without a listener or a configured interface. Installed path permissions, live subnet compatibility, and recovered state are checked when the worker starts.

| Setting | Worker behavior |
| --- | --- |
| `pool.start`, `pool.end` | Required inclusive IPv4 range, in ascending order. Both endpoints must be usable on the interface subnet. |
| `lease_duration`, `offer_duration`, `decline_duration` | Required whole-second intervals from one second through 365 days. They control the granted lease, transient hold, and conflict quarantine, respectively. |
| `excluded_addresses` | Distinct addresses within the pool. The allocator also skips the server and every configured router. Network and broadcast addresses are outside the usable range. |
| `authoritative` | Defaults to false. Enable only when the operator authorizes this server to invalidate incorrect client configuration on this link. Its effect is confined to INIT-REBOOT below. |
| `router`, `dns_servers`, `options` | Optional settings advertised to clients. Choose one spelling for the router option. Configured routers must be on-link. The subnet mask comes from the interface. An explicit broadcast address must match that subnet. |

`dhcpv4-srvctl init --interface IFACE` discovers the link and writes a trusted configuration when absent. The pool spans the usable subnet excluding the server. The server is advertised as router, lease, offer and decline durations are 12 hours, 60 seconds and 10 minutes, and authoritative mode is off. The utility snapshots usable DNS servers from systemd-resolved and omits DNS if discovery fails. The operator must ensure the entire pool is available and the advertised services are reachable. The worker requires a trusted configuration file.

`dhcpv4-srvctl refresh --interface IFACE` updates an existing trusted configuration using the current link and resolver. It retains pool bounds, router and other settings, and replaces DNS with the discovered list, including an empty list. A discovery failure retains the existing DNS list. It validates retained settings against the new link before replacing the file. Refresh commands take an exclusive `flock` on the configuration directory. Concurrent manual writers must use the same lock. Stop the instance before refreshing and review the result and persistence rules before rearming.

The option definitions specify the accepted names, value types, and RFC sections. The same YAML can advertise routes, resolvers, time sources, or boot parameters without running any of those services. [Option definitions](internal/config/options.go)

The socket unit binds `0.0.0.0:67` to the selected device and enables broadcast and packet information **before** the first datagram queues. The worker accepts exactly one systemd descriptor named `dhcp`, an unconnected IPv4 UDP socket matching that address, port, and interface. It never creates a fallback listener. [Socket unit](deploy/systemd/dhcpv4-served@.socket) · [Descriptor checks](internal/activation/activation_linux.go)

The service loads trusted configuration, checks its launch privileges, subscribes to route netlink, and discovers an up Ethernet interface with exactly one IPv4 address on a /1 through /30 subnet. It checks the pool against that link, locks and recovers state, adopts the socket, and applies the selected sandbox before emitting `worker.ready`. Readiness is a worker journal event. A listening socket alone establishes only that the manager has armed it. [Startup](cmd/dhcpv4-served/main_linux.go) · [Service unit](deploy/systemd/dhcpv4-served@.service)

## Ingress and link identity

Each datagram must come from UDP port 68 with exactly one intact `IP_PKTINFO` record for the original interface index. Truncated data or control messages are discarded. The worker drains queued link events and revalidates the original identity before receiving and again before sending. A relevant link or address event, replacement even with identical attributes, malformed event stream, or lost monitor history stops that instance. Planned link changes require stopping it first because the final revalidation and transmission are separate operations. [Link monitor](internal/transport/link_linux.go)

The parser bounds DHCP payloads to 240–1500 bytes. The handler accepts Ethernet BOOTREQUESTs with a six-byte, nonzero unicast client hardware address, zero relay address and hops, and no reserved flag bits. The DHCP library parses and concatenates fragments in the main options field. The main field must contain END, and bytes after END are ignored. Option overload is unsupported: packets containing option 52 are rejected because the library does not decode options in the file and sname fields. Invalid fixed-length options and a client maximum size below 576 are rejected. Option 61, if present, must contain 2–1024 bytes after concatenation. [Parser](internal/protocol/packet.go) · [RFC 3396](specs/rfc3396.txt)

## Allocation and replies

Ownership is scoped to the worker and keyed by opaque option 61 when present, otherwise by the Ethernet address. A transaction ID matches a pending offer. It is unnecessary for reclaiming an already committed lease. The allocator reuses a client's live lease or offer first, then tries an eligible free requested address, then scans upward from the pool start. Repeated discovery updates the offer's transaction without extending its deadline. The pool relies on administrative exclusions and client DECLINEs for conflicts. The worker does no active ARP probing.

| Client message | Decision after input validation |
| --- | --- |
| DISCOVER | With zero `ciaddr` and no server identifier, return OFFER for the selected address. Exhaustion or the limit of 128 outstanding offers suppresses a new hold. |
| REQUEST, SELECTING | With zero `ciaddr`, a selected server and requested address, ACK a matching live offer (client, address, transaction) or the client's committed lease at that address. Selecting another server drops the client's transient offer silently. A lost offer after restart requires fresh discovery. |
| REQUEST, INIT-REBOOT | With zero `ciaddr`, requested address and no server identifier, renew and ACK a matching committed lease. In authoritative mode, broadcast NAK for an off-subnet request or a client with a live lease requesting a different address. An unknown client requesting an on-subnet address always gets silence, even if someone else holds it. Other mismatches are silent. |
| REQUEST, RENEWING or REBINDING | With nonzero `ciaddr` and neither requested address nor server identifier, renew and ACK only the client's committed lease at `ciaddr`. |
| RELEASE / DECLINE | Both must name this server. RELEASE removes the client's live lease at `ciaddr`. DECLINE requires zero `ciaddr` and a requested address matching the client's live offer or lease. It commits a quarantine for the configured duration. Both complete silently. |
| INFORM | With nonzero `ciaddr` and neither requested address nor server identifier, ACK with applicable configuration. Leaves lease ownership and expiry alone. |

Contradictory request forms and unsupported message types get no reply. Addressless clients receive limited broadcast even with the broadcast flag clear. Every NAK is broadcast. Other replies go to `ciaddr` on UDP/68, using the original interface and server source address. Lease-bearing replies carry the lease duration and T1/T2 derived at one-half and seven-eighths of it. The reply echoes a supplied client identifier. Optional settings follow the parameter request list when present and are omitted if they exceed the client's size budget (default 576 bytes, capped at 1500). [Handler](internal/server/handler.go) · [RFC 2131](specs/rfc2131.txt) · [RFC 6842](specs/rfc6842.txt)

Each worker serializes packet processing. After parsing, it admits general work and matching committed-lease renewal requests through separate token buckets, each with 100 requests/second refill and a burst of 100. A matching INIT-REBOOT request also qualifies for renewal capacity. A depleted bucket drops the request before allocation. These limits apply inside the worker, after traffic has reached the host. [Admission](internal/server/admission.go)

## Persistence and recovery

The worker holds an exclusive, nonblocking lock on `leases.lock` for its lifetime. The sidecar stays in place while the worker replaces `leases.json`. Only leases and quarantines enter the snapshot. For each durable change, the store writes a private temporary file in the state directory, syncs and closes it, renames it over the snapshot, and syncs the directory. **A successful commit precedes any ACK granting or extending a lease.** A write or sync failure stops allocation and the worker exits. If sending an ACK fails after commit, ownership survives for the client's retry. [Lease engine](internal/lease/lease.go) · [Snapshot store](internal/store/snapshot_linux.go)

Startup accepts an absent snapshot as an empty pool. An existing snapshot must match the schema, instance, server IP, subnet and pool bounds. Invalid or newly excluded bindings, duplicate addresses or duplicate active leases for one client prevent startup. Changing pool bounds or server identity requires deliberate migration. Keep the private state and lock when updating the binary or repairing an instance.

Expiry uses monotonic elapsed time. A periodic sweep also removes expired records when the link is idle and commits durable removals before reuse. **Every restart reserves each recovered lease and quarantine for its full recorded duration starting at recovery.** Wall timestamps cannot shorten that interval. Repeated restarts can delay reuse enough to exhaust a small pool. Offers disappear on exit because they grant no lease.

If state is lost, uncertain, or being transferred, fence the old allocator before enabling its replacement. Migrate all current leases and quarantines, or withhold the affected pool for the longest proven historical lease or quarantine duration after fencing. If elapsed time becomes uncertain, restart the hold. If the historical bound is unknown, keep the pool offline until ownership is reconciled. Removing a snapshot or restoring an older copy can otherwise reassign an address still in use.

## Operational events

The worker emits schema-v1 JSON lines on the inherited journal stream. Startup and terminal events give a stable event ID and reason. Fixed counters summarize malformed or rejected traffic, pool pressure, and successful sends by minute. The minute heartbeat includes protection mode, pool occupancy (including offers and quarantines), rejection rate and delivery failures. Packet counters start at the worker and exclude kernel drops. Use journald's host, boot, unit and invocation identity to distinguish restarts.

Log delivery is best effort. A blocked output can drop records while DHCP continues. A fallback event marks audit delivery unknown. A fresh heartbeat confirms the worker emitted a sample. To establish continued receipt, monitor the journal or receiver independently. [Event schema and counters](internal/events/events.go) · [Delivery](internal/events/delivery_linux.go) · [Example alert rules](examples/observability/)
