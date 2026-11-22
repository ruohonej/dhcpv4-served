// dhcpv4-served is a Linux-only socket-activated DHCPv4 worker.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"runtime/debug"
	"syscall"
	"time"

	"dhcpv4-served/internal/activation"
	"dhcpv4-served/internal/config"
	"dhcpv4-served/internal/events"
	"dhcpv4-served/internal/lease"
	"dhcpv4-served/internal/privilege"
	"dhcpv4-served/internal/protocol"
	"dhcpv4-served/internal/sandbox"
	"dhcpv4-served/internal/server"
	"dhcpv4-served/internal/store"
	"dhcpv4-served/internal/transport"
)

// version is set by the release build. Local builds use Go VCS metadata.
var version string
var buildSHA string

func revision() string {
	if buildSHA != "" {
		return buildSHA
	}
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, s := range info.Settings {
			if s.Key == "vcs.revision" {
				return s.Value
			}
		}
	}
	return "unknown"
}

func currentVersion() string {
	if version != "" {
		return version
	}
	if sha := revision(); sha != "unknown" && len(sha) >= 7 {
		return "v0.0.0-" + sha[:7]
	}
	return "v0.0.0"
}

func main() {
	if err := run(); err != nil {
		os.Exit(1)
	}
}

func run() error {
	if len(os.Args) > 1 && os.Args[1] == "validate" {
		err := validateConfigs(os.Args[2:])
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
		return err
	}

	flags := flag.NewFlagSet("dhcpv4-served", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	securityProfile := flags.String("security-profile", sandbox.Strict, "security policy: strict or lab-best-effort")
	showVersion := flags.Bool("version", false, "print version and exit")
	configPath := flags.String("config", "", "DHCP YAML configuration")
	iface := flags.String("interface", "", "externally configured interface")
	stateDir := flags.String("state-dir", "", "private state directory")
	parseErr := flags.Parse(os.Args[1:])
	if errors.Is(parseErr, flag.ErrHelp) {
		flags.SetOutput(os.Stdout)
		flags.PrintDefaults()
		return nil
	}
	audit := events.NewWorker(*iface, revision(), os.Stderr, os.Stdout, time.Now)
	defer audit.Close()
	// Error causes can contain paths, packet data and YAML values. Only stable
	// classifications cross the journal boundary.
	fail := func(id, reason string, err error) error {
		audit.Logger().Error(id, "reason", reason, "result", "stopped", "count", 1)
		return err
	}
	if parseErr != nil {
		return fail("startup.rejected", "arguments", parseErr)
	}
	if *showVersion {
		fmt.Println(currentVersion())
		return nil
	}
	if flags.NArg() != 0 || *configPath == "" || *iface == "" || *stateDir == "" {
		return fail("startup.rejected", "arguments", fmt.Errorf("usage: dhcpv4-served --config FILE --interface IFACE --state-dir DIR"))
	}

	if err := sandbox.ValidateProfile(*securityProfile); err != nil {
		return fail("startup.rejected", "profile", fmt.Errorf("validate security profile: %w", err))
	}

	cfg, err := config.LoadTrusted(*configPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fail("startup.rejected", "config_missing", fmt.Errorf("configuration missing; run dhcpv4-srvctl init --interface %s: %w", *iface, err))
		}
		reason := "config"
		if errors.Is(err, config.ErrFileAccess) {
			reason = "config_file"
		}
		if errors.Is(err, config.ErrDirectoryAccess) {
			reason = "config_directory"
		}
		return fail("startup.rejected", reason, fmt.Errorf("load configuration: %w", err))
	}
	if err := privilege.Check(); err != nil {
		return fail("startup.rejected", "privilege", fmt.Errorf("check launch privileges: %w", err))
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	monitor, err := transport.OpenMonitor(*iface)
	if err != nil {
		reason := "link"
		if errors.Is(err, transport.ErrAddressCount) {
			reason = "link_addresses"
		}
		return fail("startup.rejected", reason, fmt.Errorf("watch interface: %w", err))
	}
	defer func() { _ = monitor.Close() }()

	link := monitor.Link()
	if err := cfg.ValidateLink(link.IP, link.Subnet); err != nil {
		return fail("startup.rejected", "config_link", fmt.Errorf("validate configuration against interface: %w", err))
	}

	identity := fmt.Sprintf("%s|%s|%s|%s", link.IP, link.Subnet, cfg.Pool.Start, cfg.Pool.End)
	db, recovered, err := store.OpenSnapshot(*stateDir, *iface, identity)
	if err != nil {
		reason := "open"
		if errors.Is(err, os.ErrPermission) {
			reason = "permission"
		}
		if errors.Is(err, store.ErrIdentity) {
			reason = "identity"
		}
		return fail("state.failed", reason, fmt.Errorf("open lease state: %w", err))
	}
	defer func() { _ = db.Close() }()

	options, err := cfg.EncodedOptions()
	if err != nil {
		return fail("startup.rejected", "config", fmt.Errorf("encode DHCP options: %w", err))
	}

	// Server and router addresses must never be allocated to clients.
	excluded := map[netip.Addr]bool{link.IP: true}
	if cfg.Router.IsValid() {
		excluded[cfg.Router] = true
	}
	for _, addr := range cfg.Excluded {
		excluded[addr] = true
	}
	const routerOptionCode = 3 // RFC 2132, section 3.5.
	for _, option := range options {
		if option.Code != routerOptionCode {
			continue
		}
		// EncodedOptions validates that router values contain whole IPv4 addresses.
		for i := 0; i < len(option.Value); i += net.IPv4len {
			addr, _ := netip.AddrFromSlice(option.Value[i : i+net.IPv4len])
			excluded[addr] = true
		}
	}

	engine, err := lease.New(db, audit.Logger(), time.Now, lease.Config{
		Instance:        *iface,
		Start:           cfg.Pool.Start,
		End:             cfg.Pool.End,
		Excluded:        excluded,
		OfferDuration:   cfg.OfferDuration,
		LeaseDuration:   cfg.LeaseDuration,
		DeclineDuration: cfg.DeclineDuration,
	}, recovered)
	if err != nil {
		return fail("state.failed", "identity", fmt.Errorf("recover lease state: %w", err))
	}
	handler := server.New(engine, time.Now, server.Config{
		OnReject:      audit.Count,
		Server:        link.IP,
		Subnet:        link.Subnet,
		LeaseDuration: cfg.LeaseDuration,
		Router:        cfg.Router,
		DNS:           cfg.DNS,
		Authoritative: cfg.Authoritative,
		Options:       options,
	})

	udp, err := activation.Adopt(*iface)
	if err != nil {
		reason := "activation"
		if errors.Is(err, activation.ErrDevice) {
			reason = "activation_device"
		}
		return fail("startup.rejected", reason, fmt.Errorf("adopt activated socket: %w", err))
	}
	defer func() { _ = udp.Close() }()

	conn := transport.New(udp, link)

	if err := sandbox.Restrict(*securityProfile, *stateDir); err != nil {
		reason := "protection"
		if errors.Is(err, sandbox.ErrABI) {
			reason = "abi_missing"
		}
		return fail("startup.rejected", reason, fmt.Errorf("sandbox worker: %w", err))
	}

	audit.Ready(*securityProfile == sandbox.LabBestEffort)
	buf := make([]byte, 1500)
	return serve(ctx, engine, time.Now, func(deadline time.Time) error {
		audit.Tick(time.Now(), engine.PoolUsedPercent)
		if err := monitor.Check(); err != nil {
			return fail("worker.stopped", "link", fmt.Errorf("interface monitor: %w", err))
		}
		if err := udp.SetReadDeadline(deadline); err != nil {
			return fail("worker.stopped", "receive", fmt.Errorf("set read deadline: %w", err))
		}
		n, err := conn.Read(buf)
		if err != nil {
			if errors.Is(err, transport.ErrSourcePort) {
				audit.Count(events.SourcePort)
				return nil
			}
			if errors.Is(err, transport.ErrInvalidPacket) {
				audit.Count(events.Ingress)
				return nil
			}
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				return nil
			}
			if errors.Is(err, transport.ErrLink) {
				return fail("worker.stopped", "link", err)
			}
			return fail("worker.stopped", "receive", fmt.Errorf("receive request: %w", err))
		}

		return processPacket(handler, audit, buf[:n], func(reply *server.Response) error {
			if err := monitor.Check(); err != nil {
				return fail("worker.stopped", "link", fmt.Errorf("interface monitor: %w", err))
			}
			if err := conn.Send(reply.Packet, reply.Destination); err != nil {
				if errors.Is(err, transport.ErrLink) {
					return fail("worker.stopped", "link", err)
				}
				return fail("worker.stopped", "send", fmt.Errorf("send reply: %w", err))
			}
			return nil
		})
	})
}

// processPacket keeps normal no-reply operations silent and counts a reply
// only after delivery to the inherited UDP socket succeeds.
func processPacket(handler *server.Handler, audit *events.Recorder, data []byte, send func(*server.Response) error) error {
	reply, err := handler.Reply(data)
	switch {
	case errors.Is(err, lease.ErrExhausted):
		audit.Count(events.Exhausted)
	case errors.Is(err, protocol.ErrMalformedPacket), errors.Is(err, lease.ErrInvalidIdentity):
		audit.Count(events.Malformed)
	case err != nil:
		if !errors.Is(err, lease.ErrStorage) {
			audit.Logger().Error("worker.stopped", "reason", "handler", "result", "stopped", "count", 1)
		}
		return fmt.Errorf("handle request: %w", err)
	case reply != nil:
		if err := send(reply); err != nil {
			return err
		}
		audit.Count(events.Sent)
	}
	return nil
}

// serve serializes expiry with packet handling. Read deadlines wake an idle
// worker by the next sweep, and the injected clock permits deterministic tests
// of the same loop used in production. Production time.Now retains monotonic time.
func serve(ctx context.Context, engine *lease.Engine, now func() time.Time, step func(time.Time) error) error {
	nextSweep := now().Add(time.Minute)
	for {
		if ctx.Err() != nil {
			return nil
		}
		current := now()
		if !current.Before(nextSweep) {
			if err := engine.Sweep(); err != nil {
				return fmt.Errorf("sweep lease state: %w", err)
			}
			nextSweep = current.Add(time.Minute)
		}
		deadline := now().Add(100 * time.Millisecond)
		if nextSweep.Before(deadline) {
			deadline = nextSweep
		}
		if err := step(deadline); err != nil {
			return err
		}
	}
}

func validateConfigs(paths []string) error {
	if len(paths) == 0 {
		return fmt.Errorf("usage: dhcpv4-served validate FILE [FILE...]")
	}

	configs := make([]config.Config, 0, len(paths))
	for _, path := range paths {
		cfg, err := config.Load(path)
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		configs = append(configs, cfg)
	}
	if err := config.ValidateMultiple(configs); err != nil {
		return fmt.Errorf("validate configurations: %w", err)
	}
	return nil
}
