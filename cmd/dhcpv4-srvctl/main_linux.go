// dhcpv4-srvctl provisions configuration for the DHCP worker.
package main

import (
	"errors"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"dhcpv4-served/internal/config"
	"dhcpv4-served/internal/hostservices"
	"dhcpv4-served/internal/transport"
	"golang.org/x/sys/unix"
	"gopkg.in/yaml.v3"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// checkWorkerAccess checks permissions for an unrelated dynamic service user.
func checkWorkerAccess(path string, file bool) error {
	for current := path; ; current = filepath.Dir(current) {
		info, err := os.Stat(current) // #nosec G703 -- caller supplies a validated configuration path
		if err != nil {
			return err
		}
		required := os.FileMode(0005)
		if current == path && file {
			required = 0004
		}
		if info.Mode().Perm()&required != required {
			return fmt.Errorf("worker cannot access %s", current)
		}
		if current == "/" {
			return nil
		}
	}
}

func loadExisting(path string) (config.Config, error) {
	cfg, err := config.LoadTrusted(path)
	if err != nil {
		return cfg, err
	}
	if err := checkWorkerAccess(path, true); err != nil {
		return cfg, err
	}
	return cfg, nil
}

func run(args []string) error {
	if len(args) == 0 || (args[0] != "init" && args[0] != "refresh") {
		return fmt.Errorf("usage: dhcpv4-srvctl {init|refresh} --interface IFACE")
	}
	refresh := args[0] == "refresh"
	flags := flag.NewFlagSet(args[0], flag.ContinueOnError)
	iface := flags.String("interface", "", "interface to configure")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 || *iface == "" || *iface == "." || *iface == ".." || strings.ContainsAny(*iface, "/\\") {
		return fmt.Errorf("invalid interface name")
	}
	path := filepath.Join("/etc/dhcpv4-served", *iface+".yaml")
	existing, loadErr := loadExisting(path)
	if loadErr == nil && !refresh {
		if err := syncDirectory("/etc"); err != nil {
			return err
		}
		fmt.Printf("Configuration already exists at %s\n%+v\n", path, existing)
		return nil
	}
	if loadErr != nil && (refresh || !errors.Is(loadErr, os.ErrNotExist)) {
		return fmt.Errorf("load existing configuration: %w", loadErr)
	}
	if refresh {
		dir, err := os.Open(filepath.Dir(path)) // #nosec G703 -- path uses a validated interface name
		if err != nil {
			return err
		}
		defer func() { _ = dir.Close() }()
		if err := unix.Flock(int(dir.Fd()), unix.LOCK_EX); err != nil {
			return fmt.Errorf("lock configuration directory: %w", err)
		}
		existing, err = loadExisting(path)
		if err != nil {
			return fmt.Errorf("load existing configuration: %w", err)
		}
	}
	link, err := transport.Discover(*iface)
	if err != nil {
		return fmt.Errorf("discover interface: %w", err)
	}
	dns, dnsErr := hostservices.DiscoverDNS()
	var cfg config.Config
	if refresh {
		cfg = refreshedConfig(existing, dns, dnsErr)
		cfg.Options = make(map[string]yaml.Node, len(existing.Options))
		for name, node := range existing.Options {
			cfg.Options[name] = resolveAliases(node)
		}
		if err := cfg.ValidateLink(link.IP, link.Subnet); err != nil {
			return fmt.Errorf("validate refreshed configuration: %w", err)
		}
	} else {
		cfg, err = config.Default(link.IP, link.Subnet, dns)
		if err != nil {
			return fmt.Errorf("derive configuration: %w", err)
		}
	}
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("encode configuration: %w", err)
	}
	dirPath := filepath.Dir(path)
	if _, err := os.Lstat(dirPath); errors.Is(err, os.ErrNotExist) { // #nosec G703 -- interface cannot contain path separators
		tempDir, err := os.MkdirTemp(filepath.Dir(dirPath), ".dhcpv4-served-")
		if err != nil {
			return err
		}
		defer func() { _ = os.Remove(tempDir) }()       // #nosec G703 -- path was created by MkdirTemp under /etc
		if err := os.Chmod(tempDir, 0755); err != nil { // #nosec G302 G703 -- worker needs access to the created directory
			return err
		}
		if err := unix.Renameat2(unix.AT_FDCWD, tempDir, unix.AT_FDCWD, dirPath, unix.RENAME_NOREPLACE); err != nil && !errors.Is(err, os.ErrExist) {
			return err
		}
	} else if err != nil {
		return err
	}
	if err := syncDirectory(filepath.Dir(dirPath)); err != nil {
		return err
	}
	// Check the directory chain through the same trusted loader before writing.
	current, err := loadExisting(path)
	if refresh && err != nil {
		return fmt.Errorf("check configuration path: %w", err)
	}
	if refresh && !reflect.DeepEqual(existing, current) {
		return fmt.Errorf("configuration changed during refresh")
	}
	if err == nil && !refresh {
		fmt.Printf("Configuration already exists at %s\n", path)
		return nil
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("check configuration path: %w", err)
	}
	if err := checkWorkerAccess(dirPath, false); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".srvctl-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }() // #nosec G703 -- path was created by CreateTemp in the trusted directory
	if err = tmp.Chmod(0644); err == nil {
		_, err = tmp.Write(data)
	}
	if err == nil {
		err = tmp.Sync()
	}
	closeErr := tmp.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if refresh {
		if _, err := config.Load(tmp.Name()); err != nil {
			return fmt.Errorf("validate encoded configuration: %w", err)
		}
		current, err = loadExisting(path)
		if err != nil {
			return fmt.Errorf("check configuration before install: %w", err)
		}
		if !reflect.DeepEqual(existing, current) {
			return fmt.Errorf("configuration changed during refresh")
		}
		err = os.Rename(tmp.Name(), path) // #nosec G703 -- destination uses a validated interface name
	} else {
		err = os.Link(tmp.Name(), path)
	}
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			if _, loadErr := loadExisting(path); loadErr != nil {
				return fmt.Errorf("load existing configuration: %w", loadErr)
			}
			fmt.Printf("Configuration already exists at %s\n", path)
			return nil
		}
		return fmt.Errorf("install configuration: %w", err)
	}
	if err := syncDirectory(filepath.Dir(path)); err != nil {
		return err
	}
	action := "Created"
	if refresh {
		action = "Refreshed"
	}
	fmt.Printf("%s %s\nPool: %s - %s\nRouter: %s\nDNS: %v\nThe whole usable subnet must be available on an isolated link.\n", action, path, cfg.Pool.Start, cfg.Pool.End, cfg.Router, cfg.DNS)
	if dnsErr != nil && refresh {
		fmt.Println("DNS discovery failed; existing DNS settings retained.")
	} else if len(dns) == 0 {
		fmt.Println("No usable DNS servers discovered.")
	}
	return nil
}

func refreshedConfig(existing config.Config, dns []netip.Addr, discoveryErr error) config.Config {
	if discoveryErr == nil {
		existing.DNS = dns
	}
	return existing
}

func resolveAliases(node yaml.Node) yaml.Node {
	if node.Kind == yaml.AliasNode && node.Alias != nil {
		node = *node.Alias
	}
	node.Anchor = ""
	children := make([]*yaml.Node, len(node.Content))
	for i, child := range node.Content {
		resolved := resolveAliases(*child)
		children[i] = &resolved
	}
	node.Content = children
	return node
}

func syncDirectory(path string) error {
	dir, err := os.Open(path) // #nosec G304 G703 -- caller supplies the configuration directory or its parent
	if err != nil {
		return err
	}
	err = dir.Sync()
	closeErr := dir.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return nil
}
