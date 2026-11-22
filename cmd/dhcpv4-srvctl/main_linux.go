// dhcpv4-srvctl provisions configuration for the DHCP worker.
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
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
		info, err := os.Stat(current)
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
	if len(args) == 0 || args[0] != "init" {
		return fmt.Errorf("usage: dhcpv4-srvctl init --interface IFACE")
	}
	flags := flag.NewFlagSet("init", flag.ContinueOnError)
	iface := flags.String("interface", "", "interface to configure")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 || *iface == "" || *iface == "." || *iface == ".." || strings.ContainsAny(*iface, "/\\") {
		return fmt.Errorf("invalid interface name")
	}
	path := filepath.Join("/etc/dhcpv4-served", *iface+".yaml")
	if cfg, err := loadExisting(path); err == nil {
		fmt.Printf("Configuration already exists at %s\n%+v\n", path, cfg)
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("load existing configuration: %w", err)
	}
	link, err := transport.Discover(*iface)
	if err != nil {
		return fmt.Errorf("discover interface: %w", err)
	}
	dns := hostservices.Discover()
	cfg, err := config.Default(link.IP, link.Subnet, dns)
	if err != nil {
		return fmt.Errorf("derive configuration: %w", err)
	}
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("encode configuration: %w", err)
	}
	dirPath := filepath.Dir(path)
	if _, err := os.Lstat(dirPath); errors.Is(err, os.ErrNotExist) {
		tempDir, err := os.MkdirTemp(filepath.Dir(dirPath), ".dhcpv4-served-")
		if err != nil {
			return err
		}
		defer func() { _ = os.Remove(tempDir) }()
		if err := os.Chmod(tempDir, 0755); err != nil {
			return err
		} // #nosec G302 -- worker needs directory access
		if err := unix.Renameat2(unix.AT_FDCWD, tempDir, unix.AT_FDCWD, dirPath, unix.RENAME_NOREPLACE); err != nil && !errors.Is(err, os.ErrExist) {
			return err
		}
	} else if err != nil {
		return err
	}
	// Check the directory chain through the same trusted loader before writing.
	_, err = loadExisting(path)
	if err == nil {
		fmt.Printf("Configuration already exists at %s\n", path)
		return nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("check configuration path: %w", err)
	}
	if err := checkWorkerAccess(dirPath, false); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".srvctl-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
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
	if err := os.Link(tmp.Name(), path); err != nil {
		if errors.Is(err, os.ErrExist) {
			if _, loadErr := loadExisting(path); loadErr != nil {
				return fmt.Errorf("load existing configuration: %w", loadErr)
			}
			fmt.Printf("Configuration already exists at %s\n", path)
			return nil
		}
		return fmt.Errorf("install configuration: %w", err)
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	err = dir.Sync()
	closeErr = dir.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	fmt.Printf("Created %s\nPool: %s - %s\nRouter: %s\nDNS: %v\nThe whole usable subnet must be available on an isolated link.\n", path, cfg.Pool.Start, cfg.Pool.End, cfg.Router, cfg.DNS)
	if len(dns) == 0 {
		fmt.Println("No usable DNS servers discovered; DNS omitted.")
	}
	return nil
}
