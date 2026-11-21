package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTrustedPath(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "conf")
	if err := os.Mkdir(dir, 0755); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile("../../examples/lan10.yaml")
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "lan.yaml")
	if err := os.WriteFile(file, data, 0644); err != nil {
		t.Fatal(err)
	}
	owner := uint32(os.Getuid())
	load := func(path string, want bool) {
		t.Helper()
		_, err := loadTrustedAt(root, path, owner)
		if (err == nil) != want {
			t.Fatalf("load %s: %v, want success %v", path, err, want)
		}
	}
	load("conf/lan.yaml", true)
	// This checks the trust root. Mixed per-component ownership is exercised
	// with real chown operations in the mapped startup and systemd suites.
	if _, err := loadTrustedAt(root, "conf/lan.yaml", owner+1); err == nil {
		t.Fatal("accepted untrusted root owner")
	}
	if err := os.Chmod(file, 0664); err != nil {
		t.Fatal(err)
	}
	load("conf/lan.yaml", false)
	if err := os.Chmod(file, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0775); err != nil {
		t.Fatal(err)
	}
	load("conf/lan.yaml", false)
	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("lan.yaml", filepath.Join(dir, "link.yaml")); err != nil {
		t.Fatal(err)
	}
	load("conf/link.yaml", false)
	if err := os.Symlink("conf", filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	load("link/lan.yaml", false)
	load("conf/../conf/lan.yaml", false)
	if err := os.WriteFile(file, []byte(strings.Repeat(" ", (1<<20)+1)), 0644); err != nil {
		t.Fatal(err)
	}
	load("conf/lan.yaml", false)
}

func TestTrustedPathRequiresAbsoluteCleanPath(t *testing.T) {
	for _, path := range []string{"", "relative.yaml", "/etc/../etc/config.yaml", "/"} {
		if _, err := LoadTrusted(path); err == nil {
			t.Errorf("accepted %q", path)
		}
	}
}

// Concurrent replacement must either fail closed or decode the checked inode,
// never the file targeted by a substituted symlink.
func TestTrustedPathSymlinkSwap(t *testing.T) {
	root := t.TempDir()
	good, err := os.ReadFile("../../examples/lan10.yaml")
	if err != nil {
		t.Fatal(err)
	}
	other, err := os.ReadFile("../../examples/lan20.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "other"), other, 0644); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "config")
	if err := os.WriteFile(path, good, 0644); err != nil {
		t.Fatal(err)
	}
	expected, err := loadTrustedAt(root, "config", uint32(os.Getuid()))
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		for i := 0; i < 1000; i++ {
			tmp := filepath.Join(root, "next")
			if err := os.Symlink("other", tmp); err != nil {
				done <- err
				return
			}
			if err := os.Rename(tmp, path); err != nil {
				done <- err
				return
			}
			if err := os.WriteFile(tmp, good, 0644); err != nil {
				done <- err
				return
			}
			if err := os.Rename(tmp, path); err != nil {
				done <- err
				return
			}
		}
		done <- nil
	}()
	for i := 0; i < 2000; i++ {
		cfg, err := loadTrustedAt(root, "config", uint32(os.Getuid()))
		if err == nil && cfg.Pool != expected.Pool {
			t.Errorf("loaded substituted target: %v", cfg.Pool)
			break
		}
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestTrustedMissingAndInvalidAreDistinct(t *testing.T) {
	root := t.TempDir()
	owner := uint32(os.Getuid())
	if err := os.Mkdir(filepath.Join(root, "conf"), 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := loadTrustedAt(root, "conf/missing.yaml", owner); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing: %v", err)
	}
	if _, err := loadTrustedAt(root, "missing/config.yaml", owner); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing directory: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "conf", "bad.yaml"), []byte("invalid: true\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadTrustedAt(root, "conf/bad.yaml", owner); err == nil || errors.Is(err, os.ErrNotExist) {
		t.Fatalf("invalid: %v", err)
	}
	if err := os.Symlink("missing.yaml", filepath.Join(root, "conf", "link.yaml")); err != nil {
		t.Fatal(err)
	}
	if _, err := loadTrustedAt(root, "conf/link.yaml", owner); err == nil || errors.Is(err, os.ErrNotExist) {
		t.Fatalf("dangling symlink: %v", err)
	}
}
