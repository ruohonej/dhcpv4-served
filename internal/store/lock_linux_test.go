package store

import (
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

func TestLockSurvivesSnapshotReplacementAndExit(t *testing.T) {
	if dir := os.Getenv("DHCP_LOCK_TEST_DIR"); dir != "" {
		lock, err := AcquireLock(dir)
		if err != nil {
			t.Fatal(err)
		}
		// Deliberately leave the descriptor open: process exit must release flock.
		os.Stdout.WriteString("locked\n")
		var b [1]byte
		os.Stdin.Read(b[:])
		runtime.KeepAlive(lock)
		os.Exit(0)
	}
	dir := t.TempDir()
	os.Chmod(dir, 0700)
	cmd := exec.Command(os.Args[0], "-test.run=^TestLockSurvivesSnapshotReplacementAndExit$")
	cmd.Env = append(os.Environ(), "DHCP_LOCK_TEST_DIR="+dir)
	input, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	output, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	var b [7]byte
	if n, err := io.ReadFull(output, b[:]); err != nil || string(b[:n]) != "locked\n" {
		t.Fatalf("child startup: %q %v", b, err)
	}
	for i := 0; i < 3; i++ {
		temp := filepath.Join(dir, "new.json")
		if err := os.WriteFile(temp, []byte(`{"leases":[]}`), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(temp, filepath.Join(dir, "leases.json")); err != nil {
			t.Fatal(err)
		}
		if l, err := AcquireLock(dir); err == nil {
			l.Close()
			t.Fatal("second worker acquired lock after rename")
		}
	}
	input.Close()
	if err := cmd.Wait(); err != nil {
		t.Fatal(err)
	}
	l, err := AcquireLock(dir)
	if err != nil {
		t.Fatalf("not released on exit: %v", err)
	}
	l.Close()
	if _, err := os.Stat(filepath.Join(dir, "leases.lock")); err != nil {
		t.Fatal("lock file removed")
	}
}

func TestLockRejectsUnsafePaths(t *testing.T) {
	dir := t.TempDir()
	os.Chmod(dir, 0700)
	target := filepath.Join(dir, "target")
	os.WriteFile(target, nil, 0600)
	os.Symlink(target, filepath.Join(dir, "leases.lock"))
	if l, err := AcquireLock(dir); err == nil {
		l.Close()
		t.Fatal("accepted symlink")
	}
	os.Remove(filepath.Join(dir, "leases.lock"))
	os.Chmod(dir, 0777)
	if l, err := AcquireLock(dir); err == nil {
		l.Close()
		t.Fatal("accepted shared directory")
	}
	if l, err := AcquireLock("relative"); err == nil {
		l.Close()
		t.Fatal("accepted relative path")
	}
}
