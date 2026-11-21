package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"

	"dhcpv4-served/internal/lease"
)

var ErrIdentity = errors.New("incompatible snapshot")

const maxSnapshotSize = 16 << 20

type snapshot struct {
	Version  int             `json:"version"`
	Instance string          `json:"instance"`
	Network  string          `json:"network"`
	Bindings []lease.Binding `json:"bindings"`
}

// SnapshotStore keeps one instance's durable bindings under a lifetime lock.
type SnapshotStore struct {
	dir      string
	instance string
	network  string
	lock     *Lock
	ops      snapshotOps
}

type snapshotFile interface {
	Name() string
	Chmod(os.FileMode) error
	Write([]byte) (int, error)
	Sync() error
	Close() error
}

type snapshotOps struct {
	createTemp func(string, string) (snapshotFile, error)
	rename     func(string, string) error
	openDir    func(string) (snapshotFile, error)
}

func defaultSnapshotOps() snapshotOps {
	return snapshotOps{
		createTemp: func(dir, pattern string) (snapshotFile, error) { return os.CreateTemp(dir, pattern) },
		rename:     os.Rename,
		openDir: func(dir string) (snapshotFile, error) {
			return os.Open(dir) // #nosec G304 -- trusted private state directory
		},
	}
}

// OpenSnapshot holds the stable lock for the store's lifetime. Network includes
// the server, subnet and pool identity, so incompatible changes fail closed.
func OpenSnapshot(dir, instance, network string) (*SnapshotStore, []lease.Binding, error) {
	lock, err := AcquireLock(dir)
	if err != nil {
		return nil, nil, fmt.Errorf("acquire lease lock: %w", err)
	}
	s := &SnapshotStore{
		dir:      dir,
		instance: instance,
		network:  network,
		lock:     lock,
		ops:      defaultSnapshotOps(),
	}
	bindings, err := s.load()
	if err != nil {
		return nil, nil, errors.Join(fmt.Errorf("load lease snapshot: %w", err), lock.Close())
	}
	return s, bindings, nil
}

func (s *SnapshotStore) Close() error {
	return s.lock.Close()
}

func (s *SnapshotStore) load() ([]lease.Binding, error) {
	const snapshotFlags = unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW | unix.O_NONBLOCK
	fd, err := unix.Open(filepath.Join(s.dir, "leases.json"), snapshotFlags, 0)
	if errors.Is(err, unix.ENOENT) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("open snapshot: %w", err)
	}

	file := os.NewFile(uintptr(fd), "leases.json")
	defer func() { _ = file.Close() }()

	var info unix.Stat_t
	if err := unix.Fstat(fd, &info); err != nil {
		return nil, fmt.Errorf("inspect snapshot: %w", err)
	}
	privateOwner := info.Mode&0o077 == 0 && info.Uid == uint32(os.Geteuid()) // #nosec G115 -- Linux effective UID is a nonnegative uid_t
	if info.Mode&unix.S_IFMT != unix.S_IFREG || !privateOwner || info.Nlink != 1 || info.Size > maxSnapshotSize {
		return nil, errors.New("invalid snapshot file")
	}

	decoder := json.NewDecoder(io.LimitReader(file, maxSnapshotSize))
	decoder.DisallowUnknownFields()
	var snap snapshot
	if err := decoder.Decode(&snap); err != nil {
		return nil, fmt.Errorf("decode snapshot: %w", err)
	}

	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return nil, errors.New("trailing snapshot data")
	}
	if snap.Version != 1 || snap.Instance != s.instance || snap.Network != s.network || snap.Bindings == nil {
		return nil, ErrIdentity
	}
	return snap.Bindings, nil
}

// Save syncs a temporary snapshot before replacing and syncing the directory entry.
func (s *SnapshotStore) Save(bindings []lease.Binding) error {
	if bindings == nil {
		bindings = []lease.Binding{}
	}
	data, err := json.Marshal(snapshot{
		Version:  1,
		Instance: s.instance,
		Network:  s.network,
		Bindings: bindings,
	})
	if err != nil {
		return fmt.Errorf("encode snapshot: %w", err)
	}
	if len(data) > maxSnapshotSize {
		return errors.New("snapshot too large")
	}

	file, err := s.ops.createTemp(s.dir, ".leases-*")
	if err != nil {
		return fmt.Errorf("create temporary snapshot: %w", err)
	}
	name := file.Name()
	defer func() { _ = os.Remove(name) }()
	if err = file.Chmod(0o600); err == nil {
		var n int
		n, err = file.Write(data)
		if err == nil && n != len(data) {
			err = io.ErrShortWrite
		}
	}
	if err == nil {
		if syncErr := file.Sync(); syncErr != nil {
			err = fmt.Errorf("%w: %w", lease.ErrSync, syncErr)
		}
	}
	// Close even after a write/sync failure, while preserving the first error.
	closeErr := file.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return fmt.Errorf("persist snapshot data: %w", err)
	}

	if err := s.ops.rename(name, filepath.Join(s.dir, "leases.json")); err != nil {
		return fmt.Errorf("replace snapshot: %w", err)
	}

	dir, err := s.ops.openDir(s.dir)
	if err != nil {
		return fmt.Errorf("open state directory: %w", err)
	}
	defer func() { _ = dir.Close() }()
	if err := dir.Sync(); err != nil {
		return fmt.Errorf("sync state directory: %w: %w", lease.ErrSync, err)
	}
	return nil
}
