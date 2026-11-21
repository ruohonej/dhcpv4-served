// Package store provides durable lease snapshots and stable locking.
package store

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// Lock holds an exclusive, non-blocking flock on a stable sidecar inode. The
// caller must retain it for the worker lifetime, across all snapshot renames.
type Lock struct {
	file *os.File
}

// AcquireLock requires an absolute, administrator-selected state directory,
// private to this instance and not writable by other users. Its parent path
// must also be trusted. Neither workers nor cleanup jobs may unlink/replace
// leases.lock while a worker may run. Symlink lock files are rejected.
func AcquireLock(directory string) (*Lock, error) {
	if !filepath.IsAbs(directory) {
		return nil, fmt.Errorf("state directory must be absolute")
	}

	const directoryFlags = unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC | unix.O_NOFOLLOW
	dirFD, err := unix.Open(directory, directoryFlags, 0)
	if err != nil {
		return nil, err
	}
	defer func() { _ = unix.Close(dirFD) }()

	var info unix.Stat_t
	if err := unix.Fstat(dirFD, &info); err != nil {
		return nil, err
	}
	if info.Mode&0o077 != 0 || info.Uid != uint32(os.Geteuid()) { // #nosec G115 -- Linux effective UID is a nonnegative uid_t
		return nil, fmt.Errorf("state directory must be owned by worker and private")
	}

	const lockFlags = unix.O_RDWR | unix.O_CREAT | unix.O_CLOEXEC | unix.O_NOFOLLOW | unix.O_NONBLOCK
	fd, err := unix.Openat(dirFD, "leases.lock", lockFlags, 0o600)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), "leases.lock")
	if err := unix.Fstat(fd, &info); err != nil {
		return nil, errors.Join(err, file.Close())
	}
	privateOwner := info.Mode&0o077 == 0 && info.Uid == uint32(os.Geteuid()) // #nosec G115 -- Linux effective UID is a nonnegative uid_t
	if info.Mode&unix.S_IFMT != unix.S_IFREG || !privateOwner || info.Nlink != 1 {
		return nil, errors.Join(fmt.Errorf("lock must be a private regular file with one link"), file.Close())
	}

	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return nil, errors.Join(fmt.Errorf("state lock: %w", err), file.Close())
	}
	return &Lock{file: file}, nil
}

// Close releases the lock by closing its descriptor. Never unlink the sidecar.
func (l *Lock) Close() error {
	return l.file.Close()
}
