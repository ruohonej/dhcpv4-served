package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

var (
	ErrFileAccess      = errors.New("untrusted configuration file")
	ErrDirectoryAccess = errors.New("untrusted configuration directory")
)

// LoadTrusted loads an installed configuration through root-owned, protected
// directories. Each component is opened without following symlinks; the same
// opened file that is checked is decoded. Paths must be absolute and clean.
func LoadTrusted(path string) (Config, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" {
		return Config{}, fmt.Errorf("trusted configuration path must be absolute and clean")
	}
	return loadTrustedAt("/", strings.TrimPrefix(path, "/"), 0)
}

// root and owner are parameters to allow unprivileged tests of the contract.
func loadTrustedAt(root, path string, owner uint32) (Config, error) {
	fd, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return Config{}, fmt.Errorf("open trusted root: %w", err)
	}
	dir := os.NewFile(uintptr(fd), root)
	defer func() { _ = dir.Close() }()
	if err := checkTrusted(fd, owner, true); err != nil {
		return Config{}, err
	}
	parts := strings.Split(path, "/")
	for i, part := range parts {
		if part == "" || part == "." || part == ".." {
			return Config{}, fmt.Errorf("invalid path component")
		}
		isDir := i < len(parts)-1
		flags := unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW | unix.O_NONBLOCK
		if isDir {
			flags |= unix.O_DIRECTORY
		}
		next, err := unix.Openat(int(dir.Fd()), part, flags, 0)
		if err != nil {
			return Config{}, fmt.Errorf("open configuration component %q: %w", part, err)
		}
		file := os.NewFile(uintptr(next), part)
		if err := checkTrusted(next, owner, isDir); err != nil {
			_ = file.Close()
			return Config{}, fmt.Errorf("configuration component %q: %w", part, err)
		}
		if !isDir {
			defer func() { _ = file.Close() }()
			return loadFile(file)
		}
		_ = dir.Close()
		dir = file
	}
	return Config{}, fmt.Errorf("missing configuration file")
}

func checkTrusted(fd int, owner uint32, directory bool) error {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return err
	}
	kind := uint32(unix.S_IFREG)
	kindName := "a regular file"
	if directory {
		kind = unix.S_IFDIR
		kindName = "a directory"
	}
	if st.Mode&unix.S_IFMT != kind || st.Uid != owner || st.Mode&0022 != 0 {
		cause := ErrFileAccess
		if directory {
			cause = ErrDirectoryAccess
		}
		return fmt.Errorf(
			"%w: must be %s owned by uid %d and not group/other writable",
			cause,
			kindName,
			owner,
		)
	}
	return nil
}
