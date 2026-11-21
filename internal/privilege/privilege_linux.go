// Package privilege verifies the privileges supplied at launch.
package privilege

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// Check uses capget/prctl rather than procfs text to verify serving privileges.
func Check() error {
	realUID, effectiveUID, savedUID := unix.Getresuid()
	if realUID == 0 || effectiveUID == 0 || savedUID == 0 {
		return fmt.Errorf("worker must have non-root real, effective and saved UIDs")
	}
	var data [2]unix.CapUserData
	header := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	if err := unix.Capget(&header, &data[0]); err != nil {
		return fmt.Errorf("read worker capabilities: %w", err)
	}
	if data != ([2]unix.CapUserData{}) {
		return fmt.Errorf("worker retains effective, permitted or inheritable capabilities")
	}

	noNewPrivileges, err := unix.PrctlRetInt(unix.PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0)
	if err != nil {
		return fmt.Errorf("read NoNewPrivileges: %w", err)
	}
	if noNewPrivileges != 1 {
		return fmt.Errorf("worker requires NoNewPrivileges")
	}

	for cap := 0; ; cap++ {
		bounding, err := unix.PrctlRetInt(unix.PR_CAPBSET_READ, uintptr(cap), 0, 0, 0)
		// EINVAL marks the first capability number unsupported by this kernel.
		if err == unix.EINVAL {
			break
		}
		if err != nil {
			return fmt.Errorf("read bounding capability %d: %w", cap, err)
		}
		if bounding != 0 {
			return fmt.Errorf("worker retains bounding capability %d", cap)
		}

		ambient, err := unix.PrctlRetInt(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_IS_SET, uintptr(cap), 0, 0)
		if err != nil {
			return fmt.Errorf("read ambient capability %d: %w", cap, err)
		}
		if ambient != 0 {
			return fmt.Errorf("worker retains ambient capability %d", cap)
		}
	}
	return nil
}
