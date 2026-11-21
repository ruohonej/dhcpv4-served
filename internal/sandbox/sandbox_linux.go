// Package sandbox installs the worker's serving-time Landlock policy.
package sandbox

import (
	"errors"
	"fmt"

	"github.com/landlock-lsm/go-landlock/landlock"
	ll "github.com/landlock-lsm/go-landlock/landlock/syscall"
)

const (
	Strict        = "strict"
	LabBestEffort = "lab-best-effort"
)

var ErrABI = errors.New("strict security profile requires Landlock ABI >=7")

// ValidateProfile rejects unknown profiles before startup acquires resources.
func ValidateProfile(profile string) error {
	switch profile {
	case Strict, LabBestEffort:
		return nil
	default:
		return fmt.Errorf("unknown security profile %q", profile)
	}
}

// Restrict requires ABI 7 and all-thread enforcement in strict mode. The lab
// profile deliberately permits missing rights, but never enforcement errors.
// Existing descriptors remain usable under both profiles.
func Restrict(profile string, stateDirs ...string) error {
	return restrict(profile, ll.LandlockGetABIVersion, enforce, stateDirs...)
}

func restrict(profile string, probe func() (int, error), apply func(bool, []string) error, stateDirs ...string) error {
	if err := ValidateProfile(profile); err != nil {
		return err
	}
	abi, err := probe()
	if profile == Strict && (err != nil || abi < 7) {
		return fmt.Errorf("%w: ABI=%d, probe error=%v", ErrABI, abi, err)
	}
	if err := apply(profile == LabBestEffort, stateDirs); err != nil {
		return fmt.Errorf("enforce Landlock (%s): %w", profile, err)
	}
	return nil
}

func enforce(bestEffort bool, stateDirs []string) error {
	rules := make([]landlock.Rule, 0, len(stateDirs))
	for _, dir := range stateDirs {
		rules = append(rules, landlock.RWDirs(dir).WithRefer())
	}
	policy := landlock.V7.EnableLoggingForSubprocesses()
	if bestEffort {
		policy = policy.BestEffort()
	}
	// Restrict applies the policy to all existing OS threads; newly created
	// threads inherit it. Any error is fatal, even after partial enforcement.
	return policy.Restrict(rules...)
}
