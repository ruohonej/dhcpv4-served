package sandbox

import (
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"
	"time"
	"unsafe"

	ll "github.com/landlock-lsm/go-landlock/landlock/syscall"
	"golang.org/x/sys/unix"
)

// Landlock is irreversible, so enforcement tests always run in a subprocess.
func TestLandlock(t *testing.T) {
	for _, mode := range []string{"unavailable", "enforce"} {
		t.Run(mode, func(t *testing.T) {
			if mode == "enforce" {
				abi, err := ll.LandlockGetABIVersion()
				if err != nil || abi < 7 {
					t.Skipf("requires enabled Landlock ABI 7+: ABI=%d, error=%v", abi, err)
				}
			}
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "existing"), []byte("fixture"), 0600); err != nil {
				t.Fatal(err)
			}
			abstract := "@dhcpv4-served-landlock-" + strconv.Itoa(os.Getpid()) + "-" + mode
			listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: abstract, Net: "unix"})
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			cmd := exec.Command(os.Args[0], "-test.run=^TestLandlockChild$")
			cmd.Env = append(os.Environ(), "LANDLOCK_TEST="+mode, "LANDLOCK_TEST_DIR="+dir, "LANDLOCK_TEST_UNIX="+abstract)
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("%v: %s", err, out)
			}
		})
	}
}

func TestLandlockChild(t *testing.T) {
	mode := os.Getenv("LANDLOCK_TEST")
	if mode == "" {
		return
	}
	if mode == "unavailable" {
		// Hide the ABI probe on this thread to exercise best-effort startup even
		// on hosts where Landlock is enabled. This subprocess exits immediately.
		runtime.LockOSThread()
		filter := []unix.SockFilter{
			{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: 0},
			{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, K: unix.SYS_LANDLOCK_CREATE_RULESET, Jf: 1},
			{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ERRNO | uint32(unix.ENOSYS)},
			{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ALLOW},
		}
		prog := unix.SockFprog{Len: uint16(len(filter)), Filter: &filter[0]}
		if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
			t.Fatal(err)
		}
		if err := unix.Prctl(unix.PR_SET_SECCOMP, unix.SECCOMP_MODE_FILTER, uintptr(unsafe.Pointer(&prog)), 0, 0); err != nil {
			t.Fatal(err)
		}
		runtime.KeepAlive(filter)
		runtime.KeepAlive(prog)
		if err := Restrict(Strict); err == nil {
			t.Fatal("strict startup accepted unavailable Landlock")
		}
		if err := Restrict(LabBestEffort); err != nil {
			t.Fatalf("best-effort startup without Landlock: %v", err)
		}
		return
	}

	dir := os.Getenv("LANDLOCK_TEST_DIR")
	path := filepath.Join(dir, "existing")
	peerDir := filepath.Join(dir, "peer")
	if err := os.Mkdir(peerDir, 0700); err != nil {
		t.Fatal(err)
	}
	peerPath := filepath.Join(peerDir, "private")
	if err := os.WriteFile(peerPath, []byte("peer"), 0600); err != nil {
		t.Fatal(err)
	}
	allowed := filepath.Join(dir, "state")
	if err := os.Mkdir(allowed, 0700); err != nil {
		t.Fatal(err)
	}
	// An already-open file and UDP socket model inherited logging/activation.
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	tcp, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, unix.IPPROTO_TCP)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(tcp)

	// Hold multiple OS threads across enforcement, then check each of them.
	ready, check, results := make(chan struct{}, 8), make(chan struct{}), make(chan error, 8)
	for range 8 {
		go func() {
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()
			ready <- struct{}{}
			<-check
			_, err := os.ReadFile(path)
			results <- err
		}()
	}
	for range 8 {
		<-ready
	}
	if err := Restrict(Strict, allowed); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(allowed, "snapshot"), []byte("state"), 0600); err != nil {
		t.Fatalf("state write: %v", err)
	}
	if err := os.Rename(filepath.Join(allowed, "snapshot"), filepath.Join(allowed, "leases.json")); err != nil {
		t.Fatalf("state rename: %v", err)
	}
	close(check)
	for range 8 {
		if err := <-results; !errors.Is(err, os.ErrPermission) {
			t.Fatalf("existing thread bypassed file restriction: %v", err)
		}
	}
	for name, err := range map[string]error{
		"write":         os.WriteFile(path, []byte("changed"), 0600),
		"peer read":     func() error { _, err := os.ReadFile(peerPath); return err }(),
		"peer write":    os.WriteFile(peerPath, []byte("changed"), 0600),
		"create":        os.WriteFile(filepath.Join(dir, "new"), nil, 0600),
		"mkdir":         os.Mkdir(filepath.Join(dir, "subdir"), 0700),
		"TCP bind":      unix.Bind(tcp, &unix.SockaddrInet4{}),
		"TCP connect":   unix.Connect(tcp, &unix.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}, Port: 9}),
		"parent signal": unix.Kill(os.Getppid(), unix.SIGCONT),
	} {
		if !errors.Is(err, os.ErrPermission) {
			t.Errorf("%s: want permission denied, got %v", name, err)
		}
	}
	peer, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: os.Getenv("LANDLOCK_TEST_UNIX"), Net: "unix"})
	if peer != nil {
		peer.Close()
	}
	if !errors.Is(err, os.ErrPermission) {
		t.Errorf("external abstract UNIX socket: want permission denied, got %v", err)
	}
	// New goroutines must inherit enforcement as well.
	go func() { _, err := os.ReadFile(path); results <- err }()
	if err := <-results; !errors.Is(err, os.ErrPermission) {
		t.Fatalf("new goroutine bypassed file restriction: %v", err)
	}
	if _, err := file.Read(make([]byte, 7)); err != nil {
		t.Fatalf("existing descriptor became unusable: %v", err)
	}
	if err := udp.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := udp.WriteToUDP([]byte("reply"), udp.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatalf("inherited UDP send: %v", err)
	}
	if _, _, err := udp.ReadFromUDP(make([]byte, 16)); err != nil {
		t.Fatalf("inherited UDP receive: %v", err)
	}
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		t.Fatalf("route netlink: %v", err)
	}
	unix.Close(fd)
}

func TestSystemdFilter(t *testing.T) {
	for _, tool := range []string{"python3", "systemd-analyze"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("syscall policy test needs %s", tool)
		}
	}
	cmd := exec.Command(
		"python3",
		"../../tests/robot/harness/systemd_filter.py",
		"--",
		os.Args[0],
		"-test.run=^TestSystemdFilterChild$",
	)
	cmd.Env = append(os.Environ(), "SYSTEMD_FILTER_TEST=1")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
}

func TestSystemdFilterChild(t *testing.T) {
	if os.Getenv("SYSTEMD_FILTER_TEST") != "1" {
		return
	}
	for _, family := range []int{unix.AF_INET, unix.AF_INET6, unix.AF_PACKET, unix.AF_UNIX} {
		fd, err := unix.Socket(family, unix.SOCK_DGRAM, 0)
		if fd >= 0 {
			unix.Close(fd)
		}
		if !errors.Is(err, unix.EPERM) {
			t.Errorf("socket family %d: want EPERM, got %v", family, err)
		}
	}
	if err := unix.Setpriority(unix.PRIO_PROCESS, 0, 0); !errors.Is(err, unix.EPERM) {
		t.Errorf("resource changes: want EPERM, got %v", err)
	}
	if err := unix.Setuid(os.Getuid()); !errors.Is(err, unix.EPERM) {
		t.Errorf("setuid: want EPERM, got %v", err)
	}
	if _, err := unix.MemfdCreate("sandbox-test", unix.MFD_CLOEXEC); !errors.Is(err, unix.EPERM) {
		t.Errorf("memfd creation: want EPERM, got %v", err)
	}
	if _, _, err := unix.Syscall(unix.SYS_IO_URING_SETUP, 0, 0, 0); !errors.Is(err, unix.EPERM) {
		t.Errorf("io_uring setup: want EPERM, got %v", err)
	}
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		t.Fatalf("route netlink blocked: %v", err)
	}
	defer unix.Close(fd)
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		t.Fatalf("route netlink bind blocked: %v", err)
	}
	// The query must reach the kernel (ENOSYS if the host disabled Landlock),
	// rather than being rejected by the unit's syscall allowlist.
	if _, err := ll.LandlockGetABIVersion(); errors.Is(err, unix.EPERM) {
		t.Fatal("syscall filter blocks required Landlock ABI query")
	}
}

// Probe and enforcement faults must fail closed independently. The injected
// enforcement boundary avoids irreversibly restricting the test runner.
func TestSecurityProfiles(t *testing.T) {
	denied := errors.New("enforcement denied")
	for _, tc := range []struct {
		name, profile        string
		abi                  int
		probeErr, enforceErr error
		wantErr, wantApply   bool
	}{
		{name: "unknown", profile: "typo", abi: 7, wantErr: true},
		{name: "strict unavailable", profile: Strict, probeErr: unix.ENOSYS, wantErr: true},
		{name: "strict denied probe", profile: Strict, abi: 7, probeErr: unix.EPERM, wantErr: true},
		{name: "strict old", profile: Strict, abi: 6, wantErr: true},
		{
			name:       "strict enforcement denied",
			profile:    Strict,
			abi:        7,
			enforceErr: denied,
			wantErr:    true,
			wantApply:  true,
		},
		{name: "strict supported", profile: Strict, abi: 7, wantApply: true},
		{name: "strict newer", profile: Strict, abi: 8, wantApply: true},
		{name: "lab unavailable", profile: LabBestEffort, probeErr: unix.ENOSYS, wantApply: true},
		{name: "lab old", profile: LabBestEffort, abi: 6, wantApply: true},
		{
			name:       "lab enforcement denied",
			profile:    LabBestEffort,
			abi:        7,
			enforceErr: denied,
			wantErr:    true,
			wantApply:  true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			applied := false
			err := restrict(tc.profile, func() (int, error) { return tc.abi, tc.probeErr }, func(bestEffort bool, dirs []string) error {
				applied = true
				if bestEffort != (tc.profile == LabBestEffort) {
					t.Errorf("best effort=%v", bestEffort)
				}
				if len(dirs) != 1 || dirs[0] != "/state" {
					t.Errorf("state directories=%v", dirs)
				}
				return tc.enforceErr
			}, "/state")
			if (err != nil) != tc.wantErr {
				t.Fatalf("error=%v, want error=%v", err, tc.wantErr)
			}
			if applied != tc.wantApply {
				t.Fatalf("applied=%v, want %v", applied, tc.wantApply)
			}
			if tc.enforceErr != nil && !errors.Is(err, tc.enforceErr) {
				t.Fatalf("lost enforcement error: %v", err)
			}
		})
	}
}
