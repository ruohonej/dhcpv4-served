#!/usr/bin/env python3
"""Report the actual host kernel and userspace; optionally enforce test requirements."""
import argparse
import ctypes
import errno
import json
import platform
import re
import subprocess
import sys


def report():
    distribution = platform.freedesktop_os_release()
    systemd = subprocess.check_output(["systemd-analyze", "--version"], text=True).splitlines()[0]
    seccomp = ctypes.CDLL("libseccomp.so.2")
    seccomp.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]
    number = seccomp.seccomp_syscall_resolve_name(b"landlock_create_ruleset")
    if number < 0:
        raise RuntimeError("libseccomp cannot resolve landlock_create_ruleset on this architecture")
    libc = ctypes.CDLL(None, use_errno=True)
    libc.syscall.restype = ctypes.c_long
    abi = libc.syscall(ctypes.c_long(number), ctypes.c_void_p(), ctypes.c_size_t(0), ctypes.c_uint(1))
    failure = ctypes.get_errno() if abi < 0 else None
    result = {
        "userspace": distribution.get("PRETTY_NAME", "unknown"),
        "kernel": platform.release(),
        "architecture": platform.machine(),
        "systemd": systemd,
        "landlock_abi": abi if abi >= 0 else None,
        "landlock_error": errno.errorcode.get(failure) if failure else None,
    }
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--require", action="store_true", help="require Linux 6.18+, systemd 259+ and Landlock ABI 7+")
    args = parser.parse_args()
    result = report()
    print(json.dumps(result, indent=2), flush=True)
    if args.require:
        kernel = re.match(r"(\d+)\.(\d+)", result["kernel"])
        systemd = re.match(r"systemd (\d+)", result["systemd"])
        failures = []
        if not kernel or tuple(map(int, kernel.groups())) < (6, 18):
            failures.append("host kernel must be Linux 6.18 or newer")
        if not systemd or int(systemd[1]) < 259:
            failures.append("test userspace must provide systemd 259 or newer")
        if result["landlock_abi"] is None or result["landlock_abi"] < 7:
            failures.append("Landlock ABI 7+ must be enabled and allowed by the container/host policy")
        if failures:
            sys.exit("\n".join(failures))
