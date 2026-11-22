#!/usr/bin/env python3
"""Run a command with the unit's syscall and socket-family filters.

Checks systemd syscall and socket-family policies, not the complete sandbox.
"""
import ctypes
import errno
import os
from pathlib import Path
import socket
import subprocess
import sys


def install():
    unit = Path(__file__).resolve().parents[3] / "deploy/systemd/dhcpv4-served@.service"
    filters = []
    families = None
    for line in unit.read_text().splitlines():
        key, sep, value = line.partition("=")
        if key == "SystemCallFilter" and sep:
            if not value:
                raise ValueError("test wrapper does not support filter resets")
            filters.append((value.startswith("~"), value.removeprefix("~").split()))
        elif key == "RestrictAddressFamilies" and sep:
            families = value.split()
        elif key == "SystemCallErrorNumber" and value != "EPERM":
            raise ValueError("test wrapper expects SystemCallErrorNumber=EPERM")
    if not filters or filters[0][0] or families != ["AF_NETLINK"]:
        raise ValueError("update test wrapper for changed unit policy")

    def expand(entries):
        pending, seen, names = set(entries), set(), set()
        while pending:
            name = pending.pop()
            if not name.startswith("@"):
                names.add(name)
                continue
            if name in seen:
                continue
            seen.add(name)
            output = subprocess.check_output(["systemd-analyze", "syscall-filter", name], text=True)
            for line in output.splitlines():
                entry = line.strip()
                if line.startswith(" ") and entry and not entry.startswith("#"):
                    pending.add(entry)
        return names

    # Apply allow/deny assignments in order, including systemd's implicit default.
    names = expand(["@default"])
    for exclude, entries in filters:
        if exclude:
            names.difference_update(expand(entries))
        else:
            names.update(expand(entries))

    class ArgCmp(ctypes.Structure):
        _fields_ = [("arg", ctypes.c_uint), ("op", ctypes.c_int),
                    ("datum_a", ctypes.c_uint64), ("datum_b", ctypes.c_uint64)]

    sec = ctypes.CDLL("libseccomp.so.2", use_errno=True)
    sec.seccomp_init.argtypes = [ctypes.c_uint32]
    sec.seccomp_init.restype = ctypes.c_void_p
    sec.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]
    sec.seccomp_rule_add_array.argtypes = [ctypes.c_void_p, ctypes.c_uint32,
                                          ctypes.c_int, ctypes.c_uint, ctypes.POINTER(ArgCmp)]
    sec.seccomp_load.argtypes = [ctypes.c_void_p]
    sec.seccomp_release.argtypes = [ctypes.c_void_p]
    allow = 0x7fff0000  # SCMP_ACT_ALLOW
    ctx = sec.seccomp_init(0x00050000 | errno.EPERM)  # SCMP_ACT_ERRNO(EPERM)
    if not ctx:
        raise MemoryError("seccomp_init")
    try:
        for name in sorted(names):
            number = sec.seccomp_syscall_resolve_name(name.encode())
            # Unknown aliases and pseudo-numbers cannot add a native rule.
            if number < 0:
                continue
            for family in ([socket.AF_NETLINK] if name == "socket" else [None]):
                comparison = ArgCmp(0, 4, family or 0, 0)  # SCMP_CMP_EQ
                count = 1 if family is not None else 0
                result = sec.seccomp_rule_add_array(ctx, allow, number, count,
                                                    ctypes.byref(comparison) if count else None)
                if result != 0:
                    raise OSError(-result, "seccomp rule " + name)
        result = sec.seccomp_load(ctx)
        if result != 0:
            raise OSError(-result, "seccomp_load")
    finally:
        sec.seccomp_release(ctx)


if __name__ == "__main__":
    command = (sys.argv[2:] if sys.argv[1:2] == ["--"] else
               [os.environ["DHCPV4_SERVED_FILTER_EXECUTABLE"], *sys.argv[1:]])
    if not command:
        sys.exit("missing command")
    install()
    os.execv(command[0], command)
