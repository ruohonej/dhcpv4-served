"""Executed by real systemd under the production unit's sandbox settings."""
import errno
import os
import time
from pathlib import Path
import socket
import sys


def denied(operation, *, allow_hidden_peer=False):
    try:
        operation()
    except OSError as error:
        # DynamicUser hides other instances' private state in this mount
        # namespace. The manager-side fixture verifies the live peer exists.
        if allow_hidden_peer and error.errno == errno.ENOENT:
            return
        assert error.errno in (errno.EPERM, errno.EACCES, errno.EROFS, errno.EAFNOSUPPORT), error
    else:
        raise AssertionError('Sandbox unexpectedly allowed operation')


if __name__ == '__main__':
    if sys.argv[1:] == ['hold']:
        (Path('/var/lib/dhcpv4-served-peer') / 'private').write_text('peer state')
        time.sleep(120)
    elif sys.argv[1:] == ['bind']:
        # Separate from RestrictAddressFamilies, so only the cgroup-BPF bind
        # restriction can deny this otherwise unprivileged loopback bind.
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            denied(lambda: sock.bind(('127.0.0.1', 0)))
    else:
        state = Path('/var/lib/dhcpv4-served-probe')
        (state / 'allowed').write_text('state directory is writable\n')
        peer = Path('/var/lib/private/dhcpv4-served-peer/private')
        denied(lambda: peer.read_text(), allow_hidden_peer=True)
        denied(lambda: peer.write_text('changed'), allow_hidden_peer=True)
        config = Path('/etc/dhcpv4-served/probe.yaml')
        assert config.read_text() == 'selected config\n'
        denied(lambda: config.write_text('changed'))
        # This probe does not install Landlock: systemd/DAC permit this read.
        assert Path('/etc/dhcpv4-served/unrelated').read_text() == 'unrelated\n'
        denied(lambda: os.setuid(os.getuid()))
        denied(lambda: socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
        denied(lambda: socket.socket(socket.AF_UNIX, socket.SOCK_STREAM))
        # Proc visibility remains enforced while PrivatePIDs is unavailable on
        # the baseline: guest PID 1 belongs to another user and is hidden.
        assert Path('/proc/self/status').is_file()
        assert not Path('/proc/1/status').exists()
        assert not Path('/proc/cpuinfo').exists()
        with socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, socket.NETLINK_ROUTE):
            pass
    print('Sandbox denial checks passed', flush=True)
