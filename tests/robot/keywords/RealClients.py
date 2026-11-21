"""Robot keywords for real DHCP client acquisition scenarios."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import traceback
from types import SimpleNamespace
from robot.api.deco import keyword

from harness.fixtures import namespace_check
from harness import real_client_fixture as fixture


class RealClients:
    ROBOT_LIBRARY_SCOPE = 'TEST'

    def __init__(self, backend='fast', worker='work/dhcpv4-served', output='work/robot-fixture'):
        if backend not in ('fast', 'systemd'):
            raise ValueError(f'Unknown backend {backend!r}; available: fast, systemd')
        self.backend_name = backend
        self.backend = None
        self.worker = Path(worker).resolve()
        self.output = Path(output).resolve() / 'real-clients'
        self.result = None
        self.run = None
        self.client = None
        self.binary = None

    @keyword('real-client prerequisites are available for')
    def real_client_prerequisites_are_available(self, client):
        if self.backend_name == 'fast':
            namespace_check(require_writable_proc=True)
        if not os.access(self.worker, os.X_OK):
            raise RuntimeError(f'Worker is not executable: {self.worker}')
        for name in ('ip', 'setpriv'):
            if not shutil.which(name):
                raise RuntimeError(f'Missing prerequisite: {name}')
        if client not in ('dhclient', 'dhcpcd', 'systemd-networkd'):
            raise ValueError(f'Unknown client: {client}')
        binary = shutil.which(client)
        if not binary and client == 'systemd-networkd':
            binary = next((p for p in ('/usr/lib/systemd/systemd-networkd', '/lib/systemd/systemd-networkd')
                           if os.access(p, os.X_OK)), None)
        if not binary:
            raise RuntimeError(f'Missing required client: {client}')
        self.client, self.binary = client, binary
        self.output.mkdir(parents=True, exist_ok=True)
        if self.backend_name == 'fast':
            fixture.ip('link', 'set', 'lo', 'up')

    def _record_result(self, passed, error=None):
        result = dict(self.result or {}, passed=passed)
        if error is not None:
            result['error'] = error
        (self.run / 'results.json').write_text(json.dumps({self.client: result}, indent=2) + '\n')

    def the_real_dhcp_client_requests_a_lease(self):
        if self.client is None:
            raise RuntimeError('Check real-client prerequisites before requesting a lease')
        self.run = Path(tempfile.mkdtemp(prefix=f'{self.client}-', dir=self.output))
        try:
            version = subprocess.run([self.binary, '--version'], capture_output=True, text=True, timeout=5)
            (self.run / 'versions.json').write_text(json.dumps({self.client: {'binary': self.binary,
                'version': (version.stdout + version.stderr).strip()}}, indent=2) + '\n')
            if self.backend_name == 'systemd':
                from harness.systemd_fixture import SystemdBackend
                self.backend = SystemdBackend(self.worker, self.run)
                self.backend.client_bind_port = False
                self.backend.create(configure=False)
                self.backend.clear_configuration()
                self.result = self.backend.run_real_client(self.client, self.binary, self.run / self.client)
            else:
                self.result = fixture.run_case(self.client, self.binary,
                    SimpleNamespace(worker=str(self.worker), timeout=45), self.run / self.client)
        except Exception:
            self._record_result(False, traceback.format_exc())
            raise
        (self.run / 'evidence.json').write_text(json.dumps(self.result, indent=2) + '\n')

    def the_client_acquires_a_valid_lease_and_the_server_persists_it(self):
        try:
            fixture.check_acquisition(self.result, self.client)
        except Exception:
            if self.run is not None:
                self._record_result(False, traceback.format_exc())
            raise
        self._record_result(True)

    def clean_up_the_real_client_topology(self):
        if self.backend is not None:
            self.backend.close()
            self.backend = None
