"""Robot keywords for the systemd load scenarios."""
import json
import os
from pathlib import Path

from robot.api import SkipExecution
from harness.load import LINKS, execute_phase, run_load


class LoadAcceptance:
    ROBOT_LIBRARY_SCOPE = 'TEST'

    def ten_clients_on_each_link_renew_their_leases(self):
        output = Path('/test-output/load-smoke')
        self.phase = dict(name='renewal-smoke', duration=1, flood=False)
        execute_phase(output, self.phase, 10, {'phases': []})
        (output / 'renewal-smoke.json').write_text(json.dumps(self.phase, indent=2))

    def every_client_receives_a_safe_unicast_renewal(self):
        for link in LINKS:
            result = self.phase['clients'][link]
            assert result['renewals'] == len(result['latencies']) == 10, result
            assert result['unsafe_acks'] == 0 and not result['duplicate_grants'], result

    def measured_load_testing_is_enabled(self):
        if os.environ.get('DHCPV4_SERVED_LOAD') != '1':
            raise SkipExecution('Opt in with tests/acceptance run load on a disposable host')

    def the_workers_run_under_baseline_and_flood_load(self):
        self.report = run_load('/test-output/load')

    def both_workers_meet_the_load_and_renewal_budgets(self):
        if self.report['status'] != 'pass':
            raise AssertionError({k: self.report[k] for k in ('status', 'invalid', 'failures')})
