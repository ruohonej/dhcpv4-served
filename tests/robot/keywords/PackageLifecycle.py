"""Robot keywords for package behavior in one booted guest."""
from harness import installation


class PackageLifecycle:
    ROBOT_LIBRARY_SCOPE = 'TEST'

    def use_package_guest(self, guest):
        self.guest = guest
        self.upgrading = False

    def the_installed_package_requires_explicit_enablement(self):
        installation.check_installation(self.guest)

    def a_lease_exists_with_the_socket(self, state):
        if state not in ('armed', 'disabled'):
            raise ValueError(f'Unknown socket state: {state}')
        self.upgrading = True
        self.before = installation.prepare_update(self.guest, armed=(state == 'armed'))

    def the_package_is_updated(self):
        installation.install(self.guest, installation.CANDIDATE, 'update')

    def the_update_caused_no_worker_activation(self):
        installation.check_update_activity(self.guest, self.before)

    def configuration_and_lease_state_are_preserved(self):
        installation.check_update_files(self.before)

    def the_client_requests_its_existing_lease(self):
        installation.request_existing_lease(self.guest)

    def a_new_worker_acknowledges_the_lease(self):
        installation.check_reactivation(self.guest, self.before)

    def client_traffic_leaves_the_socket_disarmed(self):
        installation.check_disabled_update(self.guest, self.before)

    def the_socket_remains_disarmed_after_reboot(self):
        installation.check_after_reboot(self.guest)

    def finish_package_update(self):
        if getattr(self, 'upgrading', False):
            installation.disarm(check=False)
