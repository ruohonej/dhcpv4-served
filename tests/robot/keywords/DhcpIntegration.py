"""Robot keywords for DHCP packet and service behavior."""
from pathlib import Path
import tempfile
from robot.api.deco import keyword

from harness import fixtures as probe
from harness.namespace_driver import FastBackend


class DhcpIntegration:
    ROBOT_LIBRARY_SCOPE = 'SUITE'

    def __init__(self, backend='fast', worker='work/dhcpv4-served', output='work/robot-fixture'):
        if backend not in ('fast', 'systemd', 'differential-go', 'differential-dnsmasq'):
            raise ValueError(f'Unknown backend {backend!r}; use fast, systemd, differential-go or differential-dnsmasq')
        self.backend_name = backend
        self.worker = worker
        self.output = Path(output).resolve()
        self.backend = None

    def an_isolated_dhcp_topology(self, configure: bool = True):
        self.output.mkdir(parents=True, exist_ok=True)
        run_output = tempfile.mkdtemp(prefix='scenario-', dir=self.output)
        if self.backend_name == 'systemd':
            from harness.systemd_fixture import SystemdBackend
            self.backend = SystemdBackend(self.worker, run_output)
        elif self.backend_name.startswith('differential-'):
            from robot.libraries.BuiltIn import BuiltIn
            from harness.differential import DifferentialBackend
            scenario = BuiltIn().get_variable_value('${TEST NAME}')
            self.backend = DifferentialBackend(self.worker, run_output, self.backend_name, scenario)
        else:
            self.backend = FastBackend(self.worker, run_output)
        if self.backend_name == 'systemd':
            self.backend.create(configure=configure)
        else:
            self.backend.create()
        return self.backend

    def clean_up_the_dhcp_topology(self, preserve_state: bool = False):
        if self.backend is not None:
            if self.backend_name == 'systemd':
                self.backend.close(preserve_state=preserve_state)
            else:
                self.backend.close()
            self.backend = None

    def a_dhcp_server_is_available_on_all_ports(self):
        self.backend.start()

    @staticmethod
    def _link(port):
        links = {'port1': 'lan10', 'port2': 'lan20'}
        if port not in links:
            raise ValueError(f'Unknown port: {port}')
        return links[port]

    @keyword('a DHCP client sends a DISCOVER on')
    def a_dhcp_client_sends_a_discover(self, port):
        self.backend.exchange(self._link(port), probe.request())

    @keyword('the other links are monitored for packets from')
    def the_other_links_are_monitored(self, port):
        self.backend.monitor_other_link(self._link(port))

    @keyword('the client receives a broadcast OFFER on')
    def the_client_receives_a_broadcast_offer(self, port):
        self.backend.check_reply(self._link(port))

    def the_other_links_should_receive_no_packets(self):
        self.backend.check_other_link()

    @keyword('a worker starts with')
    def a_worker_starts_with_invalid_settings(self, reason):
        self.backend.start_invalid(reason)

    def the_worker_rejects_startup(self):
        self.backend.check_rejected()

    def every_worker_runs_without_privileges(self):
        self.backend.check_privileges()

    @keyword('a client obtains a lease on')
    def a_client_obtains_a_lease(self, port):
        self.backend.commit_lease(self._link(port))

    def the_servers_restart(self):
        self.backend.restart()

    @keyword('a competing client sends a DISCOVER requesting the recovered address on')
    def a_competing_client_discovers_the_recovered_address(self, port):
        link = self._link(port)
        self.backend.exchange(link, probe.request(address=f'192.168.{link[3:]}.100', client_id=b'other'))

    @keyword('the competing client receives a broadcast OFFER for a different address on')
    def the_competing_client_receives_a_different_offer(self, port):
        link = self._link(port)
        self.backend.check_reply(link, address=f'192.168.{link[3:]}.103', client_id=b'other')

    @keyword('a third client sends a DISCOVER on')
    def a_third_client_sends_a_discover(self, port):
        self.backend.exchange(self._link(port), probe.request(client_id=b'third'))

    def no_dhcp_reply_is_received(self):
        if self.backend.replies != []:
            raise AssertionError(f'Unexpected replies: {self.backend.replies!r}')

    @keyword('the original client retries its REQUEST on')
    def the_original_client_retries_its_request(self, port):
        link = self._link(port)
        n = link[3:]
        self.backend.exchange(link, probe.request(3, server=f'192.168.{n}.1', address=f'192.168.{n}.100'))

    @keyword('the client receives a broadcast ACK on')
    def the_client_receives_a_broadcast_ack(self, port):
        self.backend.check_reply(self._link(port), message_type=5)

    def a_relayed_discover_arrives_on_port1(self):
        self.backend.exchange('lan10', probe.request(relay='192.168.10.2', client_id=b'relay'))

    def a_discover_with_relay_hops_arrives_on_port1(self):
        self.backend.exchange('lan10', probe.request(hops=1, client_id=b'relay'))

    def a_request_for_another_subnet_arrives_on_port1(self):
        self.backend.exchange('lan10', probe.request(3, server='192.168.10.1', address='192.168.20.100'))

    @keyword('a client sends a DISCOVER without the broadcast flag on')
    def a_client_sends_a_discover_without_broadcast(self, port):
        link = self._link(port)
        self.backend.flush_neighbors(link)
        self.backend.exchange(link, probe.request(broadcast=False))

    @keyword('the client sends a REQUEST without the broadcast flag on')
    def the_client_sends_a_request_without_broadcast(self, port):
        link = self._link(port)
        n = link[3:]
        self.backend.exchange(link, probe.request(3, broadcast=False, server=f'192.168.{n}.1', address=f'192.168.{n}.100'))

    @keyword('the server has no ARP entry for the client on')
    def the_server_has_no_arp_entry_for_the_client(self, port):
        link = self._link(port)
        neighbors = self.backend.neighbor_entries(link)
        if f'192.168.{link[3:]}.100' in neighbors:
            raise AssertionError(f'Unexpected neighbor entry: {neighbors}')

    @keyword('the client configures its leased address on')
    def the_client_configures_its_leased_address(self, port):
        self.backend.assign_client_address(self._link(port))

    @keyword('the configured client sends a unicast renewal on')
    def the_configured_client_sends_a_unicast_renewal(self, port):
        self.backend.send_unicast_renewal(self._link(port))

    @keyword('the client receives a unicast ACK on')
    def the_client_receives_a_unicast_ack(self, port):
        self.backend.check_unicast_ack(self._link(port))

    def port1_is_removed_and_immediately_recreated(self):
        self.backend.replace_link('lan10')

    @keyword('the worker on ${port} exits with an error')
    def the_worker_exits_with_an_error(self, port):
        proc = self.backend.workers[self._link(port)]
        if proc.wait(timeout=5) == 0:
            raise AssertionError('Worker exited successfully instead of failing')

    def the_server_address_is_removed_from_port2(self):
        self.backend.remove_server_address('lan20')

    def only_socket_units_are_active(self):
        self.backend.check_dormant()

    def systemd_listener_lifecycle_is_minimal(self):
        self.backend.check_listener_lifecycle()

    @keyword('the worker on ${port} is stopped')
    def stop_one_worker(self, port):
        self.backend.stop_worker(self._link(port))

    @keyword('the worker on ${port} has reactivated')
    def check_reactivated(self, port):
        self.backend.check_reactivated(self._link(port))

    def systemd_enforces_the_worker_sandbox(self):
        self.backend.check_sandbox()

    @keyword('systemd contains ${failure}')
    def systemd_contains_control_failure(self, failure):
        self.backend.check_control_failure(failure)

    def the_startup_fault_is_repaired_and_the_socket_rearmed(self):
        self.backend.repair_control_failure()

    def the_repaired_link_grants_a_lease_and_the_healthy_peer_renews(self):
        self.backend.check_control_recovery()

    def systemd_rejects_missing_configuration(self):
        self.backend.check_missing_configuration()

    def systemd_serves_with_default_configuration(self):
        self.backend.check_default_configuration()

    def systemd_rejects_untrusted_configuration_and_recovers(self):
        self.backend.check_trusted_configuration()
