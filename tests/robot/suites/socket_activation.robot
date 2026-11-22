*** Settings ***
Documentation     Service-manager behavior using the shipped units in the booted nspawn guest.
Resource          ../resources/dhcp_topology.resource
Suite Setup       Skip If    $BACKEND != 'systemd'    Requires BACKEND=systemd
Test Setup        Given an isolated DHCP topology
Test Teardown     Clean up the DHCP topology

*** Test Cases ***
Only an explicitly enabled socket adds a listener
    Then systemd listener lifecycle is minimal

Socket units leave workers dormant until traffic arrives
    Given a DHCP server is available on all ports
    Then only socket units are active
    When a DHCP client sends a DISCOVER on    port1
    Then the client receives a broadcast OFFER on    port1

Stopped worker reactivates from its socket and recovers the lease
    Given a DHCP server is available on all ports
    And a client obtains a lease on    port1
    When the worker on port1 is stopped
    And the original client retries its REQUEST on    port1
    Then the client receives a broadcast ACK on    port1
    And the worker on port1 has reactivated

Systemd rejects a pool outside the interface subnet
    When a worker starts with    pool outside the subnet
    Then the worker rejects startup
    When a DHCP client sends a DISCOVER on    port2
    Then the client receives a broadcast OFFER on    port2

Systemd rejects ambiguous server addresses
    When a worker starts with    ambiguous server addresses
    Then the worker rejects startup

Systemd rejects a missing configuration
    Then systemd rejects missing configuration

Systemd serves and recovers leases with generated configuration
    Then systemd serves with default configuration

Systemd rejects untrusted configuration and recovers after repair
    Then systemd rejects untrusted configuration and recovers

Systemd enforces the worker sandbox
    Then systemd enforces the worker sandbox

Unavailable Landlock prevents serving and preserves the peer
    Then systemd contains Landlock unavailable
    When the startup fault is repaired and the socket rearmed
    Then the repaired link grants a lease and the healthy peer renews

Denied Landlock enforcement prevents serving and preserves the peer
    Then systemd contains Landlock enforcement denied
    When the startup fault is repaired and the socket rearmed
    Then the repaired link grants a lease and the healthy peer renews

Denied state access prevents serving and preserves the peer
    Then systemd contains state access denied
    When the startup fault is repaired and the socket rearmed
    Then the repaired link grants a lease and the healthy peer renews
