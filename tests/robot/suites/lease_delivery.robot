*** Settings ***
Resource          ../resources/dhcp_topology.resource
Test Setup        Given an isolated DHCP topology
Test Teardown     Clean up the DHCP topology

*** Test Cases ***
Workers run without privileges
    Given a DHCP server is available on all ports
    Then every worker runs without privileges

Offer stays on its link on port1
    [Tags]    differential
    [Template]    Offer remains on the requesting link
    port1

Offer stays on its link on port2
    [Tags]    differential
    [Template]    Offer remains on the requesting link
    port2

Acknowledgement is broadcast on port1
    [Tags]    differential
    [Template]    Acknowledgement uses broadcast delivery
    port1

Acknowledgement is broadcast on port2
    [Tags]    differential
    [Template]    Acknowledgement uses broadcast delivery
    port2

Recovered lease remains reserved on port1
    [Template]    Restart preserves the lease reservation
    port1

Recovered lease remains reserved on port2
    [Template]    Restart preserves the lease reservation
    port2

Broadcast fallback works without an ARP entry on port1
    [Template]    Broadcast fallback works without ARP
    port1

Broadcast fallback works without an ARP entry on port2
    [Template]    Broadcast fallback works without ARP
    port2

Configured client renews its lease on port1
    [Template]    Configured client renews by unicast
    port1

Configured client renews its lease on port2
    [Template]    Configured client renews by unicast
    port2

Relayed requests are ignored
    Given a DHCP server is available on all ports
    When a relayed discover arrives on port1
    Then no DHCP reply is received
    When a DHCP client sends a DISCOVER on    port1
    Then the client receives a broadcast OFFER on    port1

Requests with relay hops are ignored
    Given a DHCP server is available on all ports
    When a discover with relay hops arrives on port1
    Then no DHCP reply is received
    When a DHCP client sends a DISCOVER on    port1
    Then the client receives a broadcast OFFER on    port1

Requests for another subnet are ignored
    Given a DHCP server is available on all ports
    When a request for another subnet arrives on port1
    Then no DHCP reply is received

Recreating a link stops only its worker
    Given a DHCP server is available on all ports
    And a client obtains a lease on    port1
    And a client obtains a lease on    port2
    When port1 is removed and immediately recreated
    Then the worker on port1 exits with an error
    When a DHCP client sends a DISCOVER on    port2
    Then the client receives a broadcast OFFER on    port2

Removing a server address stops its worker
    Given a DHCP server is available on all ports
    And a client obtains a lease on    port2
    When the server address is removed from port2
    Then the worker on port2 exits with an error

Identical clients retain independent leases on both ports after restart
    Given a DHCP server is available on all ports
    And a client obtains a lease on    port1
    And a client obtains a lease on    port2
    When the servers restart
    And a competing client sends a DISCOVER requesting the recovered address on    port1
    Then the competing client receives a broadcast OFFER for a different address on    port1
    When a competing client sends a DISCOVER requesting the recovered address on    port2
    Then the competing client receives a broadcast OFFER for a different address on    port2

*** Keywords ***
Offer remains on the requesting link
    [Arguments]    ${port}
    Given a DHCP server is available on all ports
    And the other links are monitored for packets from    ${port}
    When a DHCP client sends a DISCOVER on    ${port}
    Then the client receives a broadcast OFFER on    ${port}
    And the other links should receive no packets

Acknowledgement uses broadcast delivery
    [Arguments]    ${port}
    Given a DHCP server is available on all ports
    When a client obtains a lease on    ${port}
    Then the client receives a broadcast ACK on    ${port}

Restart preserves the lease reservation
    [Arguments]    ${port}
    Given a DHCP server is available on all ports
    And a client obtains a lease on    ${port}
    When the servers restart
    And a competing client sends a DISCOVER requesting the recovered address on    ${port}
    Then the competing client receives a broadcast OFFER for a different address on    ${port}
    When a third client sends a DISCOVER on    ${port}
    Then no DHCP reply is received
    When the original client retries its REQUEST on    ${port}
    Then the client receives a broadcast ACK on    ${port}

Broadcast fallback works without ARP
    [Arguments]    ${port}
    Given a DHCP server is available on all ports
    And the other links are monitored for packets from    ${port}
    When a client sends a DISCOVER without the broadcast flag on    ${port}
    Then the client receives a broadcast OFFER on    ${port}
    And the other links should receive no packets
    When the client sends a REQUEST without the broadcast flag on    ${port}
    Then the client receives a broadcast ACK on    ${port}
    And the server has no ARP entry for the client on    ${port}

Configured client renews by unicast
    [Arguments]    ${port}
    Given a DHCP server is available on all ports
    And a client obtains a lease on    ${port}
    And the client configures its leased address on    ${port}
    When the configured client sends a unicast renewal on    ${port}
    Then the client receives a unicast ACK on    ${port}
