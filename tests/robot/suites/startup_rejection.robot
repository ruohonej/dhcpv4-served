*** Settings ***
Resource          ../resources/dhcp_topology.resource
Test Setup        Given an isolated DHCP topology
Test Teardown     Clean up the DHCP topology
Test Template     Reject invalid startup

*** Test Cases ***
Startup rejects wrong interface    wrong interface
Startup rejects wrong descriptor name    wrong descriptor name
Startup rejects wrong descriptor count    wrong descriptor count
Startup rejects pool outside the subnet    pool outside the subnet
Startup rejects unexpected capabilities    unexpected capabilities
Startup rejects ambiguous server addresses    ambiguous server addresses
Startup rejects worker-owned configuration beneath trusted ancestors    worker-owned configuration
Startup rejects an untrusted ancestor with root-owned configuration    untrusted configuration directory

*** Keywords ***
Reject invalid startup
    [Arguments]    ${reason}
    When a worker starts with    ${reason}
    Then the worker rejects startup
