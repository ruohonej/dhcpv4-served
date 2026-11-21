*** Settings ***
Resource          ../resources/test_defaults.resource
Library           keywords.RealClients.RealClients    backend=${BACKEND}    worker=${WORKER}    output=${FIXTURE_OUTPUT}
Test Teardown     Clean up the real client topology
Test Template     Acquire and persist a lease

*** Test Cases ***
dhclient acquires a lease    dhclient
dhcpcd acquires a lease    dhcpcd
systemd-networkd acquires a lease    systemd-networkd

*** Keywords ***
Acquire and persist a lease
    [Arguments]    ${client}
    Given real-client prerequisites are available for    ${client}
    When the real DHCP client requests a lease
    Then the client acquires a valid lease and the server persists it
