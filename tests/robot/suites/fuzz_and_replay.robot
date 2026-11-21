*** Settings ***
Documentation     Stateful DHCP sequence replay and generated tests in isolated namespaces.
Library           harness.fuzz_dhcp

*** Variables ***
${WORKER}         work/dhcpv4-served
${FUZZ_OUTPUT}    work/fuzz-dhcp
${REPLAY}         ${CURDIR}/../data/fuzz-replay.json
${EXAMPLES}       4
${PACKET_REPLAY}  ${EMPTY}

*** Test Cases ***
Replay DHCP sequence
    Then lease isolation holds for the recorded sequence    ${REPLAY}    ${WORKER}    ${FUZZ_OUTPUT}/stateful-replay

Generate DHCP sequences
    Then lease isolation holds for generated sequences    ${EXAMPLES}    ${WORKER}    ${FUZZ_OUTPUT}/stateful-generated

Fuzz DHCP packet fields
    Then both workers retain their leases across generated packets and replay    ${EXAMPLES}    ${WORKER}    ${FUZZ_OUTPUT}/packet-generated

Replay DHCP packet sequence
    Skip If    $PACKET_REPLAY == ''    No packet sequence supplied
    Then both workers retain their leases across the recorded packets    ${PACKET_REPLAY}    ${WORKER}    ${FUZZ_OUTPUT}/packet-replay
