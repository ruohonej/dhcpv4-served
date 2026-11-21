*** Settings ***
Documentation     Installed DEB defaults and package updates in isolated guests.
Resource          ../resources/dhcp_topology.resource
Library           keywords.PackageLifecycle.PackageLifecycle
Suite Setup       Skip If    $BACKEND != 'systemd'    Requires BACKEND=systemd
Test Setup        Prepare package guest
Test Teardown     Close package guest

*** Test Cases ***
The installed package only serves after explicit configuration and enablement
    [Tags]    install-setup    install-fresh
    Then the installed package requires explicit enablement

Updating an armed socket leaves the worker dormant
    [Tags]    install-setup    install-armed
    Given a lease exists with the socket    armed
    When the package is updated
    Then the update caused no worker activation
    And configuration and lease state are preserved
    When the client requests its existing lease
    Then a new worker acknowledges the lease

Updating a disabled socket leaves it disarmed
    [Tags]    install-setup    install-disabled
    [Teardown]    Close package guest    preserve_state=${TRUE}
    Given a lease exists with the socket    disabled
    When the package is updated
    Then the update caused no worker activation
    And configuration and lease state are preserved
    And client traffic leaves the socket disarmed

A previously disabled installation stays disarmed after reboot
    Then the socket remains disarmed after reboot

*** Keywords ***
Prepare package guest
    ${guest}=    Given an isolated DHCP topology    configure=${FALSE}
    Use package guest    ${guest}

Close package guest
    [Arguments]    ${preserve_state}=${FALSE}
    TRY
        Finish package update
    FINALLY
        Clean up the DHCP topology    preserve_state=${preserve_state}
    END
