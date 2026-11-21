*** Settings ***
Documentation     Optional issue 37 production-path flood and renewal acceptance.
Library           keywords.LoadAcceptance.LoadAcceptance

*** Test Cases ***
Load clients receive unicast renewals on both links
    When ten clients on each link renew their leases
    Then every client receives a safe unicast renewal

Independent Workers Meet Flood And Renewal Budgets
    Given measured load testing is enabled
    When the workers run under baseline and flood load
    Then both workers meet the load and renewal budgets
