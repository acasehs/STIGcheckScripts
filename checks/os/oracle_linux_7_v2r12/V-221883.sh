#!/usr/bin/env bash
#
# STIG Check: V-221883
# Severity: medium
# Rule Title: The Oracle Linux operating system must be configured to prevent unrestricted mail relaying.
# STIG ID: OL07-00-040680
# STIG Version: Oracle Linux 8 v1r7
# Requires Elevation: No
# Third-Party Tools: None (uses yum/rpm)
#
# AUTO-GENERATED: 2025-11-22 04:31:25
# Based on template: V-248519 (package check)

set -eo pipefail

VULN_ID="V-221883"
SEVERITY="medium"
STIG_ID="OL07-00-040680"
RULE_TITLE="The Oracle Linux operating system must be configured to prevent unrestricted mail relaying."
STIG_VERSION="Oracle Linux 8 v1r7"

# TODO: Extract actual package name from check content
PACKAGE_NAME="postfix"

# Check implementation
run_check() {

    # Check if postfix package is NOT installed
    if ! check_package_installed "postfix"; then
        STATUS="NotAFinding"
        # Package not installed (as required) - PASS
        return 0
    else
        package_version=$(get_package_version "postfix")
        STATUS="Open"
        # Package installed (should not be) - FAIL
        return 1
    fi

}

# Main execution
run_check
exit $?
