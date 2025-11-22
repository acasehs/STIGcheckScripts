#!/usr/bin/env bash
#
# STIG Check: V-256977
# Severity: medium
# Rule Title: The Oracle Linux operating system must be configured to allow sending email notifications of unauthorized configuration changes to designated personnel.
# STIG ID: OL07-00-020028
# STIG Version: Oracle Linux 8 v1r7
# Requires Elevation: No
# Third-Party Tools: None (uses yum/rpm)
#
# AUTO-GENERATED: 2025-11-22 04:31:25
# Based on template: V-248519 (package check)

set -eo pipefail

VULN_ID="V-256977"
SEVERITY="medium"
STIG_ID="OL07-00-020028"
RULE_TITLE="The Oracle Linux operating system must be configured to allow sending email notifications of unauthorized configuration changes to designated personnel."
STIG_VERSION="Oracle Linux 8 v1r7"

# TODO: Extract actual package name from check content
PACKAGE_NAME="provides"

# Check implementation
run_check() {

    # Check if provides package is NOT installed
    if ! check_package_installed "provides"; then
        STATUS="NotAFinding"
        # Package not installed (as required) - PASS
        return 0
    else
        package_version=$(get_package_version "provides")
        STATUS="Open"
        # Package installed (should not be) - FAIL
        return 1
    fi

}

# Main execution
run_check
exit $?
