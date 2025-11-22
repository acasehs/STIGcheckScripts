#!/usr/bin/env bash
#
# STIG Check: V-221705
# Severity: high
# Rule Title: The Oracle Linux operating system must not have the ypserv package installed.
# STIG ID: OL07-00-020010
# STIG Version: Oracle Linux 8 v1r7
# Requires Elevation: No
# Third-Party Tools: None (uses yum/rpm)
#
# AUTO-GENERATED: 2025-11-22 04:31:25
# Based on template: V-248519 (package check)

set -eo pipefail

VULN_ID="V-221705"
SEVERITY="high"
STIG_ID="OL07-00-020010"
RULE_TITLE="The Oracle Linux operating system must not have the ypserv package installed."
STIG_VERSION="Oracle Linux 8 v1r7"

# TODO: Extract actual package name from check content
PACKAGE_NAME="is"

# Check implementation
run_check() {

    # Check if is package is NOT installed
    if ! check_package_installed "is"; then
        STATUS="NotAFinding"
        # Package not installed (as required) - PASS
        return 0
    else
        package_version=$(get_package_version "is")
        STATUS="Open"
        # Package installed (should not be) - FAIL
        return 1
    fi

}

# Main execution
run_check
exit $?
