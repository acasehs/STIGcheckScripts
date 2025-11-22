#!/usr/bin/env bash
#
# STIG Check: V-251701
# Severity: medium
# Rule Title: The Oracle Linux operating system must use a file integrity tool to verify correct operation of all security functions.
# STIG ID: OL07-00-020029
# STIG Version: Oracle Linux 8 v1r7
# Requires Elevation: No
# Third-Party Tools: None (uses yum/rpm)
#
# AUTO-GENERATED: 2025-11-22 04:31:25
# Based on template: V-248519 (package check)

set -eo pipefail

VULN_ID="V-251701"
SEVERITY="medium"
STIG_ID="OL07-00-020029"
RULE_TITLE="The Oracle Linux operating system must use a file integrity tool to verify correct operation of all security functions."
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
