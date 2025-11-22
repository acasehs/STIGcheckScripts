#!/usr/bin/env bash
#
# STIG Check: V-221652
# Severity: high
# Rule Title: The Oracle Linux operating system must be configured so that the file permissions, ownership, and group membership of system files and commands match the vendor values.
# STIG ID: OL07-00-010010
# STIG Version: Oracle Linux 8 v1r7
# Requires Elevation: No
# Third-Party Tools: None (uses yum/rpm)
#
# AUTO-GENERATED: 2025-11-22 04:31:25
# Based on template: V-248519 (package check)

set -eo pipefail

VULN_ID="V-221652"
SEVERITY="high"
STIG_ID="OL07-00-010010"
RULE_TITLE="The Oracle Linux operating system must be configured so that the file permissions, ownership, and group membership of system files and commands match the vendor values."
STIG_VERSION="Oracle Linux 8 v1r7"

# TODO: Extract actual package name from check content
PACKAGE_NAME="PACKAGE_NAME"

# Check implementation
run_check() {

    # Check if PACKAGE_NAME package is NOT installed
    if ! check_package_installed "PACKAGE_NAME"; then
        STATUS="NotAFinding"
        # Package not installed (as required) - PASS
        return 0
    else
        package_version=$(get_package_version "PACKAGE_NAME")
        STATUS="Open"
        # Package installed (should not be) - FAIL
        return 1
    fi

}

# Main execution
run_check
exit $?
