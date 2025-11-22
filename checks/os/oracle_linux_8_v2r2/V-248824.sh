#!/usr/bin/env bash
#
# STIG Check: V-248824
# Severity: medium
# Rule Title: OL 8 must not have any automated bug reporting tools installed.
# STIG ID: OL08-00-040001
# STIG Version: Oracle Linux 8 v2r2
# Requires Elevation: No
# Third-Party Tools: None (uses yum/rpm)
#
# AUTO-GENERATED: 2025-11-22 04:51:30
# Based on template: V-248519 (package check)

set -eo pipefail

VULN_ID="V-248824"
SEVERITY="medium"
STIG_ID="OL08-00-040001"
RULE_TITLE="OL 8 must not have any automated bug reporting tools installed."
STIG_VERSION="Oracle Linux 8 v2r2"

# TODO: Extract actual package name from check content
PACKAGE_NAME="abrt*"

# Check implementation
run_check() {

    # Check if abrt* package is NOT installed
    if ! check_package_installed "abrt*"; then
        STATUS="NotAFinding"
        # Package not installed (as required) - PASS
        return 0
    else
        package_version=$(get_package_version "abrt*")
        STATUS="Open"
        # Package installed (should not be) - FAIL
        return 1
    fi

}

# Main execution
run_check
exit $?
