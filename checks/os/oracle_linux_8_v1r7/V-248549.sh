#!/usr/bin/env bash
#
# STIG Check: V-248549
# Severity: low
# Rule Title: OL 8 must have the "policycoreutils" package installed.
# STIG ID: OL08-00-010171
# STIG Version: Oracle Linux 8 v1r7
# Requires Elevation: No
# Third-Party Tools: None (uses yum/rpm)
#
# AUTO-GENERATED: 2025-11-22 04:22:00
# Based on template: V-248519 (package check)

set -eo pipefail

VULN_ID="V-248549"
SEVERITY="low"
STIG_ID="OL08-00-010171"
RULE_TITLE="OL 8 must have the "policycoreutils" package installed."
STIG_VERSION="Oracle Linux 8 v1r7"

# TODO: Extract actual package name from check content
PACKAGE_NAME="installed"

# Check implementation
run_check() {

    # Check if installed package is NOT installed
    if ! check_package_installed "installed"; then
        STATUS="NotAFinding"
        # Package not installed (as required) - PASS
        return 0
    else
        package_version=$(get_package_version "installed")
        STATUS="Open"
        # Package installed (should not be) - FAIL
        return 1
    fi

}

# Main execution
run_check
exit $?
