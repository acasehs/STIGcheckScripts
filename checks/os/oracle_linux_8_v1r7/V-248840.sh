#!/usr/bin/env bash
#
# STIG Check: V-248840
# Severity: medium
# Rule Title: A firewall must be installed on OL 8.
# STIG ID: OL08-00-040100
# STIG Version: Oracle Linux 8 v1r7
# Requires Elevation: No
# Third-Party Tools: None (uses yum/rpm)
#
# AUTO-GENERATED: 2025-11-22 04:22:00
# Based on template: V-248519 (package check)

set -eo pipefail

VULN_ID="V-248840"
SEVERITY="medium"
STIG_ID="OL08-00-040100"
RULE_TITLE="A firewall must be installed on OL 8."
STIG_VERSION="Oracle Linux 8 v1r7"

# TODO: Extract actual package name from check content
PACKAGE_NAME="firewalld"

# Check implementation
run_check() {

    # Check if firewalld package is installed
    if check_package_installed "firewalld"; then
        package_version=$(get_package_version "firewalld")
        STATUS="NotAFinding"
        # Package is installed - PASS
        # (Add audit evidence here)
        return 0
    else
        STATUS="Open"
        # Package not installed - FAIL
        # (Add compliance issues here)
        return 1
    fi

}

# Main execution
run_check
exit $?
