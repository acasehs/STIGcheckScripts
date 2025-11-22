#!/usr/bin/env bash
#
# STIG Check: V-221847
# Severity: medium
# Rule Title: The Oracle Linux operating system must be configured so that all networked systems have SSH installed.
# STIG ID: OL07-00-040300
# STIG Version: Oracle Linux 8 v1r7
# Requires Elevation: No
# Third-Party Tools: None (uses yum/rpm)
#
# AUTO-GENERATED: 2025-11-22 04:31:25
# Based on template: V-248519 (package check)

set -eo pipefail

VULN_ID="V-221847"
SEVERITY="medium"
STIG_ID="OL07-00-040300"
RULE_TITLE="The Oracle Linux operating system must be configured so that all networked systems have SSH installed."
STIG_VERSION="Oracle Linux 8 v1r7"

# TODO: Extract actual package name from check content
PACKAGE_NAME="\*ssh\*"

# Check implementation
run_check() {

    # Check if \*ssh\* package is NOT installed
    if ! check_package_installed "\*ssh\*"; then
        STATUS="NotAFinding"
        # Package not installed (as required) - PASS
        return 0
    else
        package_version=$(get_package_version "\*ssh\*")
        STATUS="Open"
        # Package installed (should not be) - FAIL
        return 1
    fi

}

# Main execution
run_check
exit $?
