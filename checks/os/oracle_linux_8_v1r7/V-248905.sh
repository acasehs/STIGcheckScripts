#!/usr/bin/env bash
#
# STIG Check: V-248905
# Severity: medium
# Rule Title: OL 8 must not have the "iprutils" package installed if not required for operational support.
# STIG ID: OL08-00-040380
# STIG Version: Oracle Linux 8 v1r7
# Requires Elevation: No
# Third-Party Tools: None (uses yum/rpm)
#
# AUTO-GENERATED: 2025-11-22 04:22:00
# Based on template: V-248519 (package check)

set -eo pipefail

VULN_ID="V-248905"
SEVERITY="medium"
STIG_ID="OL08-00-040380"
RULE_TITLE="OL 8 must not have the "iprutils" package installed if not required for operational support."
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
