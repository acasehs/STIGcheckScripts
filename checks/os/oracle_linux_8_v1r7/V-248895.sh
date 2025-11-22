#!/usr/bin/env bash
#
# STIG Check: V-248895
# Severity: medium
# Rule Title: OL 8 must be configured to prevent unrestricted mail relaying.
# STIG ID: OL08-00-040290
# STIG Version: Oracle Linux 8 v1r7
# Requires Elevation: No
# Third-Party Tools: None (uses yum/rpm)
#
# AUTO-GENERATED: 2025-11-22 04:22:00
# Based on template: V-248519 (package check)

set -eo pipefail

VULN_ID="V-248895"
SEVERITY="medium"
STIG_ID="OL08-00-040290"
RULE_TITLE="OL 8 must be configured to prevent unrestricted mail relaying."
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
