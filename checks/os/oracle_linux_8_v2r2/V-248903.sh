#!/usr/bin/env bash
#
# STIG Check: V-248903
# Severity: high
# Rule Title: A File Transfer Protocol (FTP) server package must not be installed unless mission essential on OL 8.
# STIG ID: OL08-00-040360
# STIG Version: Oracle Linux 8 v2r2
# Requires Elevation: No
# Third-Party Tools: None (uses yum/rpm)
#
# AUTO-GENERATED: 2025-11-22 04:51:30
# Based on template: V-248519 (package check)

set -eo pipefail

VULN_ID="V-248903"
SEVERITY="high"
STIG_ID="OL08-00-040360"
RULE_TITLE="A File Transfer Protocol (FTP) server package must not be installed unless mission essential on OL 8."
STIG_VERSION="Oracle Linux 8 v2r2"

# TODO: Extract actual package name from check content
PACKAGE_NAME="|"

# Check implementation
run_check() {

    # Check if | package is NOT installed
    if ! check_package_installed "|"; then
        STATUS="NotAFinding"
        # Package not installed (as required) - PASS
        return 0
    else
        package_version=$(get_package_version "|")
        STATUS="Open"
        # Package installed (should not be) - FAIL
        return 1
    fi

}

# Main execution
run_check
exit $?
