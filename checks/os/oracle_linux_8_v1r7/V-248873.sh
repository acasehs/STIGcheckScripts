#!/usr/bin/env bash
#
# STIG Check: V-248873
# Severity: high
# Rule Title: The Trivial File Transfer Protocol (TFTP) server package must not be installed if not required for OL 8 operational support.
# STIG ID: OL08-00-040190
# STIG Version: Oracle Linux 8 v1r7
# Requires Elevation: No
# Third-Party Tools: None (uses yum/rpm)
#
# AUTO-GENERATED: 2025-11-22 04:22:00
# Based on template: V-248519 (package check)

set -eo pipefail

VULN_ID="V-248873"
SEVERITY="high"
STIG_ID="OL08-00-040190"
RULE_TITLE="The Trivial File Transfer Protocol (TFTP) server package must not be installed if not required for OL 8 operational support."
STIG_VERSION="Oracle Linux 8 v1r7"

# TODO: Extract actual package name from check content
PACKAGE_NAME="tftp-server"

# Check implementation
run_check() {

    # Check if tftp-server package is NOT installed
    if ! check_package_installed "tftp-server"; then
        STATUS="NotAFinding"
        # Package not installed (as required) - PASS
        return 0
    else
        package_version=$(get_package_version "tftp-server")
        STATUS="Open"
        # Package installed (should not be) - FAIL
        return 1
    fi

}

# Main execution
run_check
exit $?
