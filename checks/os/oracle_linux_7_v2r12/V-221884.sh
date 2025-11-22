#!/usr/bin/env bash
#
# STIG Check: V-221884
# Severity: high
# Rule Title: The Oracle Linux operating system must not have a File Transfer Protocol (FTP) server package installed unless needed.
# STIG ID: OL07-00-040690
# STIG Version: Oracle Linux 8 v1r7
# Requires Elevation: No
# Third-Party Tools: None (uses yum/rpm)
#
# AUTO-GENERATED: 2025-11-22 04:31:25
# Based on template: V-248519 (package check)

set -eo pipefail

VULN_ID="V-221884"
SEVERITY="high"
STIG_ID="OL07-00-040690"
RULE_TITLE="The Oracle Linux operating system must not have a File Transfer Protocol (FTP) server package installed unless needed."
STIG_VERSION="Oracle Linux 8 v1r7"

# TODO: Extract actual package name from check content
PACKAGE_NAME="vsftpd"

# Check implementation
run_check() {

    # Check if vsftpd package is NOT installed
    if ! check_package_installed "vsftpd"; then
        STATUS="NotAFinding"
        # Package not installed (as required) - PASS
        return 0
    else
        package_version=$(get_package_version "vsftpd")
        STATUS="Open"
        # Package installed (should not be) - FAIL
        return 1
    fi

}

# Main execution
run_check
exit $?
