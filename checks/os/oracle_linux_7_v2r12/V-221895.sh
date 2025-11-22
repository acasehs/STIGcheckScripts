#!/usr/bin/env bash
#
# STIG Check: V-221895
# Severity: medium
# Rule Title: The Oracle Linux operating system must have the required packages for multifactor authentication installed.
# STIG ID: OL07-00-041001
# STIG Version: Oracle Linux 8 v1r7
# Requires Elevation: No
# Third-Party Tools: None (uses yum/rpm)
#
# AUTO-GENERATED: 2025-11-22 04:31:25
# Based on template: V-248519 (package check)

set -eo pipefail

VULN_ID="V-221895"
SEVERITY="medium"
STIG_ID="OL07-00-041001"
RULE_TITLE="The Oracle Linux operating system must have the required packages for multifactor authentication installed."
STIG_VERSION="Oracle Linux 8 v1r7"

# TODO: Extract actual package name from check content
PACKAGE_NAME="pam_pkcs11"

# Check implementation
run_check() {

    # Check if pam_pkcs11 package is NOT installed
    if ! check_package_installed "pam_pkcs11"; then
        STATUS="NotAFinding"
        # Package not installed (as required) - PASS
        return 0
    else
        package_version=$(get_package_version "pam_pkcs11")
        STATUS="Open"
        # Package installed (should not be) - FAIL
        return 1
    fi

}

# Main execution
run_check
exit $?
