#!/usr/bin/env bash
#
# STIG Check: V-248859
# Severity: medium
# Rule Title: The OL 8 "fapolicy" module must be installed.
# STIG ID: OL08-00-040135
# STIG Version: Oracle Linux 8 v2r2
# Requires Elevation: No
# Third-Party Tools: None (uses yum/rpm)
#
# AUTO-GENERATED: 2025-11-22 04:51:30
# Based on template: V-248519 (package check)

set -eo pipefail

VULN_ID="V-248859"
SEVERITY="medium"
STIG_ID="OL08-00-040135"
RULE_TITLE="The OL 8 "fapolicy" module must be installed."
STIG_VERSION="Oracle Linux 8 v2r2"

# TODO: Extract actual package name from check content
PACKAGE_NAME="fapolicyd"

# Check implementation
run_check() {

    # Check if fapolicyd package is installed
    if check_package_installed "fapolicyd"; then
        package_version=$(get_package_version "fapolicyd")
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
