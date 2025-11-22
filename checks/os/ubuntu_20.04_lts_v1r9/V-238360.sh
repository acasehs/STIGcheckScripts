#!/usr/bin/env bash
#
# STIG Check: V-238360
# Severity: medium
# Rule Title: The Ubuntu operating system must be configured to use AppArmor.
# STIG ID: UBTU-20-010439
# STIG Version: Ubuntu 20.04 LTS v1r9
#
# AUTO-GENERATED: 2025-11-22 04:43:06
# Based on template: V-248520 (service check)

set -eo pipefail

VULN_ID="V-238360"
SEVERITY="medium"
STIG_ID="UBTU-20-010439"
STIG_VERSION="Ubuntu 20.04 LTS v1r9"

SERVICE_NAME="apparmor"

# Check service status
is_active=$(systemctl is-active "$SERVICE_NAME" 2>/dev/null || echo "inactive")

if [[ "$is_active" == "active" ]]; then
    echo "PASS: Service $SERVICE_NAME is active"
    exit 0
else
    echo "FAIL: Service $SERVICE_NAME is not active (current: $is_active)"
    exit 1
fi
