#!/usr/bin/env bash
#
# STIG Check: V-221892
# Severity: medium
# Rule Title: The Oracle Linux operating system access control program must be configured to grant or deny system access to specific hosts and services.
# STIG ID: OL07-00-040810
# STIG Version: Oracle Linux 8 v1r7
#
# AUTO-GENERATED: 2025-11-22 04:31:25
# Based on template: V-248520 (service check)

set -eo pipefail

VULN_ID="V-221892"
SEVERITY="medium"
STIG_ID="OL07-00-040810"
STIG_VERSION="Oracle Linux 8 v1r7"

SERVICE_NAME="firewalld"

# Check service status
is_active=$(systemctl is-active "$SERVICE_NAME" 2>/dev/null || echo "inactive")

if [[ "$is_active" == "active" ]]; then
    echo "PASS: Service $SERVICE_NAME is active"
    exit 0
else
    echo "FAIL: Service $SERVICE_NAME is not active (current: $is_active)"
    exit 1
fi
