#!/usr/bin/env bash
#
# STIG Check: V-248841
# Severity: medium
# Rule Title: A firewall must be active on OL 8.
# STIG ID: OL08-00-040101
# STIG Version: Oracle Linux 8 v2r2
#
# AUTO-GENERATED: 2025-11-22 04:51:30
# Based on template: V-248520 (service check)

set -eo pipefail

VULN_ID="V-248841"
SEVERITY="medium"
STIG_ID="OL08-00-040101"
STIG_VERSION="Oracle Linux 8 v2r2"

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
