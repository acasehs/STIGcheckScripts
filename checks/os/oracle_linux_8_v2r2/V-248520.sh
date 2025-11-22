#!/usr/bin/env bash
#
# STIG Check: V-248520
# Severity: medium
# Rule Title: OL 8 audit records must contain information to establish what type of events occurred, the source of events, where events occurred, and the outcome of events.
# STIG ID: OL08-00-030181
# STIG Version: Oracle Linux 8 v2r2
#
# AUTO-GENERATED: 2025-11-22 04:51:30
# Based on template: V-248520 (service check)

set -eo pipefail

VULN_ID="V-248520"
SEVERITY="medium"
STIG_ID="OL08-00-030181"
STIG_VERSION="Oracle Linux 8 v2r2"

SERVICE_NAME="auditd"

# Check service status
is_active=$(systemctl is-active "$SERVICE_NAME" 2>/dev/null || echo "inactive")

if [[ "$is_active" == "active" ]]; then
    echo "PASS: Service $SERVICE_NAME is active"
    exit 0
else
    echo "FAIL: Service $SERVICE_NAME is not active (current: $is_active)"
    exit 1
fi
