#!/usr/bin/env bash
#
# STIG Check: V-248615
# Severity: medium
# Rule Title: OL 8 must have the rsyslog service enabled and active.
# STIG ID: OL08-00-010561
# STIG Version: Oracle Linux 8 v1r7
#
# AUTO-GENERATED: 2025-11-22 04:22:00
# Based on template: V-248520 (service check)

set -eo pipefail

VULN_ID="V-248615"
SEVERITY="medium"
STIG_ID="OL08-00-010561"
STIG_VERSION="Oracle Linux 8 v1r7"

SERVICE_NAME="rsyslog"

# Check service status
is_active=$(systemctl is-active "$SERVICE_NAME" 2>/dev/null || echo "inactive")

if [[ "$is_active" == "active" ]]; then
    echo "PASS: Service $SERVICE_NAME is active"
    exit 0
else
    echo "FAIL: Service $SERVICE_NAME is not active (current: $is_active)"
    exit 1
fi
