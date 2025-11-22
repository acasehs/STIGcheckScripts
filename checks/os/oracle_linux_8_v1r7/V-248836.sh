#!/usr/bin/env bash
#
# STIG Check: V-248836
# Severity: medium
# Rule Title: The OL 8 file system automounter must be disabled unless required.
# STIG ID: OL08-00-040070
# STIG Version: Oracle Linux 8 v1r7
#
# AUTO-GENERATED: 2025-11-22 04:22:00
# Based on template: V-248520 (service check)

set -eo pipefail

VULN_ID="V-248836"
SEVERITY="medium"
STIG_ID="OL08-00-040070"
STIG_VERSION="Oracle Linux 8 v1r7"

SERVICE_NAME="autofs"

# Check service status
is_active=$(systemctl is-active "$SERVICE_NAME" 2>/dev/null || echo "inactive")

if [[ "$is_active" == "active" ]]; then
    echo "PASS: Service $SERVICE_NAME is active"
    exit 0
else
    echo "FAIL: Service $SERVICE_NAME is not active (current: $is_active)"
    exit 1
fi
