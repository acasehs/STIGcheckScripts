#!/usr/bin/env bash
#
# STIG Check: V-221764
# Severity: medium
# Rule Title: The Oracle Linux operating system must be configured so that auditing is configured to produce records containing information to establish what type of events occurred, where the events occurred, the source of the events, and the outcome of the events. These audit records must also identify individual identities of group account users.
# STIG ID: OL07-00-030000
# STIG Version: Oracle Linux 8 v1r7
#
# AUTO-GENERATED: 2025-11-22 04:31:25
# Based on template: V-248520 (service check)

set -eo pipefail

VULN_ID="V-221764"
SEVERITY="medium"
STIG_ID="OL07-00-030000"
STIG_VERSION="Oracle Linux 8 v1r7"

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
