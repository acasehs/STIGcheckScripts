#!/usr/bin/env bash
################################################################################
# STIG Check: V-248541
# STIG ID: OL08-00-010151
# Severity: medium
# Rule Title: OL 8 operating systems must require authentication upon booting into r...
#
# Automated Check: Service Status Validation
################################################################################

set -euo pipefail

VULN_ID="V-248541"
STIG_ID="OL08-00-010151"
SEVERITY="medium"
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
OUTPUT_JSON=""

while [[ $# -gt 0 ]]; do
    case $1 in --output-json) OUTPUT_JSON="$2"; shift 2;; *) shift;; esac
done

output_json() {
    [[ -n "$OUTPUT_JSON" ]] && cat > "$OUTPUT_JSON" << EOF
{"vuln_id":"$VULN_ID","stig_id":"$STIG_ID","severity":"$SEVERITY","status":"$1","finding_details":"$2","timestamp":"$TIMESTAMP"}
EOF
}

SERVICE="ExecStart"

if ! systemctl list-unit-files "$SERVICE" &>/dev/null; then
    output_json "Not_Applicable" "Service not found: $SERVICE"
    echo "[$VULN_ID] N/A - Service not found"
    exit 2
fi

# Check service status - most checks are for disabled services
if systemctl is-enabled "$SERVICE" &>/dev/null || systemctl is-active "$SERVICE" &>/dev/null; then
    output_json "Open" "Service is enabled or active"
    echo "[$VULN_ID] FAIL - Service is enabled/active"
    exit 1
else
    output_json "NotAFinding" "Service is disabled and inactive (compliant)"
    echo "[$VULN_ID] PASS - Service is disabled"
    exit 0
fi
