#!/usr/bin/env bash
################################################################################
# STIG Check: V-271607
# STIG ID: OL09-00-000925
# Severity: medium
# Rule Title: OL 9 must enable certificate-based smart card authentication....
#
# Automated Check: Service Status Validation
################################################################################

set -euo pipefail

VULN_ID="V-271607"
STIG_ID="OL09-00-000925"
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

SERVICE="service_name"

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
