#!/usr/bin/env bash
################################################################################
# STIG Check: V-271755
# STIG ID: OL09-00-002417
# Severity: medium
# Rule Title: OL 9 must maintain an account lock until the locked account is release...
#
# Automated Check: Configuration Parameter Validation
################################################################################

set -euo pipefail

VULN_ID="V-271755"
STIG_ID="OL09-00-002417"
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

CONFIG_FILE="/etc/security/faillock.conf"
PATTERN="unlock_time ="

if [[ ! -f "$CONFIG_FILE" ]]; then
    output_json "Not_Applicable" "Config file not found: $CONFIG_FILE"
    echo "[$VULN_ID] N/A - Config file not found"
    exit 2
fi

if grep -q "$PATTERN" "$CONFIG_FILE" 2>/dev/null; then
    output_json "NotAFinding" "Required configuration found"
    echo "[$VULN_ID] PASS - Configuration found: $PATTERN"
    exit 0
else
    output_json "Open" "Required configuration not found: $PATTERN"
    echo "[$VULN_ID] FAIL - Configuration not found: $PATTERN"
    exit 1
fi
