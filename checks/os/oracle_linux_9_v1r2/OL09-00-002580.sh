#!/usr/bin/env bash
################################################################################
# STIG Check: V-271827
# STIG ID: OL09-00-002580
# Severity: medium
# Rule Title: OL 9 cron configuration directories must have a mode of 0700 or less p...
#
# Automated Check: File Permission Validation
################################################################################

set -euo pipefail

VULN_ID="V-271827"
STIG_ID="OL09-00-002580"
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

FILE_PATH="that"
EXPECTED_PERM="0644"

if [[ ! -e "$FILE_PATH" ]]; then
    output_json "Not_Applicable" "File does not exist: $FILE_PATH"
    echo "[$VULN_ID] N/A - File not found"
    exit 2
fi

ACTUAL_PERM=$(stat -c "%a" "$FILE_PATH" 2>/dev/null)

if [[ "$ACTUAL_PERM" -le "$EXPECTED_PERM" ]]; then
    output_json "NotAFinding" "Permissions compliant: $ACTUAL_PERM"
    echo "[$VULN_ID] PASS - Permissions: $ACTUAL_PERM"
    exit 0
else
    output_json "Open" "Permissions too permissive: $ACTUAL_PERM (expected: $EXPECTED_PERM)"
    echo "[$VULN_ID] FAIL - Permissions: $ACTUAL_PERM (expected: $EXPECTED_PERM)"
    exit 1
fi
