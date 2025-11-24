#!/usr/bin/env bash
################################################################################
# STIG Check: V-221875
# STIG ID: OL07-00-040612
# Severity: medium
# Rule Title: The Oracle Linux operating system must use a reverse-path filter for I...
#
# Automated Check: Kernel Parameter Validation
################################################################################

set -euo pipefail

VULN_ID="V-221875"
STIG_ID="OL07-00-040612"
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

PARAM=".d"
EXPECTED="1"

ACTUAL=$(sysctl -n "$PARAM" 2>/dev/null || echo "NOT_SET")

if [[ "$ACTUAL" == "$EXPECTED" ]]; then
    output_json "NotAFinding" "Kernel parameter compliant: $PARAM=$ACTUAL"
    echo "[$VULN_ID] PASS - $PARAM=$ACTUAL"
    exit 0
else
    output_json "Open" "Kernel parameter not compliant: $PARAM=$ACTUAL (expected: $EXPECTED)"
    echo "[$VULN_ID] FAIL - $PARAM=$ACTUAL (expected: $EXPECTED)"
    exit 1
fi
