#!/usr/bin/env bash
################################################################################
# STIG Check: V-248881
# STIG ID: OL08-00-040249
# Severity: medium
# Rule Title: OL 8 must not forward IPv4 source-routed packets by default....
#
# Automated Check: Kernel Parameter Validation
################################################################################

set -euo pipefail

VULN_ID="V-248881"
STIG_ID="OL08-00-040249"
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

PARAM="net.ipv4.conf.default.accept_source_route"
EXPECTED="0"

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
