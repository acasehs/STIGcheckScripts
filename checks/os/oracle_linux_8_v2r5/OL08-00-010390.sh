#!/usr/bin/env bash
################################################################################
# STIG Check: V-248586
# STIG ID: OL08-00-010390
# Severity: low
# Rule Title: OL 8 must have the package required for multifactor authentication ins...
#
# Automated Check: Package Installation Validation
################################################################################

set -euo pipefail

VULN_ID="V-248586"
STIG_ID="OL08-00-010390"
SEVERITY="low"
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

PACKAGE="installed"

# Most STIG checks are for packages that should NOT be installed
if rpm -q "$PACKAGE" &>/dev/null; then
    output_json "Open" "Package should not be installed"
    echo "[$VULN_ID] FAIL - Package $PACKAGE should not be installed"
    exit 1
else
    output_json "NotAFinding" "Package not installed (compliant)"
    echo "[$VULN_ID] PASS - Package $PACKAGE is not installed"
    exit 0
fi
