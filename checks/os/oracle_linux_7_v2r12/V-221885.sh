#!/usr/bin/env bash
################################################################################
# STIG Check: V-221885
# STIG ID: OL07-00-040700
# Severity: high
# Rule Title: The Oracle Linux operating system must not have the Trivial File Trans...
#
# Automated Check: Package Installation Validation
################################################################################

set -euo pipefail

VULN_ID="V-221885"
STIG_ID="OL07-00-040700"
SEVERITY="high"
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

if rpm -q "$PACKAGE" &>/dev/null; then
    if [[ true ]]; then
        output_json "NotAFinding" "Package is installed (compliant)"
        echo "[$VULN_ID] PASS - Package $PACKAGE is installed"
        exit 0
    else
        output_json "Open" "Package should be installed"
        echo "[$VULN_ID] FAIL - Package $PACKAGE should be installed"
        exit 1
    fi
else
    if [[ false ]]; then
        output_json "NotAFinding" "Package not installed (compliant)"
        echo "[$VULN_ID] PASS - Package $PACKAGE is not installed"
        exit 0
    else
        output_json "Open" "Required package not installed"
        echo "[$VULN_ID] FAIL - Package $PACKAGE should be installed"
        exit 1
    fi
fi
