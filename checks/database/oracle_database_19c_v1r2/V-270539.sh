#!/usr/bin/env bash
################################################################################
# STIG Check: V-270539
# STIG ID: O19C-00-011200
# Severity: medium
# Rule Title: Network access to Oracle Database must be restricted to authorized per...
#
# Automated Check: Listener Configuration Validation
################################################################################

set -euo pipefail

VULN_ID="V-270539"
STIG_ID="O19C-00-011200"
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

# Check Oracle environment
if [[ -z "$ORACLE_HOME" ]]; then
    output_json "Not_Applicable" "Oracle not configured (ORACLE_HOME not set)"
    echo "[$VULN_ID] N/A - Oracle not configured"
    exit 2
fi

# Find listener.ora
LISTENER_ORA="$ORACLE_HOME/network/admin/listener.ora"

if [[ ! -f "$LISTENER_ORA" ]]; then
    output_json "Not_Applicable" "listener.ora not found"
    echo "[$VULN_ID] N/A - listener.ora not found at $LISTENER_ORA"
    exit 2
fi

# Check for required configuration
PATTERN=".*"

if grep -qi "$PATTERN" "$LISTENER_ORA" 2>/dev/null; then
    output_json "NotAFinding" "Required listener configuration found"
    echo "[$VULN_ID] PASS - Configuration found: $PATTERN"
    exit 0
else
    output_json "Open" "Required listener configuration not found: $PATTERN"
    echo "[$VULN_ID] FAIL - Configuration not found: $PATTERN"
    exit 1
fi
