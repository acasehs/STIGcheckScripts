#!/usr/bin/env bash
################################################################################
# STIG Check: V-221447
# STIG ID: OH12-1X-000209
# Severity: medium
# Rule Title: A public OHS installation, if hosted on the NIPRNet, must be isolated ...
#
# Automated Check: Oracle HTTP Server Configuration
################################################################################

set -euo pipefail

VULN_ID="V-221447"
STIG_ID="OH12-1X-000209"
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

# Check for Oracle HTTP Server
if [[ -z "$DOMAIN_HOME" ]]; then
    output_json "Not_Applicable" "Oracle HTTP Server not configured (DOMAIN_HOME not set)"
    echo "[$VULN_ID] N/A - OHS not configured"
    exit 2
fi

# Find config file
CONFIG_FILE=$(find "$DOMAIN_HOME/config/fmwconfig/components/OHS/" -name "httpd.conf" 2>/dev/null | head -1)

if [[ -z "$CONFIG_FILE" || ! -f "$CONFIG_FILE" ]]; then
    output_json "Not_Applicable" "Config file not found: httpd.conf"
    echo "[$VULN_ID] N/A - Config file not found"
    exit 2
fi

# Check for directive
DIRECTIVE="DirectiveName"

if grep -qi "^[[:space:]]*$DIRECTIVE" "$CONFIG_FILE" 2>/dev/null; then
    output_json "NotAFinding" "Directive found in configuration"
    echo "[$VULN_ID] PASS - Directive $DIRECTIVE configured"
    exit 0
else
    output_json "Open" "Required directive not found: $DIRECTIVE"
    echo "[$VULN_ID] FAIL - Directive $DIRECTIVE not found"
    exit 1
fi
