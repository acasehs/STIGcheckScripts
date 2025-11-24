#!/usr/bin/env bash
################################################################################
# STIG Check: V-221516
# STIG ID: OH12-1X-000301
# Severity: medium
# Rule Title: OHS must have the SSLCipherSuite directive enabled so SSL requests can...
#
# Automated Check: Oracle HTTP Server Configuration Validation
################################################################################

set -euo pipefail

VULN_ID="V-221516"
STIG_ID="OH12-1X-000301"
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

# Check for Oracle HTTP Server installation
if [[ -z "$DOMAIN_HOME" ]]; then
    output_json "Not_Applicable" "Oracle HTTP Server not configured (DOMAIN_HOME not set)"
    echo "[$VULN_ID] N/A - OHS not configured"
    exit 2
fi

CONFIG_FILE="$DOMAIN_HOME/config/fmwconfig/components/OHS/*/httpd.conf"
DIRECTIVE="SSLCipherSuite"

# Find actual config file
ACTUAL_CONFIG=$(find "$DOMAIN_HOME/config/fmwconfig/components/OHS/" -name "httpd.conf" 2>/dev/null | head -1)

if [[ -z "$ACTUAL_CONFIG" || ! -f "$ACTUAL_CONFIG" ]]; then
    output_json "Not_Applicable" "Config file not found: httpd.conf"
    echo "[$VULN_ID] N/A - Config file not found"
    exit 2
fi

# Check for directive
if grep -qi "^[[:space:]]*$DIRECTIVE" "$ACTUAL_CONFIG" 2>/dev/null; then
    output_json "NotAFinding" "Directive found in configuration"
    echo "[$VULN_ID] PASS - Directive $DIRECTIVE configured"
    exit 0
else
    output_json "Open" "Required directive not found: $DIRECTIVE"
    echo "[$VULN_ID] FAIL - Directive $DIRECTIVE not found"
    exit 1
fi
