#!/bin/bash
################################################################################
# STIG Check: V-235928
# Severity: medium
# Rule Title: Oracle WebLogic must utilize cryptography to protect the
#             confidentiality of remote access management sessions.
# STIG ID: WBLC-01-000009
# Requires Elevation: Yes (Read access to WebLogic domain directory)
# Third-Party Tools: None (uses bash, grep, xml parsing)
#
# Description:
#     Checks if Oracle WebLogic servers have SSL Listen Port enabled and
#     non-SSL Listen Port disabled for all servers in the domain by parsing
#     config.xml files directly.
#
# Execution:
#     bash V-235928.sh --domain-home /u01/oracle/user_projects/domains/base_domain
#     bash V-235928.sh --domain-home /u01/oracle/user_projects/domains/base_domain --output-json results.json
#     bash V-235928.sh --domain-home /u01/oracle/user_projects/domains/base_domain --force
#
# Output Formats:
#     - Exit Code: 0 (Pass), 1 (Fail), 2 (Not Applicable), 3 (Error)
#     - JSON: --output-json results.json
#     - Human Readable: Default to stdout
################################################################################

# Default values
DOMAIN_HOME=""
OUTPUT_JSON=""
FORCE=false
VULN_ID="V-235928"
STIG_ID="WBLC-01-000009"
SEVERITY="medium"
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --domain-home)
            DOMAIN_HOME="$2"
            shift 2
            ;;
        --output-json)
            OUTPUT_JSON="$2"
            shift 2
            ;;
        --force)
            FORCE=true
            shift
            ;;
        -h|--help)
            echo "Usage: $0 --domain-home <path> [--output-json <file>] [--force]"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 3
            ;;
    esac
done

# Validate domain home
if [[ -z "$DOMAIN_HOME" ]]; then
    echo "ERROR: --domain-home is required"
    exit 3
fi

if [[ ! -d "$DOMAIN_HOME" ]]; then
    echo "ERROR: Domain home directory does not exist: $DOMAIN_HOME"
    exit 3
fi

CONFIG_FILE="$DOMAIN_HOME/config/config.xml"
if [[ ! -f "$CONFIG_FILE" ]]; then
    echo "ERROR: config.xml not found at: $CONFIG_FILE"
    exit 3
fi

# Check elevation (read access to config.xml)
if [[ ! -r "$CONFIG_FILE" ]] && [[ "$FORCE" != true ]]; then
    echo "ERROR: Cannot read $CONFIG_FILE - insufficient permissions"
    echo "Use --force to attempt execution anyway"
    exit 3
fi

# Initialize results
STATUS="Not Checked"
FINDING_DETAILS=""
EXIT_CODE=0

# Function to extract server configurations from config.xml
check_ssl_configuration() {
    local config_file="$1"
    local findings=()
    local has_findings=false

    # Extract server configurations using grep and sed
    # Look for <server> blocks and check listen-port and ssl settings

    # For simplicity, we'll use xmllint if available, otherwise fall back to grep
    if command -v xmllint &> /dev/null; then
        # Use xmllint to parse XML properly
        local servers=$(xmllint --xpath "//server/name/text()" "$config_file" 2>/dev/null || echo "")

        if [[ -z "$servers" ]]; then
            findings+=("INFO: No servers found or unable to parse config.xml")
            echo "${findings[@]}"
            return 2
        fi

        # Check each server
        while IFS= read -r server_name; do
            [[ -z "$server_name" ]] && continue

            # Check if listen-port is enabled (look for <listen-port-enabled>true</listen-port-enabled>)
            local listen_enabled=$(xmllint --xpath "//server[name='$server_name']/listen-port-enabled/text()" "$config_file" 2>/dev/null || echo "true")

            # Check if SSL is enabled
            local ssl_enabled=$(xmllint --xpath "//server[name='$server_name']/ssl/enabled/text()" "$config_file" 2>/dev/null || echo "false")

            # Check SSL listen port
            local ssl_port=$(xmllint --xpath "//server[name='$server_name']/ssl/listen-port/text()" "$config_file" 2>/dev/null || echo "")

            local finding="Server: $server_name | ListenPortEnabled: $listen_enabled | SSLEnabled: $ssl_enabled | SSLPort: ${ssl_port:-N/A}"

            # Determine if this is a finding
            if [[ "$listen_enabled" == "true" ]]; then
                finding="$finding | STATUS: FAIL | REASON: Listen Port is enabled (should be disabled)"
                has_findings=true
            elif [[ "$ssl_enabled" != "true" ]]; then
                finding="$finding | STATUS: FAIL | REASON: SSL is not enabled"
                has_findings=true
            else
                finding="$finding | STATUS: PASS | REASON: SSL enabled and non-SSL port disabled"
            fi

            findings+=("$finding")
        done <<< "$servers"
    else
        # Fallback: Use grep/sed for basic parsing (less reliable but works without xmllint)
        findings+=("WARNING: xmllint not available, using basic grep parsing")
        findings+=("INFO: Install libxml2-utils for better XML parsing")

        # Basic grep approach - look for server sections
        local server_count=$(grep -c "<server>" "$config_file" || echo "0")

        if [[ "$server_count" -eq 0 ]]; then
            findings+=("INFO: No servers found in config.xml")
            echo "${findings[@]}"
            return 2
        fi

        findings+=("INFO: Found $server_count server(s) in config.xml")
        findings+=("MANUAL: Please verify SSL configuration manually or install xmllint")
        has_findings=true
    fi

    # Set global status
    if [[ "$has_findings" == true ]]; then
        STATUS="Open"
        EXIT_CODE=1
    else
        STATUS="NotAFinding"
        EXIT_CODE=0
    fi

    # Join findings with newlines
    FINDING_DETAILS=$(printf '%s\n' "${findings[@]}")
}

# Run the check
check_ssl_configuration "$CONFIG_FILE"

# Generate output
if [[ -n "$OUTPUT_JSON" ]]; then
    # JSON output
    cat > "$OUTPUT_JSON" << EOF
{
  "vuln_id": "$VULN_ID",
  "severity": "$SEVERITY",
  "stig_id": "$STIG_ID",
  "rule_title": "Oracle WebLogic must utilize cryptography to protect the confidentiality of remote access management sessions.",
  "status": "$STATUS",
  "finding_details": $(echo "$FINDING_DETAILS" | jq -R -s -c 'split("\n")'),
  "timestamp": "$TIMESTAMP",
  "requires_elevation": true,
  "third_party_tools": "None (optional: xmllint for better parsing)",
  "check_method": "Bash script - config.xml parsing",
  "exit_code": $EXIT_CODE
}
EOF
    echo "Results written to: $OUTPUT_JSON"
fi

# Human-readable output (always to stdout unless only JSON requested)
cat << EOF

================================================================================
STIG Check: $VULN_ID - $STIG_ID
Severity: ${SEVERITY^^}
================================================================================
Rule: Oracle WebLogic must utilize cryptography to protect the confidentiality
      of remote access management sessions.
Status: $STATUS
Timestamp: $TIMESTAMP
Requires Elevation: Yes (read access to domain directory)
Third-Party Tools: None (optional: xmllint for better XML parsing)
Check Method: Bash - Direct config.xml parsing

--------------------------------------------------------------------------------
Finding Details:
--------------------------------------------------------------------------------
$FINDING_DETAILS

================================================================================

EOF

exit $EXIT_CODE
