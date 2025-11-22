#!/usr/bin/env bash
################################################################################
# STIG Check: V-248816
# Severity: medium
# Rule Title: OL 8 must encrypt the transfer of audit records offloaded onto a different system or media from the system being audited.
# STIG ID: OL08-00-030710
# Rule ID: SV-248816r958754
#
# Description:
#     Information stored in one location is vulnerable to accidental or incidental deletion or alteration. 
 
Offloading is a common process in information systems with limited audit storage capacity. 
 
OL 8 installation media provides \"rsyslogd\". This is a system utility providing support for message logging. Support for both internet and UNIX domain sockets enables this utility to support both local and remote logging. Coupling this utility with \"gnutls\" (which is a secure communications librar
#
# Check Content:
#     Verify the operating system encrypts audit records offloaded onto a different system or media from the system being audited with the following commands: 
 
$ sudo grep -i '\''$DefaultNetstreamDriver'\'' /etc/rsyslog.conf /etc/rsyslog.d/*.conf 
 
/etc/rsyslog.conf:$DefaultNetstreamDriver gtls 
 
If the value of the \"$DefaultNetstreamDriver\" option is not set to \"gtls\" or the line is commented out, this is a finding. 
 
$ sudo grep -i '\''$ActionSendStreamDriverMode'\'' /etc/rsyslog.conf /etc/rsyslog.d/*.conf 
 
/etc/rsyslog.conf:$ActionSendStreamDriverMode 1 
 
If the value of the \"$ActionSendStreamDriverMode\" option is not set to \"1\" or the line is commented out, this is a finding. 
 
If neither of the definitions above are set, ask the System Administrator to indicate how the audit logs are offloaded to a different system or media.  
 
If there is no evidence that the transfer of the audit logs being offloaded to another system or media is encrypted, this is a finding.
#
# Exit Codes:
#     0 = Check Passed (Compliant)
#     1 = Check Failed (Finding)
#     2 = Check Not Applicable
#     3 = Check Error
################################################################################

# Configuration
VULN_ID="V-248816"
STIG_ID="OL08-00-030710"
SEVERITY="medium"
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
CONFIG_FILE=""
OUTPUT_JSON=""

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --config)
            CONFIG_FILE="$2"
            shift 2
            ;;
        --output-json)
            OUTPUT_JSON="$2"
            shift 2
            ;;
        -h|--help)
            cat << 'EOF'
Usage: $0 [OPTIONS]

Options:
  --config <file>         Configuration file (JSON)
  --output-json <file>    Output results in JSON format
  -h, --help             Show this help message

Exit Codes:
  0 = Pass (Compliant)
  1 = Fail (Finding)
  2 = Not Applicable
  3 = Error

EOF
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 3
            ;;
    esac
done

# Load configuration if provided
if [[ -n "$CONFIG_FILE" ]] && [[ -f "$CONFIG_FILE" ]]; then
    # Source configuration or parse JSON as needed
    :
fi

################################################################################
# HELPER FUNCTIONS
################################################################################

# Output results in JSON format
output_json() {
    local status="$1"
    local message="$2"
    local details="$3"

    cat > "$OUTPUT_JSON" << EOF
{
  "vuln_id": "$VULN_ID",
  "stig_id": "$STIG_ID",
  "severity": "$SEVERITY",
  "status": "$status",
  "message": "$message",
  "details": "$details",
  "timestamp": "$TIMESTAMP"
}
EOF
}

################################################################################
# MAIN CHECK LOGIC
################################################################################

main() {
    CONFIG="/etc/rsyslog.conf"

    if [[ ! -f "$CONFIG" ]]; then
        echo "ERROR: Config file not found"
        [[ -n "$OUTPUT_JSON" ]] && output_json "ERROR" "File not found" "$CONFIG"
        exit 3
    fi

    if grep -q "Unknown" "$CONFIG"; then
        echo "PASS: Directive found in config"
        [[ -n "$OUTPUT_JSON" ]] && output_json "PASS" "Configured" "Unknown"
        exit 0
    else
        echo "FAIL: Directive not found"
        [[ -n "$OUTPUT_JSON" ]] && output_json "FAIL" "Not configured" "Unknown"
        exit 1
    fi

}

# Run main check
main "$@"
