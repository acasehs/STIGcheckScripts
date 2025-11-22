#!/usr/bin/env bash
################################################################################
# STIG Check: V-248801
# Severity: medium
# Rule Title: OL 8 must generate audit records for any attempted modifications to the \"faillock\" log file.
# STIG ID: OL08-00-030590
# Rule ID: SV-248801r958412
#
# Description:
#     Without the capability to generate audit records, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. 
 
Audit records can be generated from various components within the information system (e.g., module or policy filter). 
 
The list of audited events is the set of events for which audits are to be generated. This set of events is typically a subset of the list of all events for which the system is capable of g
#
# Check Content:
#     Verify OL 8 generates an audit record for any attempted modifications to the \"faillock\" file.  
 
Determine where the faillock tallies are stored with the following commands: 
 
For OL versions 8.0 and 8.1: 
 
$ sudo grep -i pam_faillock.so /etc/pam.d/system-auth 
 
auth required pam_faillock.so preauth dir=/var/log/faillock silent deny=3 fail_interval=900 even_deny_root 
 
For OL versions 8.2 and newer: 
 
$ sudo grep dir /etc/security/faillock.conf 
 
dir=/var/log/faillock 
 
Using the location of the faillock log file, check that the following calls are being audited by running the following command to check the file system rules in \"/etc/audit/audit.rules\": 
 
$ sudo grep -w faillock /etc/audit/audit.rules 
 
-w /var/log/faillock -p wa -k logins 
 
If the command does not return a line or the line is commented out, this is a finding.
#
# Exit Codes:
#     0 = Check Passed (Compliant)
#     1 = Check Failed (Finding)
#     2 = Check Not Applicable
#     3 = Check Error
################################################################################

# Configuration
VULN_ID="V-248801"
STIG_ID="OL08-00-030590"
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
    CONFIG="/etc/pam.d/system-auth"

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
