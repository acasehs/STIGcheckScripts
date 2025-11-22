#!/usr/bin/env bash
################################################################################
# STIG Check: V-214235
# Severity: medium
# Rule Title: The Apache web server log files must only be accessible by privileged users.
# STIG ID: AS24-U1-000180
# Rule ID: SV-214235r960930
#
# Description:
#     Log data is essential in the investigation of events. If log data were to become compromised, competent forensic analysis and discovery of the true source of potentially malicious system activity would be difficult, if not impossible, to achieve. In addition, access to log records provides information an attacker could potentially use to their advantage since each event record might contain communication ports, protocols, services, trust relationships, user names, etc.

The web server must prote
#
# Check Content:
#     Determine the location of the \"HTTPD_ROOT\" directory and the \"httpd.conf\" file:

# apachectl -V | egrep -i '\''httpd_root|server_config_file'\''
-D HTTPD_ROOT=\"/etc/httpd\"
-D SERVER_CONFIG_FILE=\"conf/httpd.conf\"

Note: The apachectl front end is the preferred method for locating the Apache httpd file. For some Linux distributions, \"apache2ctl -V\" or  \"httpd -V\" can also be used.

Work with the Administrator to locate the log files:
Example: /etc/httpd/logs

List the POSIX permission set and owner/group of the log files:
# ls -laH /etc/httpd/logs/*log*
Output Example:
-rw-r------. 1 apache root    0 Sep 27 2020 /etc/httpd/logs/access_log
-rw-r------. 1 apache root 1235 Sep 23 2020 /etc/httpd/logs/access_log-20200927
-rw-r------. 1 apache root  332 Sep 26 03:40 /etc/httpd/logs/error_log

Only system administrators and service accounts running the server should have permissions to the files and the POSIX permissions should be set to 640 or more restrictive

If any users other 
#
# Exit Codes:
#     0 = Check Passed (Compliant)
#     1 = Check Failed (Finding)
#     2 = Check Not Applicable
#     3 = Check Error
################################################################################

# Configuration
VULN_ID="V-214235"
STIG_ID="AS24-U1-000180"
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
    SVC="and"

    running=$(systemctl is-active "$SVC" 2>/dev/null)
    enabled=$(systemctl is-enabled "$SVC" 2>/dev/null)

    if [[ "$running" == "active" ]] && [[ "$enabled" == "enabled" ]]; then
        echo "PASS: Service running and enabled (compliant)"
        [[ -n "$OUTPUT_JSON" ]] && output_json "PASS" "Running" "$SVC"
        exit 0
    else
        echo "FAIL: Service not running/enabled"
        [[ -n "$OUTPUT_JSON" ]] && output_json "FAIL" "Not running" "$SVC"
        exit 1
    fi

}

# Run main check
main "$@"
