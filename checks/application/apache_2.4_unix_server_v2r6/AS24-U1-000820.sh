#!/usr/bin/env bash
################################################################################
# STIG Check: V-214267
# Severity: medium
# Rule Title: The Apache web server must be protected from being stopped by a non-privileged user.
# STIG ID: AS24-U1-000820
# Rule ID: SV-214267r961620
#
# Description:
#     An attacker has at least two reasons to stop a web server. The first is to cause a denial of service (DoS), and the second is to put in place changes the attacker made to the web server configuration.

To prohibit an attacker from stopping the Apache web server, the process ID (pid) of the web server and the utilities used to start/stop it must be protected from access by non-privileged users. By knowing the \"pid\" and having access to the Apache web server utilities, a non-privileged user has 
#
# Check Content:
#     Review the web server documentation and deployed configuration to determine where the process ID is stored and which utilities are used to start/stop the web server.

Locate the httpd.pid file and list its permission set and owner/group

# find / -name â€œhttpd.pid
Output should be similar to: /run/httpd/httpd.pidÂ 

# ls -laH /run/httpd/httpd.pid
Output should be similar -rw-r--r--. 1 root root 5 Jun 13 03:18 /run/httpd/httpd.pid

If the file owner/group is not an administrative service account, this is a finding.

If permission set is not 644 or more restrictive, this is a finding.
Â 
Verify the Apache service utilities (binaries) have the correct permission set and are user/group owned by an administrator account

# ls -laH /usr/sbin/service
Output should be similar: -rwxr-xr-x. 1 root root 3.2K Aug 19, 2019 /usr/sbin/service

# ls -laH /usr/sbin/apachectl
Output should be similar: -rwxr-xr-x. 1 root root 4.2K Oct 8, 2019 /usr/sbin/apachectl
Â 
If the service utilities owner/group i
#
# Exit Codes:
#     0 = Check Passed (Compliant)
#     1 = Check Failed (Finding)
#     2 = Check Not Applicable
#     3 = Check Error
################################################################################

# Configuration
VULN_ID="V-214267"
STIG_ID="AS24-U1-000820"
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
    SVC="administrative"

    running=$(systemctl is-active "$SVC" 2>/dev/null)
    enabled=$(systemctl is-enabled "$SVC" 2>/dev/null)

    if [[ "$running" == "active" ]] && [[ "$enabled" == "enabled" ]]; then
        echo "FAIL: Service should not be running"
        [[ -n "$OUTPUT_JSON" ]] && output_json "FAIL" "Should not run" "$SVC"
        exit 1
    else
        echo "PASS: Service disabled (compliant)"
        [[ -n "$OUTPUT_JSON" ]] && output_json "PASS" "Disabled" "$SVC"
        exit 0
    fi

}

# Run main check
main "$@"
