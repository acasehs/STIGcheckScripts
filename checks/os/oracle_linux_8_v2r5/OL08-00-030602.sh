#!/usr/bin/env bash
################################################################################
# STIG Check: V-248804
# Severity: low
# Rule Title: OL 8 must allocate an \"audit_backlog_limit\" of sufficient size to capture processes that start prior to the audit daemon.
# STIG ID: OL08-00-030602
# Rule ID: SV-248804r958412
#
# Description:
#     Without the capability to generate audit records, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. 
 
If auditing is enabled late in the startup process, the actions of some startup processes may not be audited. Some audit systems also maintain state information only available if auditing is enabled before a given process is created. 
 
Audit records can be generated from various components within the informa
#
# Check Content:
#     Verify OL 8 allocates a sufficient \"audit_backlog_limit\" to capture processes that start prior to the audit daemon with the following commands: 
 
$ sudo grub2-editenv list | grep audit 
 
kernelopts=root=/dev/mapper/ol-root ro crashkernel=auto resume=/dev/mapper/ol-swap rd.lvm.lv=ol/root rd.lvm.lv=ol/swap rhgb quiet fips=1 audit=1 audit_backlog_limit=8192 boot=UUID=8d171156-cd61-421c-ba41-1c021ac29e82 
 
If the \"audit_backlog_limit\" entry does not equal \"8192\" or larger, is missing, or the line is commented out, this is a finding. 
 
Verify \"audit_backlog_limit\" is set to persist in kernel updates:  
 
$ sudo grep audit /etc/default/grub 
 
GRUB_CMDLINE_LINUX=\"audit_backlog_limit=8192\" 
 
If \"audit_backlog_limit\" is not set to \"8192\" or larger or is missing or commented out, this is a finding.
#
# Exit Codes:
#     0 = Check Passed (Compliant)
#     1 = Check Failed (Finding)
#     2 = Check Not Applicable
#     3 = Check Error
################################################################################

# Configuration
VULN_ID="V-248804"
STIG_ID="OL08-00-030602"
SEVERITY="low"
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
    SVC="audit"

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
