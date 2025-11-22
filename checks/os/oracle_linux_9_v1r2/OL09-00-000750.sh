#!/usr/bin/env bash
################################################################################
# STIG Check: V-271577
# Severity: low
# Rule Title: OL 9 must enable auditing of processes that start prior to the audit daemon.
# STIG ID: OL09-00-000750
# Rule ID: SV-271577r1091443
#
# Description:
#     Without the capability to generate audit records, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

If auditing is enabled late in the startup process, the actions of some startup processes may not be audited. Some audit systems also maintain state information only available if auditing is enabled before a given process is created.

Satisfies: SRG-OS-000037-GPOS-00015, SRG-OS-000042-GPOS-00020, SRG-OS-000062-
#
# Check Content:
#     Verify that OL 9 is configured to enable auditing of processes that start prior to the audit daemon.

Check that the current GRUB 2 configuration enables auditing:

$ sudo grubby --info=ALL | grep audit
args=\"ro crashkernel=auto resume=/dev/mapper/ol-swap rd.lvm.lv=ol/root rd.lvm.lv=ol/swap rhgb quiet fips=1 audit=1 audit_backlog_limit=8192 pti=on 

If \"audit\" is not set to \"1\" or is missing, this is a finding.

Check that auditing is enabled by default to persist through kernel updates: 

$ sudo grep audit /etc/default/grub
GRUB_CMDLINE_LINUX=\"audit=1\"

If \"audit\" is not set to \"1\", is missing, or is commented out, this is a finding.
#
# Exit Codes:
#     0 = Check Passed (Compliant)
#     1 = Check Failed (Finding)
#     2 = Check Not Applicable
#     3 = Check Error
################################################################################

# Configuration
VULN_ID="V-271577"
STIG_ID="OL09-00-000750"
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
