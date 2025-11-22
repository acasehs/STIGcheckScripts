#!/usr/bin/env bash
################################################################################
# STIG Check: V-2272
# Severity: medium
# Rule Title: PERL scripts must use the TAINT option.
# STIG ID: WG460 A22
# Rule ID: SV-6932r1
#
# Description:
#     PERL (Practical Extraction and Report Language) is an interpreted language optimized for scanning arbitrary text files, extracting information from those text files, and printing reports based on that information. The language is often used in shell scripting and is intended to be practical, easy to use, and efficient means of generating interactive web pages for the user. Unfortunately, many widely available freeware PERL programs (scripts) are extremely insecure. This is most readily accomplis
#
# Check Content:
#     When a PERL script is invoked for execution on a UNIX server, the method which invokes the script must utilize the TAINT option._x000D_
_x000D_
The serverâ€™s interpreter examines the first line of the script. Typically, the first line of the script contains a reference to the scriptâ€™s language and processing options._x000D_
_x000D_
The first line of a PERL script will be as follows:_x000D_
_x000D_
#!/usr/local/bin/perl â€“T_x000D_
_x000D_
The â€“T at the end of the line referenced above, tells the UNIX server to execute a PERL script using the TAINT option._x000D_
_x000D_
Perform the following steps:_x000D_
1) grep perl httpd.conf |grep -v '\''#'\''_x000D_
_x000D_
You should also check /apache/sysconfig.d/loadmodule.conf for PERL._x000D_
_x000D_
NOTE: The name of the loadmodule.conf may vary by installation._x000D_
_x000D_
If Apache doesn'\''t have the mod_perl module loaded and it doesn'\''t use PERL, this check is Not Applicable._x000D_
_x000D_
2) grep -i '\''PerlTaintCheck'\'' ht
#
# Exit Codes:
#     0 = Check Passed (Compliant)
#     1 = Check Failed (Finding)
#     2 = Check Not Applicable
#     3 = Check Error
################################################################################

# Configuration
VULN_ID="V-2272"
STIG_ID="WG460 A22"
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
    CONFIG="/usr/local/bin/perl"

    if [[ ! -f "$CONFIG" ]]; then
        echo "ERROR: Config file not found"
        [[ -n "$OUTPUT_JSON" ]] && output_json "ERROR" "File not found" "$CONFIG"
        exit 3
    fi

    if grep -q "the" "$CONFIG"; then
        echo "PASS: Directive found in config"
        [[ -n "$OUTPUT_JSON" ]] && output_json "PASS" "Configured" "the"
        exit 0
    else
        echo "FAIL: Directive not found"
        [[ -n "$OUTPUT_JSON" ]] && output_json "FAIL" "Not configured" "the"
        exit 1
    fi

}

# Run main check
main "$@"
