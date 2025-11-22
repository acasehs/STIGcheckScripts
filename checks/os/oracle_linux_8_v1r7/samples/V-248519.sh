#!/usr/bin/env bash
#
# STIG Check: V-248519
# Severity: medium
# Rule Title: The OL 8 audit package must be installed.
# STIG ID: OL08-00-030180
# STIG Version: Oracle Linux 8 v1r7
# Requires Elevation: No (package query doesn't require root)
# Third-Party Tools: None (uses native yum/rpm)
#
# Description:
#     Verifies that the audit package is installed on the system.
#     The audit service is required for security auditing and compliance.
#
# Execution:
#     bash V-248519.sh
#     bash V-248519.sh --config stig-config.json
#     bash V-248519.sh --config stig-config.json --output-json results.json
#
# Output Formats:
#     - Exit Code: 0 (Pass), 1 (Fail), 2 (Not Applicable), 3 (Error)
#     - JSON: --output-json results.json
#     - Human Readable: Default to stdout

set -eo pipefail

# Global variables
VULN_ID="V-248519"
SEVERITY="medium"
STIG_ID="OL08-00-030180"
RULE_TITLE="The OL 8 audit package must be installed."
STIG_VERSION="Oracle Linux 8 v1r7"

REQUIRED_PACKAGE="audit"
CONFIG_FILE=""
OUTPUT_JSON=""
FORCE=false

# Results tracking
STATUS="Not Checked"
FINDING_DETAILS=()
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

# Parse command line arguments
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
        --force)
            FORCE=true
            shift
            ;;
        --help)
            echo "Usage: $0 [OPTIONS]"
            echo "Options:"
            echo "  --config FILE         Configuration file (JSON)"
            echo "  --output-json FILE    Output results to JSON file"
            echo "  --force               Force execution (ignore elevation checks)"
            echo "  --help                Show this help message"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Use --help for usage information"
            exit 3
            ;;
    esac
done

# Load configuration file if provided
if [[ -n "$CONFIG_FILE" ]]; then
    if [[ ! -f "$CONFIG_FILE" ]]; then
        echo "ERROR: Configuration file not found: $CONFIG_FILE"
        exit 3
    fi

    if command -v jq &> /dev/null; then
        # Override REQUIRED_PACKAGE if specified in config
        PACKAGE_FROM_CONFIG=$(jq -r '.operating_system.required_packages.values[]? // empty' "$CONFIG_FILE" 2>/dev/null | grep -w "audit" || echo "")
        if [[ -n "$PACKAGE_FROM_CONFIG" ]]; then
            echo "INFO: Loaded configuration from $CONFIG_FILE"
            echo "  - Required package: $REQUIRED_PACKAGE (verified in config)"
        fi
    else
        echo "WARNING: jq not installed, using default values"
    fi
fi

# Function to add finding details
add_finding() {
    FINDING_DETAILS+=("$1")
}

# Function to check if package is installed
check_package_installed() {
    local package="$1"

    # Try yum first (Oracle Linux 8 default)
    if command -v yum &> /dev/null; then
        if yum list installed "$package" &> /dev/null; then
            return 0
        fi
    fi

    # Fallback to rpm
    if command -v rpm &> /dev/null; then
        if rpm -q "$package" &> /dev/null; then
            return 0
        fi
    fi

    return 1
}

# Function to get package version
get_package_version() {
    local package="$1"

    if command -v rpm &> /dev/null; then
        rpm -q "$package" 2>/dev/null || echo "unknown"
    else
        echo "unknown"
    fi
}

# Main check logic
run_check() {
    local package_version

    # Check if audit package is installed
    if check_package_installed "$REQUIRED_PACKAGE"; then
        package_version=$(get_package_version "$REQUIRED_PACKAGE")

        STATUS="NotAFinding"

        # Build finding details with audit evidence
        cat <<EOF | add_finding "$(cat)"
{
  "package": "$REQUIRED_PACKAGE",
  "status": "PASS",
  "reason": "Required audit package is installed",
  "check_details": {
    "what_was_checked": "Audit package installation status",
    "requirement": "The audit package must be installed for security auditing",
    "actual_configuration": {
      "package_name": "$REQUIRED_PACKAGE",
      "installed": "true",
      "version": "$package_version"
    },
    "expected_configuration": {
      "package_name": "$REQUIRED_PACKAGE",
      "installed": "true",
      "version": "any"
    }
  },
  "evidence": {
    "package_installed": "Package '$REQUIRED_PACKAGE' is installed",
    "package_version": "Version: $package_version",
    "verification_method": "Verified using yum/rpm package manager",
    "conclusion": "System meets audit package installation requirements"
  }
}
EOF

        return 0  # PASS

    else
        STATUS="Open"

        # Build finding details with compliance issues
        cat <<EOF | add_finding "$(cat)"
{
  "package": "$REQUIRED_PACKAGE",
  "status": "FAIL",
  "reason": "Required audit package is not installed",
  "check_details": {
    "what_was_checked": "Audit package installation status",
    "requirement": "The audit package must be installed for security auditing",
    "actual_configuration": {
      "package_name": "$REQUIRED_PACKAGE",
      "installed": "false",
      "version": "N/A"
    },
    "expected_configuration": {
      "package_name": "$REQUIRED_PACKAGE",
      "installed": "true",
      "version": "any"
    }
  },
  "compliance_issues": [
    {
      "issue": "Audit package not installed",
      "evidence": "Package '$REQUIRED_PACKAGE' is not present on the system",
      "expected": "Package '$REQUIRED_PACKAGE' must be installed",
      "risk": "Without the audit package, the system cannot perform security auditing, making it difficult to investigate security incidents and maintain compliance",
      "remediation": "Install the audit package using: sudo yum install $REQUIRED_PACKAGE"
    }
  ],
  "recommendation": "Install the audit package immediately to enable security auditing"
}
EOF

        return 1  # FAIL
    fi
}

# Function to output results in JSON format
output_json() {
    local exit_code=$1

    cat > "$OUTPUT_JSON" <<EOF
{
  "vuln_id": "$VULN_ID",
  "severity": "$SEVERITY",
  "stig_id": "$STIG_ID",
  "stig_version": "$STIG_VERSION",
  "rule_title": "$RULE_TITLE",
  "status": "$STATUS",
  "finding_details": [
$(printf '%s\n' "${FINDING_DETAILS[@]}" | sed '$ ! s/$/,/')
  ],
  "timestamp": "$TIMESTAMP",
  "requires_elevation": false,
  "third_party_tools": "None (uses yum/rpm)",
  "check_method": "Bash - Native package manager query",
  "config_file": "${CONFIG_FILE:-None (using defaults)}",
  "exit_code": $exit_code
}
EOF

    echo "Results written to: $OUTPUT_JSON"
}

# Function to print human-readable results
print_results() {
    echo ""
    echo "================================================================================"
    echo "STIG Check: $VULN_ID - $STIG_ID"
    echo "STIG Version: $STIG_VERSION"
    echo "Severity: ${SEVERITY^^}"
    echo "================================================================================"
    echo "Rule: $RULE_TITLE"
    echo "Status: $STATUS"
    echo "Timestamp: $TIMESTAMP"
    echo "Requires Elevation: No"
    echo "Third-Party Tools: None (uses yum/rpm)"
    echo "Check Method: Bash - Native package manager query"
    echo ""
    echo "--------------------------------------------------------------------------------"
    echo "Finding Details:"
    echo "--------------------------------------------------------------------------------"

    # Parse and print finding details
    for detail in "${FINDING_DETAILS[@]}"; do
        echo "$detail" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    print(f\"\\nPackage: {data.get('package', 'N/A')}\")
    print(f\"  Status: {data.get('status', 'N/A')}\")
    print(f\"  Reason: {data.get('reason', 'N/A')}\")

    if 'check_details' in data:
        check_info = data['check_details']
        print(f\"\\n  What Was Checked:\")
        print(f\"    {check_info.get('what_was_checked', 'N/A')}\")
        print(f\"  Requirement:\")
        print(f\"    {check_info.get('requirement', 'N/A')}\")

    if data.get('status') == 'FAIL' and 'compliance_issues' in data:
        print(f\"\\n  Compliance Issues ({len(data['compliance_issues'])}):\" )
        for i, issue in enumerate(data['compliance_issues'], 1):
            print(f\"\\n    Issue #{i}: {issue.get('issue', 'N/A')}\")
            print(f\"      Evidence Found: {issue.get('evidence', 'N/A')}\")
            print(f\"      Expected: {issue.get('expected', 'N/A')}\")
            print(f\"      Risk: {issue.get('risk', 'N/A')}\")
            print(f\"      Remediation: {issue.get('remediation', 'N/A')}\")

        if 'recommendation' in data:
            print(f\"\\n  Recommendation: {data['recommendation']}\")

    elif data.get('status') == 'PASS' and 'evidence' in data:
        print(f\"\\n  Evidence Supporting PASS:\")
        evidence = data['evidence']
        for key, value in evidence.items():
            if key != 'conclusion':
                print(f\"    ✓ {value}\")
        if 'conclusion' in evidence:
            print(f\"\\n  Conclusion: {evidence['conclusion']}\")

    if 'check_details' in data:
        check_info = data['check_details']
        if 'actual_configuration' in check_info:
            print(f\"\\n  Actual Configuration:\")
            for key, value in check_info['actual_configuration'].items():
                print(f\"    - {key}: {value}\")
        if 'expected_configuration' in check_info:
            print(f\"  Expected Configuration:\")
            for key, value in check_info['expected_configuration'].items():
                print(f\"    - {key}: {value}\")
except:
    print(sys.stdin.read())
"
    done

    echo ""
    echo "================================================================================"
    echo ""
}

# Main execution
EXIT_CODE=0

# Run the check
run_check
EXIT_CODE=$?

# Output results
if [[ -n "$OUTPUT_JSON" ]]; then
    output_json $EXIT_CODE
fi

print_results

exit $EXIT_CODE
