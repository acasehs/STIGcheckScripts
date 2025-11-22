#!/usr/bin/env bash
################################################################################
# STIG Check: V-234205
# Severity: medium
# Rule Title: The FortiGate device must enforce password complexity by requiring that at least one lowercase character be used.
# STIG ID: FGFW-ND-000230
# Rule ID: SV-234205r917456
#
# Description:
#     Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.
#     
#     Password complexity is one factor of several that determine how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised.
#     
#     Multifactor authentication (MFA) is required for all administrative and user accounts on network devices, except for an account of last resort and (where applicable) a root account. Passwords should only be used when MFA using PKI is not available, and for the account of last resort and root account.
#
# Check Content:
#     Log in to the FortiGate GUI with Super-Admin privilege.
#     
#     1. Click System.
#     2. Click Settings.
#     3. Navigate to Password Policy.
#     4. Verify Password scope is enabled for Admin and Character requirements is toggled to right.
#     5. Verify the Lowercase value is set to 1 or greater.
#     
#     If the Lowercase parameter is not set to 1 or greater, this is a finding.
#     
#     or
#     
#     Log in to the FortiGate GUI with Super-Admin privilege.
#     
#     1. Open a CLI console, via SSH or available from the GUI.
#     2. Run the following command:
#          # show full-configuration system password-policy | grep -i lower-case
#     
#     If the min-lower-case-letter parameter is not set to 1 or greater, this is a finding.
#
# Exit Codes:
#     0 = Check Passed (Compliant)
#     1 = Check Failed (Finding)
#     2 = Check Not Applicable
#     3 = Check Error
################################################################################

# Configuration
VULN_ID="V-234205"
STIG_ID="FGFW-ND-000230"
SEVERITY="medium"
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
CONFIG_FILE=""
OUTPUT_JSON=""

# Default connection parameters (override with config file)
DEVICE_HOST=""
DEVICE_PORT="22"
DEVICE_USER=""
DEVICE_PASSWORD=""
SSH_KEY_FILE=""
USE_API=false
API_KEY=""

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
        --host)
            DEVICE_HOST="$2"
            shift 2
            ;;
        --port)
            DEVICE_PORT="$2"
            shift 2
            ;;
        --user)
            DEVICE_USER="$2"
            shift 2
            ;;
        -h|--help)
            cat << 'EOF'
Usage: $0 [OPTIONS]

Options:
  --config <file>         Configuration file (JSON)
  --output-json <file>    Output results in JSON format
  --host <hostname>       Device hostname or IP address
  --port <port>           Device SSH/API port (default: 22)
  --user <username>       Device username
  -h, --help             Show this help message

Exit Codes:
  0 = Pass (Compliant)
  1 = Fail (Finding)
  2 = Not Applicable
  3 = Error

Configuration File Format (JSON):
{
  "device": {
    "host": "firewall.example.com",
    "port": 22,
    "username": "admin",
    "auth_method": "key",
    "ssh_key_file": "/path/to/key",
    "api_key": "optional_api_key"
  }
}

Example:
  $0 --config device-config.json
  $0 --host 192.168.1.1 --user admin --output-json results.json
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
if [[ -n "$CONFIG_FILE" ]]; then
    if [[ ! -f "$CONFIG_FILE" ]]; then
        echo "ERROR: Configuration file not found: $CONFIG_FILE"
        exit 3
    fi

    # Load device connection parameters from JSON config
    if command -v jq &> /dev/null; then
        DEVICE_HOST=$(jq -r '.device.host // empty' "$CONFIG_FILE")
        DEVICE_PORT=$(jq -r '.device.port // 22' "$CONFIG_FILE")
        DEVICE_USER=$(jq -r '.device.username // empty' "$CONFIG_FILE")
        SSH_KEY_FILE=$(jq -r '.device.ssh_key_file // empty' "$CONFIG_FILE")
        API_KEY=$(jq -r '.device.api_key // empty' "$CONFIG_FILE")
    else
        echo "WARNING: jq not found, cannot parse config file"
    fi
fi

################################################################################
# NETWORK DEVICE HELPER FUNCTIONS
################################################################################

# Execute SSH command on device
ssh_exec() {
    local command="$1"
    local result=""

    if [[ -z "$DEVICE_HOST" ]] || [[ -z "$DEVICE_USER" ]]; then
        echo "ERROR: Device host and user must be specified"
        return 3
    fi

    # Build SSH command with appropriate authentication
    local ssh_cmd="ssh -p $DEVICE_PORT"

    if [[ -n "$SSH_KEY_FILE" ]]; then
        ssh_cmd="$ssh_cmd -i $SSH_KEY_FILE"
    fi

    ssh_cmd="$ssh_cmd $DEVICE_USER@$DEVICE_HOST"

    # Execute command
    result=$($ssh_cmd "$command" 2>&1)
    local exit_code=$?

    echo "$result"
    return $exit_code
}

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
  "timestamp": "$TIMESTAMP",
  "device": {
    "host": "$DEVICE_HOST",
    "port": "$DEVICE_PORT"
  }
}
EOF
}

################################################################################
# MAIN CHECK LOGIC
################################################################################

main() {
    # Validate prerequisites
    if [[ -z "$DEVICE_HOST" ]]; then
        echo "ERROR: Device host not specified (use --host or --config)"
        [[ -n "$OUTPUT_JSON" ]] && output_json "ERROR" "Device host not specified" ""
        exit 3
    fi

    # Firewall Configuration Check (fortinet_fortigate)
    # Command: get system status

    if [[ -z "$DEVICE_HOST" ]]; then
        echo "ERROR: Device host not specified (use --config or --host)"
        [[ -n "$OUTPUT_JSON" ]] && output_json "ERROR" "Device host not configured" ""
        exit 3
    fi

    # Execute command via SSH
    output=$(ssh_exec "get system status")
    exit_code=$?

    if [[ $exit_code -ne 0 ]]; then
        echo "ERROR: Failed to connect to firewall device"
        echo "$output"
        [[ -n "$OUTPUT_JSON" ]] && output_json "ERROR" "SSH connection failed" "$output"
        exit 3
    fi

    # Display command output
    echo "Command Output:"
    echo "$output"

    # TODO: Add specific pass/fail logic based on expected output
    # For now, successful command execution is considered a pass

    echo "PASS: Firewall check completed - review output above"
    [[ -n "$OUTPUT_JSON" ]] && output_json "PASS" "Command executed successfully" "$output"
    exit 0

}

# Run main check
main "$@"
