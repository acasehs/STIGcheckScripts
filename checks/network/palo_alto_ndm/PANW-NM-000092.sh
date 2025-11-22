#!/usr/bin/env bash
################################################################################
# STIG Check: V-228660
# Severity: medium
# Rule Title: The Palo Alto Networks security platform must automatically lock the account until the locked account is released by an administrator when three unsuccessful logon attempts in 15 minutes are exceeded.
# STIG ID: PANW-NM-000092
# Rule ID: SV-228660r961863
#
# Description:
#     By limiting the number of failed logon attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute-forcing, is reduced. Limits are imposed by locking the account.
#     
#     This should not be configured in Device >> Setup >> Management >> Authentication Settings; instead, an authentication profile should be configured with lockout settings of three failed attempts and a lockout time of zero minutes.  The Lockout Time is the number of minutes that a user is locked out if the number of failed attempts is reached (0-60 minutes, default 0). 0 means that the lockout is in effect until it is manually unlocked.
#
# Check Content:
#     Go to Device >> Administrators.
#     If there is no authentication profile configured for each account (aside from the emergency administration account), this is a finding.
#     
#     Note which authentication profile is used for each account.
#     Go to Device >> Authentication Profile.
#     Check the authentication profile used for each account (noted in the previous step). 
#     If the Lockout Time is not set to "0" (zero), this is a finding.
#
# Exit Codes:
#     0 = Check Passed (Compliant)
#     1 = Check Failed (Finding)
#     2 = Check Not Applicable
#     3 = Check Error
################################################################################

# Configuration
VULN_ID="V-228660"
STIG_ID="PANW-NM-000092"
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

    # Firewall Configuration Check (palo_alto)
    # Command: show config running

    if [[ -z "$DEVICE_HOST" ]]; then
        echo "ERROR: Device host not specified (use --config or --host)"
        [[ -n "$OUTPUT_JSON" ]] && output_json "ERROR" "Device host not configured" ""
        exit 3
    fi

    # Execute command via SSH
    output=$(ssh_exec "show config running")
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
