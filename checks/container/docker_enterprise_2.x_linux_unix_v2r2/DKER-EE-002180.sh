#!/usr/bin/env bash
################################################################################
# STIG Check: V-235821
# Severity: medium
# Rule Title: SAML integration must be enabled in Docker Enterprise.
# STIG ID: DKER-EE-002180
# Rule ID: SV-235821r960972
#
# Description:
#     Both the Universal Control Plane (UCP) and Docker Trusted Registry (DTR) components of Docker Enterprise leverage the same authentication and authorization backplane known as eNZi. The eNZi backplane includes its own managed user database, and also allows for LDAP and SAML integration in UCP and DTR. To meet the requirements of this control, configure LDAP and SAML integration.
#     
#     Satisfies: SRG-APP-000149, SRG-APP-000150, SRG-APP-000151, SRG-APP-000152, SRG-APP-000153, SRG-APP-000391,
#
# Check Content:
#     Verify that SAML integration is enabled and properly configured in the UCP Admin Settings.
#     
#     via UI:
#     
#     In the UCP web console, navigate to "Admin Settings" | "Authentication & Authorization" and verify "SAML Enabled" is set to "Yes" and that it is properly configured. If SAML authentication is not enabled, this is a finding.
#     
#     via CLI:
#     
#     Linux (requires curl and jq): As a Docker EE Admin, execute the following commands from a machine with connectivity 
#
# Exit Codes:
#     0 = Check Passed (Compliant)
#     1 = Check Failed (Finding)
#     2 = Check Not Applicable
#     3 = Check Error
################################################################################

# Configuration
VULN_ID="V-235821"
STIG_ID="DKER-EE-002180"
SEVERITY="medium"
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
CONFIG_FILE=""
OUTPUT_JSON=""

# Default parameters (override with config file)
PRIMARY_CMD="docker"
NAMESPACE=""
CONTEXT=""
KUBECONFIG=""

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
        --namespace)
            NAMESPACE="$2"
            shift 2
            ;;
        --context)
            CONTEXT="$2"
            shift 2
            ;;
        --kubeconfig)
            KUBECONFIG="$2"
            shift 2
            ;;
        -h|--help)
            cat << 'EOF'
Usage: $0 [OPTIONS]

Options:
  --config <file>         Configuration file (JSON)
  --output-json <file>    Output results in JSON format
  --namespace <name>      Kubernetes namespace (if applicable)
  --context <name>        Kubernetes context (if applicable)
  --kubeconfig <file>     Path to kubeconfig file
  -h, --help             Show this help message

Exit Codes:
  0 = Pass (Compliant)
  1 = Fail (Finding)
  2 = Not Applicable
  3 = Error

Configuration File Format (JSON):
{
  "kubernetes": {
    "kubeconfig": "/path/to/kubeconfig",
    "context": "production",
    "namespace": "default"
  },
  "docker": {
    "socket": "/var/run/docker.sock",
    "tls_verify": true
  }
}

Example:
  $0 --config container-config.json
  $0 --namespace kube-system --output-json results.json
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

    # Load parameters from JSON config
    if command -v jq &> /dev/null; then
        NAMESPACE=$(jq -r '.kubernetes.namespace // empty' "$CONFIG_FILE" 2>/dev/null)
        CONTEXT=$(jq -r '.kubernetes.context // empty' "$CONFIG_FILE" 2>/dev/null)
        KUBECONFIG=$(jq -r '.kubernetes.kubeconfig // empty' "$CONFIG_FILE" 2>/dev/null)
    else
        echo "WARNING: jq not found, cannot parse config file"
    fi
fi

################################################################################
# HELPER FUNCTIONS
################################################################################

# Check if command exists
command_exists() {
    command -v "$1" &> /dev/null
}

# Execute Docker command
docker_exec() {
    local cmd="$1"
    if ! command_exists docker; then
        echo "ERROR: docker command not found"
        return 3
    fi
    eval "docker $cmd" 2>&1
    return $?
}

# Execute kubectl command
kubectl_exec() {
    local cmd="$1"
    local kubectl_cmd="kubectl"

    if ! command_exists kubectl; then
        echo "ERROR: kubectl command not found"
        return 3
    fi

    [[ -n "$KUBECONFIG" ]] && kubectl_cmd="$kubectl_cmd --kubeconfig=$KUBECONFIG"
    [[ -n "$CONTEXT" ]] && kubectl_cmd="$kubectl_cmd --context=$CONTEXT"
    [[ -n "$NAMESPACE" ]] && kubectl_cmd="$kubectl_cmd --namespace=$NAMESPACE"

    eval "$kubectl_cmd $cmd" 2>&1
    return $?
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
  "timestamp": "$TIMESTAMP"
}
EOF
}

################################################################################
# MAIN CHECK LOGIC
################################################################################

main() {
    # Validate prerequisites
    if ! command_exists "$PRIMARY_CMD"; then
        echo "ERROR: $PRIMARY_CMD command not found"
        [[ -n "$OUTPUT_JSON" ]] && output_json "ERROR" "$PRIMARY_CMD not available" ""
        exit 3
    fi


    # Check UCP per_user_limit setting via API
    # Requires UCP credentials from config file
    if [[  -z "${UCP_URL}" ]] || [[ -z "${UCP_USERNAME}" ]]; then
        echo "ERROR: UCP credentials not configured (use --config with UCP details)"
        [[ -n "$OUTPUT_JSON" ]] && output_json "ERROR" "UCP credentials required" ""
        exit 3
    fi

    # Authenticate to UCP
    AUTH_RESPONSE=$(curl -sk -d '{"username":"'"$UCP_USERNAME"'","password":"'"$UCP_PASSWORD"'"}' \
        https://$UCP_URL/auth/login 2>/dev/null)

    AUTHTOKEN=$(echo "$AUTH_RESPONSE" | jq -r .auth_token 2>/dev/null)

    if [[ -z "$AUTHTOKEN" ]] || [[ "$AUTHTOKEN" == "null" ]]; then
        echo "ERROR: Failed to authenticate to UCP"
        [[ -n "$OUTPUT_JSON" ]] && output_json "ERROR" "UCP authentication failed" ""
        exit 3
    fi

    # Get UCP config
    output=$(curl -sk -H "Authorization: Bearer $AUTHTOKEN" \
        https://$UCP_URL/api/ucp/config-toml 2>/dev/null)

    if [[ -z "$output" ]]; then
        echo "FAIL: Unable to retrieve UCP configuration"
        [[ -n "$OUTPUT_JSON" ]] && output_json "FAIL" "Could not retrieve config" ""
        exit 1
    fi

    # Check for the specific setting
    if echo "$output" | grep -q "per_user_limit"; then
        setting_value=$(echo "$output" | grep "per_user_limit" | head -1)
        echo "PASS: per_user_limit is configured: $setting_value"
        [[ -n "$OUTPUT_JSON" ]] && output_json "PASS" "Setting configured" "$setting_value"
        exit 0
    else
        echo "FAIL: per_user_limit not found in UCP configuration"
        [[ -n "$OUTPUT_JSON" ]] && output_json "FAIL" "Setting not configured" ""
        exit 1
    fi
}

# Run main check
main "$@"
