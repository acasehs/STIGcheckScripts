#!/usr/bin/env bash
################################################################################
# STIG Check: V-235778
# Severity: medium
# Rule Title: The audit log configuration level must be set to request in the Universal Control Plane (UCP) component of Docker Enterprise.
# STIG ID: DKER-EE-001080
# Rule ID: SV-235778r960765
#
# Description:
#     The UCP and Docker Trusted Registry (DTR) components of Docker Enterprise provide audit record generation capabilities. Audit logs capture all HTTP actions for the following endpoints: Kubernetes API, Swarm API and UCP API. The following UCP API endpoints are excluded from audit logging (where "*" designates a wildcard of exclusions): "/_ping", "/ca", "/auth", "/trustedregistryca", "/kubeauth", "/metrics", "/info", "/version*", "/debug", "/openid_keys", "/apidocs", "kubernetesdocs" and "/manage"
#
# Check Content:
#     This check only applies to the UCP component of Docker Enterprise.
#     
#     Verify that the audit log configuration level in UCP is set to "request":
#     
#     Via UI:
#     
#     As a Docker EE Admin, navigate to "Admin Settings" | "Audit Logs" in the UCP management console, and verify "Audit Log Level" is set to "Request". If the audit log configuration level is not set to "Request", this is a finding.
#     
#     via CLI:
#     
#     Linux (requires curl and jq): As a Docker EE Admi
#
# Exit Codes:
#     0 = Check Passed (Compliant)
#     1 = Check Failed (Finding)
#     2 = Check Not Applicable
#     3 = Check Error
################################################################################

# Configuration
VULN_ID="V-235778"
STIG_ID="DKER-EE-001080"
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
