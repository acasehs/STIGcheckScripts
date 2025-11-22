#!/usr/bin/env bash
################################################################################
# STIG Check: V-235777
# Severity: high
# Rule Title: FIPS mode must be enabled on all Docker Engine - Enterprise nodes.
# STIG ID: DKER-EE-001070
# Rule ID: SV-235777r960762
#
# Description:
#     When FIPS mode is enabled on a Docker Engine - Enterprise node, it uses FIPS-validated cryptography to protect the confidentiality of remote access sessions to any bound TCP sockets with TLS enabled and configured. FIPS mode in Docker Engine - Enterprise is automatically enabled when FIPS mode is also enabled on the underlying host operating system.
#     
#     This control is only configurable for the Docker Engine - Enterprise component of Docker Enterprise as only the Engine includes FIPS-va
#
# Check Content:
#     This check only applies to Docker Engine - Enterprise.
#     
#     Verify FIPS mode is enabled on the host operating system.
#     
#     Execute the following command to verify that FIPS mode is enabled on the Engine:
#     
#     docker info
#     
#     The "Security Options" section in the response should show a "fips" label, indicating that, when configured, the remotely accessible Engine API uses FIPS-validated digital signatures in conjunction with an approved hash function to protect th
#
# Exit Codes:
#     0 = Check Passed (Compliant)
#     1 = Check Failed (Finding)
#     2 = Check Not Applicable
#     3 = Check Error
################################################################################

# Configuration
VULN_ID="V-235777"
STIG_ID="DKER-EE-001070"
SEVERITY="high"
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


    # Check FIPS mode
    # Check host FIPS mode first
    if [[ -f /proc/sys/crypto/fips_enabled ]]; then
        host_fips=$(cat /proc/sys/crypto/fips_enabled)
        if [[ "$host_fips" == "1" ]]; then
            echo "PASS: FIPS mode enabled on host"
            [[ -n "$OUTPUT_JSON" ]] && output_json "PASS" "FIPS enabled" "host fips: $host_fips"
            exit 0
        fi
    fi

    # Check DOCKER_FIPS environment variable
    if docker_fips=$(docker info 2>/dev/null | grep -i "FIPS mode"); then
        if echo "$docker_fips" | grep -qi "enabled\|true"; then
            echo "PASS: FIPS mode enabled on Docker"
            [[ -n "$OUTPUT_JSON" ]] && output_json "PASS" "FIPS enabled" "$docker_fips"
            exit 0
        fi
    fi

    echo "FAIL: FIPS mode not enabled"
    [[ -n "$OUTPUT_JSON" ]] && output_json "FAIL" "FIPS mode not enabled" ""
    exit 1
}

# Run main check
main "$@"
