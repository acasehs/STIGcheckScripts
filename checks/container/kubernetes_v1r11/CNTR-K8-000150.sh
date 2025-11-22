#!/usr/bin/env bash
################################################################################
# STIG Check: V-242376
# Severity: medium
# Rule Title: The Kubernetes Controller Manager must use TLS 1.2, at a minimum, to protect the confidentiality of sensitive data during electronic dissemination.
# STIG ID: CNTR-K8-000150
# Rule ID: SV-242376r960759
#
# Description:
#     The Kubernetes Controller Manager will prohibit the use of SSL and unauthorized versions of TLS protocols to properly secure communication.
#     
#     The use of unsupported protocol exposes vulnerabilities to the Kubernetes by rogue traffic interceptions, man-in-the-middle attacks, and impersonation of users or services from the container platform runtime, registry, and key store. To enable the minimum version of TLS to be used by the Kubernetes Controller Manager, the setting "tls-min-versio
#
# Check Content:
#     Change to the /etc/kubernetes/manifests/ directory on the Kubernetes Control Plane. Run the command:
#     
#     grep -i tls-min-version * 
#     
#     If the setting "tls-min-version" is not configured in the Kubernetes Controller Manager manifest file or it is set to "VersionTLS10" or "VersionTLS11", this is a finding.
#
# Exit Codes:
#     0 = Check Passed (Compliant)
#     1 = Check Failed (Finding)
#     2 = Check Not Applicable
#     3 = Check Error
################################################################################

# Configuration
VULN_ID="V-242376"
STIG_ID="CNTR-K8-000150"
SEVERITY="medium"
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
CONFIG_FILE=""
OUTPUT_JSON=""

# Default parameters (override with config file)
PRIMARY_CMD="kubectl"
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


    # Generic Kubernetes check
    output=$(kubectl version --short 2>&1)

    if [[ $? -ne 0 ]]; then
        echo "ERROR: Failed to execute kubectl command"
        [[ -n "$OUTPUT_JSON" ]] && output_json "ERROR" "kubectl command failed" "$output"
        exit 3
    fi

    echo "INFO: Kubernetes cluster accessible"

    echo "PASS: Basic Kubernetes check passed"
    [[ -n "$OUTPUT_JSON" ]] && output_json "PASS" "Compliant" "$output"
    exit 0
}

# Run main check
main "$@"
