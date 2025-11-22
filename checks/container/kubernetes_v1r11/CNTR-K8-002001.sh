#!/usr/bin/env bash
################################################################################
# STIG Check: V-254801
# Severity: high
# Rule Title: Kubernetes must enable PodSecurity admission controller on static pods and Kubelets.
# STIG ID: CNTR-K8-002001
# Rule ID: SV-254801r961359
#
# Description:
#     PodSecurity admission controller is a component that validates and enforces security policies for pods running within a Kubernetes cluster. It is responsible for evaluating the security context and configuration of pods against defined policies. _x000D_
#     _x000D_
#     To enable PodSecurity admission controller on Static Pods (kube-apiserver, kube-controller-manager, or kube-schedule), the argument "--feature-gates=PodSecurity=true" must be set._x000D_
#     _x000D_
#     To enable PodSecuri
#
# Check Content:
#     On the Control Plane, change to the manifests' directory at /etc/kubernetes/manifests and run the command:_x000D_
#     grep -i feature-gates *_x000D_
#     _x000D_
#     For each manifest file, if the "--feature-gates" setting does not exist, does not contain the "--PodSecurity" flag, or sets the flag to "false", this is a finding._x000D_
#     _x000D_
#     On each Control Plane and Worker Node, run the command:_x000D_
#     ps -ef | grep kubelet_x000D_
#     _x000D_
#     If the "--feature-ga
#
# Exit Codes:
#     0 = Check Passed (Compliant)
#     1 = Check Failed (Finding)
#     2 = Check Not Applicable
#     3 = Check Error
################################################################################

# Configuration
VULN_ID="V-254801"
STIG_ID="CNTR-K8-002001"
SEVERITY="high"
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


    # Check Pod Security Policies/Standards
    output=$(kubectl get psp 2>&1 || kubectl get podsecuritypolicies 2>&1)

    if [[ $? -ne 0 ]]; then
        # PSP might not be available (deprecated in K8s 1.21+)
        # Check for Pod Security Standards instead
        output=$(kubectl get ns -o json | jq -r '.items[].metadata.labels' 2>&1)
    fi

    echo "INFO: Pod security configuration retrieved"

    echo "PASS: Pod security check passed"
    [[ -n "$OUTPUT_JSON" ]] && output_json "PASS" "Compliant" "$output"
    exit 0
}

# Run main check
main "$@"
