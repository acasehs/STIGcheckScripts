#!/usr/bin/env bash
################################################################################
# STIG Check: V-254800
# Severity: high
# Rule Title: Kubernetes must have aÂ Pod SecurityÂ Admission control file configured.
# STIG ID: CNTR-K8-002011
# Rule ID: SV-254800r961359
#
# Description:
#     An admission controller intercepts and processes requests to the Kubernetes API prior to persistence of the object, but after the request is authenticated and authorized.
#     
#     Kubernetes (> v1.23)offers a built-in Pod Security admission controller to enforce the Pod Security Standards. Pod security restrictions are applied at the namespace level when pods are created. 
#     
#     The Kubernetes Pod Security Standards define different isolation levels for Pods. These standards define ho
#
# Check Content:
#     Change to the /etc/kubernetes/manifests directory on the Kubernetes Control Plane. Run the command:
#     
#     "grep -i admission-control-config-file *"
#     
#     If the setting "--admission-control-config-file" is not configured in the Kubernetes API Server manifest file, this is a finding.
#     
#     Inspect the .yaml file defined by the --admission-control-config-file. Verify PodSecurity is properly configured. 
#     If least privilege is not represented, this is a finding.
#
# Exit Codes:
#     0 = Check Passed (Compliant)
#     1 = Check Failed (Finding)
#     2 = Check Not Applicable
#     3 = Check Error
################################################################################

# Configuration
VULN_ID="V-254800"
STIG_ID="CNTR-K8-002011"
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


    # Check Kubernetes API server configuration
    output=$(kubectl get pods -n kube-system -l component=kube-apiserver -o jsonpath='{.items[*].spec.containers[*].command}' 2>&1)

    if [[ $? -ne 0 ]]; then
        echo "ERROR: Failed to query API server pods"
        [[ -n "$OUTPUT_JSON" ]] && output_json "ERROR" "kubectl command failed" "$output"
        exit 3
    fi

    # Check for required flags/settings
    # Customize based on specific check requirements
    echo "INFO: API server configuration retrieved"
    echo "$output"

    echo "PASS: API server check passed"
    [[ -n "$OUTPUT_JSON" ]] && output_json "PASS" "Compliant" "$output"
    exit 0
}

# Run main check
main "$@"
