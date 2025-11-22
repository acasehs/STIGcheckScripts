#!/usr/bin/env python3
"""
Complete Container Technologies STIG Automation Framework Generator

Generates automation frameworks for all 2 container STIG benchmarks:
- Docker Enterprise 2.x Linux/UNIX (88 checks)
- Kubernetes (75 checks)

Tool Priority: bash > python > third-party
Platform: Container platforms (Docker CLI, kubectl required)

Exit Codes: 0=PASS, 1=FAIL, 2=N/A, 3=ERROR
"""

import json
import sys
from pathlib import Path
from datetime import datetime
import stat
import re

# Container STIG products configuration
CONTAINER_STIGS = [
    {
        "name": "Docker Enterprise 2.x Linux/UNIX",
        "benchmark_id": "Docker_Enterprise_2-x_Linux-UNIX_STIG",
        "json_filter": "Docker Enterprise 2.x Linux/UNIX",
        "dir_name": "docker_enterprise_2.x_linux_unix_v2r2",
        "version": "v2r2",
        "platform": "Linux/UNIX",
        "primary_command": "docker",
        "secondary_command": "curl"
    },
    {
        "name": "Kubernetes",
        "benchmark_id": "Kubernetes_STIG",
        "json_filter": "Kubernetes",
        "dir_name": "kubernetes_v1r11",
        "version": "v1r11",
        "platform": "Linux",
        "primary_command": "kubectl",
        "secondary_command": "curl"
    }
]

# ============================================================================
# BASH SCRIPT TEMPLATE (Primary for Container Platforms)
# ============================================================================

BASH_TEMPLATE = '''#!/usr/bin/env bash
################################################################################
# STIG Check: {vuln_id}
# Severity: {severity}
# Rule Title: {rule_title}
# STIG ID: {stig_id}
# Rule ID: {rule_id}
#
# Description:
#     {description}
#
# Check Content:
#     {check_content}
#
# Exit Codes:
#     0 = Check Passed (Compliant)
#     1 = Check Failed (Finding)
#     2 = Check Not Applicable
#     3 = Check Error
################################################################################

# Configuration
VULN_ID="{vuln_id}"
STIG_ID="{stig_id}"
SEVERITY="{severity}"
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
CONFIG_FILE=""
OUTPUT_JSON=""

# Default parameters (override with config file)
PRIMARY_CMD="{primary_command}"
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
{{
  "kubernetes": {{
    "kubeconfig": "/path/to/kubeconfig",
    "context": "production",
    "namespace": "default"
  }},
  "docker": {{
    "socket": "/var/run/docker.sock",
    "tls_verify": true
  }}
}}

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
command_exists() {{
    command -v "$1" &> /dev/null
}}

# Execute Docker command
docker_exec() {{
    local cmd="$1"
    if ! command_exists docker; then
        echo "ERROR: docker command not found"
        return 3
    fi
    eval "docker $cmd" 2>&1
    return $?
}}

# Execute kubectl command
kubectl_exec() {{
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
}}

# Output results in JSON format
output_json() {{
    local status="$1"
    local message="$2"
    local details="$3"

    cat > "$OUTPUT_JSON" << EOF
{{
  "vuln_id": "$VULN_ID",
  "stig_id": "$STIG_ID",
  "severity": "$SEVERITY",
  "status": "$status",
  "message": "$message",
  "details": "$details",
  "timestamp": "$TIMESTAMP"
}}
EOF
}}

################################################################################
# MAIN CHECK LOGIC
################################################################################

main() {{
    # Validate prerequisites
    if ! command_exists "$PRIMARY_CMD"; then
        echo "ERROR: $PRIMARY_CMD command not found"
        [[ -n "$OUTPUT_JSON" ]] && output_json "ERROR" "$PRIMARY_CMD not available" ""
        exit 3
    fi

    # TODO: Implement actual STIG check logic
    # This is a stub implementation requiring container domain expertise
    #
    # Implementation notes:
    # 1. Execute appropriate CLI commands ({primary_command})
    # 2. Parse output to verify compliance
    # 3. Return appropriate exit code
    #
    # Example for Docker:
    # output=$(docker_exec "info --format '{{{{.SecurityOptions}}}}'")
    # if [[ $? -ne 0 ]]; then
    #     echo "ERROR: Failed to execute docker command"
    #     exit 3
    # fi
    #
    # Example for Kubernetes:
    # output=$(kubectl_exec "get pods --all-namespaces")
    # if [[ $? -ne 0 ]]; then
    #     echo "ERROR: Failed to execute kubectl command"
    #     exit 3
    # fi
    #
    # Analyze output and determine compliance:
    # if [[ "$output" =~ <expected_pattern> ]]; then
    #     echo "PASS: Check {stig_id} - Compliant"
    #     [[ -n "$OUTPUT_JSON" ]] && output_json "PASS" "Compliant" "$output"
    #     exit 0
    # else
    #     echo "FAIL: Check {stig_id} - Finding"
    #     [[ -n "$OUTPUT_JSON" ]] && output_json "FAIL" "Non-compliant" "$output"
    #     exit 1
    # fi

    echo "TODO: Implement check logic for {stig_id}"
    echo "Description: {description}"
    echo "This check requires container domain expertise to implement"

    [[ -n "$OUTPUT_JSON" ]] && output_json "ERROR" "Not implemented" "Stub implementation"
    exit 3
}}

# Run main check
main "$@"
'''

# ============================================================================
# PYTHON SCRIPT TEMPLATE (Fallback)
# ============================================================================

PYTHON_TEMPLATE = '''#!/usr/bin/env python3
"""
STIG Check: {vuln_id}
Severity: {severity}
Rule Title: {rule_title}
STIG ID: {stig_id}
Rule ID: {rule_id}

Description:
    {description}

Check Content:
    {check_content}

Exit Codes:
    0 = Check Passed (Compliant)
    1 = Check Failed (Finding)
    2 = Check Not Applicable
    3 = Check Error
"""

import sys
import json
import argparse
import subprocess
from datetime import datetime
from pathlib import Path

# Configuration
VULN_ID = "{vuln_id}"
STIG_ID = "{stig_id}"
SEVERITY = "{severity}"
PRIMARY_COMMAND = "{primary_command}"

def run_command(cmd, check_error=True):
    """Execute shell command and return output"""
    try:
        result = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=30
        )

        if check_error and result.returncode != 0:
            return None, result.stderr

        return result.stdout, None
    except subprocess.TimeoutExpired:
        return None, "Command timed out"
    except Exception as e:
        return None, str(e)

def docker_exec(command):
    """Execute Docker command"""
    stdout, error = run_command(f"docker {{command}}")
    return stdout, error

def kubectl_exec(command, namespace=None, context=None, kubeconfig=None):
    """Execute kubectl command"""
    cmd_parts = ["kubectl"]

    if kubeconfig:
        cmd_parts.append(f"--kubeconfig={{kubeconfig}}")
    if context:
        cmd_parts.append(f"--context={{context}}")
    if namespace:
        cmd_parts.append(f"--namespace={{namespace}}")

    cmd_parts.append(command)
    cmd = " ".join(cmd_parts)

    stdout, error = run_command(cmd)
    return stdout, error

def load_config(config_file):
    """Load configuration from JSON file"""
    try:
        with open(config_file, 'r') as f:
            return json.load(f)
    except Exception as e:
        print(f"ERROR: Failed to load config file: {{e}}", file=sys.stderr)
        sys.exit(3)

def output_json(output_file, status, message, details=""):
    """Output results in JSON format"""
    result = {{
        "vuln_id": VULN_ID,
        "stig_id": STIG_ID,
        "severity": SEVERITY,
        "status": status,
        "message": message,
        "details": details,
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }}

    try:
        with open(output_file, 'w') as f:
            json.dump(result, f, indent=2)
    except Exception as e:
        print(f"ERROR: Failed to write JSON output: {{e}}", file=sys.stderr)

def perform_check(config):
    """
    Perform the actual STIG check

    TODO: Implement actual check logic
    This is a stub implementation requiring container domain expertise

    Implementation notes:
    1. Execute appropriate CLI commands (docker or kubectl)
    2. Parse output to verify compliance
    3. Return (exit_code, message, details)

    Returns:
        tuple: (exit_code, message, details)
               exit_code: 0=PASS, 1=FAIL, 2=N/A, 3=ERROR
               message: Human-readable status message
               details: Additional details about the check
    """

    # Example implementation structure for Docker:
    # stdout, error = docker_exec("info --format '{{{{.SecurityOptions}}}}'")
    # if error:
    #     return (3, f"Error executing docker command: {{error}}", "")
    #
    # # Analyze output for compliance
    # if "expected_value" in stdout:
    #     return (0, "Compliant", stdout)
    # else:
    #     return (1, "Non-compliant - Finding", stdout)

    # Example implementation structure for Kubernetes:
    # namespace = config.get('kubernetes', {{}}).get('namespace')
    # context = config.get('kubernetes', {{}}).get('context')
    # kubeconfig = config.get('kubernetes', {{}}).get('kubeconfig')
    #
    # stdout, error = kubectl_exec("get pods", namespace, context, kubeconfig)
    # if error:
    #     return (3, f"Error executing kubectl command: {{error}}", "")
    #
    # # Analyze output for compliance
    # if some_compliance_check(stdout):
    #     return (0, "Compliant", stdout)
    # else:
    #     return (1, "Non-compliant - Finding", stdout)

    return (3, "Not implemented - Stub implementation",
            "This check requires container domain expertise to implement")

def main():
    parser = argparse.ArgumentParser(
        description=f"STIG Check {{STIG_ID}} - {rule_title}",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('--config', help='Configuration file (JSON)')
    parser.add_argument('--output-json', help='Output results in JSON format')
    parser.add_argument('--namespace', help='Kubernetes namespace (if applicable)')
    parser.add_argument('--context', help='Kubernetes context (if applicable)')
    parser.add_argument('--kubeconfig', help='Path to kubeconfig file')

    args = parser.parse_args()

    # Load configuration
    config = {{}}
    if args.config:
        config = load_config(args.config)

    # Override with command-line arguments
    if args.namespace:
        config.setdefault('kubernetes', {{}})['namespace'] = args.namespace
    if args.context:
        config.setdefault('kubernetes', {{}})['context'] = args.context
    if args.kubeconfig:
        config.setdefault('kubernetes', {{}})['kubeconfig'] = args.kubeconfig

    # Check if required command is available
    stdout, error = run_command(f"command -v {{PRIMARY_COMMAND}}", check_error=False)
    if not stdout or error:
        print(f"ERROR: {{PRIMARY_COMMAND}} command not found", file=sys.stderr)
        if args.output_json:
            output_json(args.output_json, "ERROR",
                       f"{{PRIMARY_COMMAND}} not available")
        sys.exit(3)

    # Perform the check
    exit_code, message, details = perform_check(config)

    # Output results
    print(f"{{message}}")
    if details:
        print(f"Details: {{details}}")

    if args.output_json:
        status_map = {{0: "PASS", 1: "FAIL", 2: "N/A", 3: "ERROR"}}
        output_json(args.output_json, status_map.get(exit_code, "ERROR"),
                   message, details)

    sys.exit(exit_code)

if __name__ == '__main__':
    main()
'''

# ============================================================================
# README TEMPLATE
# ============================================================================

README_TEMPLATE = '''# {name} STIG Automation Framework

## Overview

This directory contains automation scripts for the **{name}** Security Technical Implementation Guide (STIG).

- **Benchmark ID**: {benchmark_id}
- **Version**: {version}
- **Platform**: {platform}
- **Primary Command**: `{primary_command}`
- **Tool Priority**: bash > python > third-party

## Directory Structure

```
{dir_name}/
├── README.md                    # This file
├── config-example.json          # Example configuration file
├── <STIG-ID>.sh                # Bash scripts for each check
└── <STIG-ID>.py                # Python scripts for each check
```

## Requirements

### Command-Line Tools
- `{primary_command}` - Primary tool for {name}
- `bash` 4.0+ - For bash scripts
- `python3` 3.6+ - For Python scripts
- `jq` - Optional, for JSON parsing in bash scripts

### Docker Requirements (if applicable)
- Docker Engine installed and running
- Docker socket accessible: `/var/run/docker.sock`
- Appropriate permissions to execute docker commands
- Docker Compose (optional, for some checks)

### Kubernetes Requirements (if applicable)
- kubectl installed and configured
- Valid kubeconfig file
- Appropriate cluster access permissions
- Network connectivity to Kubernetes API server

## Configuration File

Create a configuration file (e.g., `container-config.json`):

```json
{{
  "kubernetes": {{
    "kubeconfig": "/home/user/.kube/config",
    "context": "production-cluster",
    "namespace": "default"
  }},
  "docker": {{
    "socket": "/var/run/docker.sock",
    "tls_verify": true,
    "cert_path": "/path/to/certs"
  }},
  "output": {{
    "format": "json",
    "directory": "./results"
  }}
}}
```

**Important**: Set restrictive permissions on configuration files:
```bash
chmod 600 container-config.json
```

## Quick Start

### Individual Check Execution

Run a single STIG check using bash (primary):
```bash
# Using configuration file
./STIG-ID-001.sh --config container-config.json

# With JSON output
./STIG-ID-001.sh --config container-config.json --output-json results.json

# For Kubernetes checks
./STIG-ID-001.sh --namespace kube-system --context prod
```

Run using Python (fallback):
```bash
python3 STIG-ID-001.py --config container-config.json
python3 STIG-ID-001.py --namespace kube-system --output-json results.json
```

### Batch Execution

Run all checks in the directory:
```bash
#!/bin/bash
# Example batch execution script

CONFIG_FILE="container-config.json"
RESULTS_DIR="./results"
mkdir -p "$RESULTS_DIR"

for script in *.sh; do
    stig_id="${{script%.sh}}"
    echo "Running check: $stig_id"

    ./"$script" --config "$CONFIG_FILE" \\
        --output-json "$RESULTS_DIR/${{stig_id}}.json"

    exit_code=$?
    case $exit_code in
        0) echo "  ✓ PASS" ;;
        1) echo "  ✗ FAIL" ;;
        2) echo "  - N/A" ;;
        3) echo "  ! ERROR" ;;
    esac
done
```

## Exit Codes

All scripts use standardized exit codes:

| Code | Status | Description |
|------|--------|-------------|
| 0    | PASS   | Check passed - System is compliant |
| 1    | FAIL   | Check failed - Finding identified |
| 2    | N/A    | Check not applicable to this system |
| 3    | ERROR  | Check error - Unable to complete |

## Script Parameters

### Common Parameters

All scripts support these parameters:

- `--config <file>` - Configuration file (JSON format)
- `--output-json <file>` - Output results in JSON format
- `--namespace <name>` - Kubernetes namespace (if applicable)
- `--context <name>` - Kubernetes context (if applicable)
- `--kubeconfig <file>` - Path to kubeconfig file
- `-h, --help` - Display help message

### JSON Output Format

When using `--output-json`, results are written in this format:

```json
{{
  "vuln_id": "V-XXXXX",
  "stig_id": "STIG-ID-XXX",
  "severity": "medium",
  "status": "PASS|FAIL|N/A|ERROR",
  "message": "Human-readable status message",
  "details": "Additional check details",
  "timestamp": "2025-11-22T12:34:56Z"
}}
```

## Implementation Status

**Current Status**: Framework/Stub Implementation

All scripts in this directory are **framework implementations** with TODO placeholders. They provide:
- ✓ Complete script structure and argument parsing
- ✓ Command execution helper functions
- ✓ Configuration file support
- ✓ JSON output formatting
- ✓ Standardized exit codes
- ✗ Actual STIG check logic (requires container domain expertise)

### To Complete Implementation

Each script requires:
1. Specific CLI commands for the check ({primary_command})
2. Output parsing and compliance verification
3. Error handling for command failures
4. Testing in actual container environments

## Platform-Specific Notes

### Docker Enterprise
- Requires Docker Engine Enterprise Edition
- Universal Control Plane (UCP) access may be required
- Docker Trusted Registry (DTR) access for some checks
- Swarm mode configuration
- Security scanning and image signing

### Kubernetes
- Works with various Kubernetes distributions (EKS, GKE, AKS, etc.)
- Requires appropriate RBAC permissions
- Pod Security Policies or Pod Security Standards
- Network Policies
- API server configuration
- etcd encryption settings

## Troubleshooting

### Command Not Found
```bash
# Check if docker is installed
docker version

# Check if kubectl is installed
kubectl version --client

# Verify kubectl can connect to cluster
kubectl cluster-info
```

### Permission Errors
```bash
# Add user to docker group (requires logout/login)
sudo usermod -aG docker $USER

# Check kubeconfig permissions
ls -l ~/.kube/config
chmod 600 ~/.kube/config
```

### Kubernetes Context Issues
```bash
# List available contexts
kubectl config get-contexts

# Switch context
kubectl config use-context <context-name>

# View current config
kubectl config view
```

## Additional Resources

- DISA STIG Viewer: https://public.cyber.mil/stigs/srg-stig-tools/
- STIG Documentation: https://public.cyber.mil/stigs/downloads/
- Docker Documentation: https://docs.docker.com/
- Kubernetes Documentation: https://kubernetes.io/docs/
- Automation Guide: See main repository README

## Support

For issues or questions:
1. Check script help: `./script.sh --help`
2. Review STIG documentation
3. Verify command-line tools are installed
4. Check configuration file format
5. Verify appropriate permissions

---

**Note**: This is an automation framework. All scripts require domain expertise to complete implementation with actual check logic.
'''

# ============================================================================
# REPORT GENERATION
# ============================================================================

def generate_automation_report(container_config, checks, output_file):
    """Generate automation analysis report for a container STIG"""

    # Analyze automation feasibility
    fully_automatable = 0
    partially_automatable = 0
    manual_only = 0

    for check in checks:
        check_content = check.get('Check Content', '').lower()

        # Keywords indicating automation feasibility
        if any(keyword in check_content for keyword in ['docker', 'kubectl', 'config', 'cli', 'command']):
            fully_automatable += 1
        elif any(keyword in check_content for keyword in ['review', 'verify', 'interview', 'examine']):
            if any(keyword in check_content for keyword in ['log', 'file', 'configuration', 'yaml', 'json']):
                partially_automatable += 1
            else:
                manual_only += 1
        else:
            partially_automatable += 1

    # Generate report
    report = f"""
{'='*80}
{container_config['name']} STIG Automation Analysis
{'='*80}

Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Benchmark: {container_config['benchmark_id']}
Version: {container_config['version']}
Platform: {container_config['platform']}
Total Checks: {len(checks)}

{'='*80}
AUTOMATION FEASIBILITY SUMMARY
{'='*80}

Total STIG Checks:           {len(checks):3d}
├─ Fully Automatable:        {fully_automatable:3d} ({fully_automatable/len(checks)*100:.1f}%)
├─ Partially Automatable:    {partially_automatable:3d} ({partially_automatable/len(checks)*100:.1f}%)
└─ Manual Review Required:   {manual_only:3d} ({manual_only/len(checks)*100:.1f}%)

{'='*80}
SEVERITY BREAKDOWN
{'='*80}
"""

    # Count by severity
    severity_counts = {}
    for check in checks:
        sev = check.get('Severity', 'unknown').upper()
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    for severity in ['HIGH', 'MEDIUM', 'LOW']:
        count = severity_counts.get(severity, 0)
        if count > 0:
            report += f"{severity:8s}: {count:3d} checks ({count/len(checks)*100:.1f}%)\n"

    report += f"\n{'='*80}\n"
    report += "FRAMEWORK GENERATION DETAILS\n"
    report += f"{'='*80}\n\n"
    report += f"Output Directory: checks/container/{container_config['dir_name']}/\n"
    report += f"Scripts Generated: {len(checks) * 2} ({len(checks)} bash + {len(checks)} Python)\n"
    report += f"Primary Command: {container_config['primary_command']}\n"
    report += f"Tool Priority: bash > python > third-party\n"

    report += f"\n{'='*80}\n"
    report += "IMPLEMENTATION NOTES\n"
    report += f"{'='*80}\n\n"
    report += "All scripts are STUB/FRAMEWORK implementations with:\n"
    report += "  ✓ Complete argument parsing and configuration support\n"
    report += "  ✓ Command execution helper functions\n"
    report += "  ✓ JSON output formatting\n"
    report += "  ✓ Standardized exit codes (0=PASS, 1=FAIL, 2=N/A, 3=ERROR)\n"
    report += "  ✗ Actual check logic (TODO - requires container expertise)\n\n"
    report += "Platform Requirements:\n"
    report += f"  - {container_config['primary_command']} command-line tool installed\n"
    report += "  - Appropriate permissions to execute commands\n"
    report += "  - Platform-specific configuration (kubeconfig, docker socket, etc.)\n"
    report += "  - Network connectivity if required\n\n"
    report += "Security Considerations:\n"
    report += "  - Use minimal required permissions (read-only when possible)\n"
    report += "  - Secure configuration files (chmod 600)\n"
    report += "  - Never store credentials in scripts\n"
    report += "  - Use service accounts or IAM roles when available\n"
    report += "  - Implement logging and audit trails\n"

    report += f"\n{'='*80}\n"
    report += "CHECK DETAILS\n"
    report += f"{'='*80}\n\n"

    for i, check in enumerate(checks, 1):
        vuln_id = check.get('Group ID', 'Unknown')
        stig_id = check.get('STIG ID', 'Unknown')
        severity = check.get('Severity', 'unknown').upper()
        title = check.get('Rule Title', 'No title')

        # Truncate long titles
        if len(title) > 70:
            title = title[:67] + "..."

        report += f"{i:3d}. [{severity:6s}] {stig_id:20s} - {title}\n"

    report += f"\n{'='*80}\n"
    report += "AUTOMATION READINESS\n"
    report += f"{'='*80}\n\n"
    report += f"Framework Status:     COMPLETE\n"
    report += f"Implementation Status: STUB (requires domain expertise)\n"
    report += f"Testing Status:       NOT TESTED (requires actual platforms)\n"
    report += f"Production Ready:     NO (implementation incomplete)\n"

    report += f"\n{'='*80}\n"
    report += "NEXT STEPS\n"
    report += f"{'='*80}\n\n"
    report += "1. Review generated framework scripts\n"
    report += "2. Implement platform-specific check logic for each STIG\n"
    report += "3. Test in actual container environments\n"
    report += "4. Create platform configuration files (chmod 600)\n"
    report += "5. Validate all exit codes and error handling\n"
    report += "6. Document platform-specific requirements\n"
    report += "7. Implement batch execution scripts if needed\n"
    report += "8. Consider integration with compliance reporting tools\n"

    report += f"\n{'='*80}\n"
    report += "END OF REPORT\n"
    report += f"{'='*80}\n"

    # Write report
    with open(output_file, 'w') as f:
        f.write(report)

    return fully_automatable, partially_automatable, manual_only

def sanitize_filename(stig_id):
    """Sanitize STIG ID for use as filename"""
    # Replace any characters that might be problematic in filenames
    safe_name = re.sub(r'[^a-zA-Z0-9_-]', '_', stig_id)
    return safe_name

def extract_checks_from_allstigs(json_filter, allstigs_file):
    """Extract checks for a specific container platform from AllSTIGS2.json"""
    try:
        with open(allstigs_file, 'r') as f:
            all_checks = json.load(f)

        # Filter checks for this platform
        filtered_checks = [
            check for check in all_checks
            if check.get('Benchmark Name', '') == json_filter
        ]

        return filtered_checks
    except Exception as e:
        print(f"ERROR: Failed to load AllSTIGS2.json: {e}")
        return []

def generate_container_framework(container_config, base_dir):
    """Generate complete automation framework for a container STIG"""

    print(f"\n{'='*80}")
    print(f"Generating {container_config['name']} STIG Framework")
    print(f"{'='*80}\n")

    # Extract checks from AllSTIGS2.json
    allstigs_file = base_dir / "AllSTIGS2.json"
    print(f"Extracting checks from: {allstigs_file}")
    print(f"Filter: {container_config['json_filter']}")

    checks = extract_checks_from_allstigs(container_config['json_filter'], allstigs_file)

    if not checks:
        print(f"WARNING: No checks found for {container_config['json_filter']}")
        print("This may be expected if the STIG is not in AllSTIGS2.json")
        return None

    print(f"Extracted {len(checks)} checks")

    # Create output directory
    output_dir = base_dir / "checks" / "container" / container_config['dir_name']
    output_dir.mkdir(parents=True, exist_ok=True)
    print(f"Output directory: {output_dir}")

    # Generate scripts for each check
    bash_count = 0
    python_count = 0

    for check in checks:
        vuln_id = check.get('Group ID', 'Unknown')
        stig_id = check.get('STIG ID', 'Unknown')
        severity = check.get('Severity', 'unknown')
        rule_title = check.get('Rule Title', '')
        rule_id = check.get('Rule ID', '')
        discussion = check.get('Discussion', '')
        check_content = check.get('Check Content', '')

        # Sanitize STIG ID for filename
        safe_stig_id = sanitize_filename(stig_id)

        # Clean up text for script templates
        description = discussion.replace('\n', '\n#     ')[:500]  # Limit length
        check_text = check_content.replace('\n', '\n#     ')[:500]  # Limit length

        # Generate bash script
        bash_content = BASH_TEMPLATE.format(
            vuln_id=vuln_id,
            stig_id=stig_id,
            severity=severity,
            rule_title=rule_title.replace("'", "'\\''"),
            rule_id=rule_id,
            description=description,
            check_content=check_text,
            primary_command=container_config['primary_command']
        )

        bash_file = output_dir / f"{safe_stig_id}.sh"
        with open(bash_file, 'w') as f:
            f.write(bash_content)

        # Make executable
        bash_file.chmod(bash_file.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
        bash_count += 1

        # Generate Python script
        python_content = PYTHON_TEMPLATE.format(
            vuln_id=vuln_id,
            stig_id=stig_id,
            severity=severity,
            rule_title=rule_title.replace('"', '\\"'),
            rule_id=rule_id,
            description=discussion[:500],  # Limit length
            check_content=check_content[:500],  # Limit length
            primary_command=container_config['primary_command']
        )

        python_file = output_dir / f"{safe_stig_id}.py"
        with open(python_file, 'w') as f:
            f.write(python_content)

        # Make executable
        python_file.chmod(python_file.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
        python_count += 1

    print(f"Generated {bash_count} bash scripts")
    print(f"Generated {python_count} Python scripts")

    # Generate README
    readme_content = README_TEMPLATE.format(
        name=container_config['name'],
        benchmark_id=container_config['benchmark_id'],
        version=container_config['version'],
        platform=container_config['platform'],
        primary_command=container_config['primary_command'],
        dir_name=container_config['dir_name']
    )

    readme_file = output_dir / "README.md"
    with open(readme_file, 'w') as f:
        f.write(readme_content)
    print(f"Generated README: {readme_file}")

    # Generate example configuration file
    config_example = {
        "kubernetes": {
            "kubeconfig": "/home/user/.kube/config",
            "context": "production-cluster",
            "namespace": "default"
        },
        "docker": {
            "socket": "/var/run/docker.sock",
            "tls_verify": True,
            "cert_path": "/path/to/certs"
        },
        "output": {
            "format": "json",
            "directory": "./results"
        }
    }

    config_file = output_dir / "config-example.json"
    with open(config_file, 'w') as f:
        json.dump(config_example, f, indent=2)
    print(f"Generated example config: {config_file}")

    # Generate automation report
    reports_dir = base_dir / "reports"
    reports_dir.mkdir(exist_ok=True)

    report_file = reports_dir / f"{container_config['dir_name']}_automation_analysis.txt"
    fully_auto, partial_auto, manual = generate_automation_report(
        container_config, checks, report_file
    )
    print(f"Generated automation report: {report_file}")

    # Save extracted checks to JSON for reference
    checks_json_file = base_dir / f"{container_config['dir_name']}_checks.json"
    with open(checks_json_file, 'w') as f:
        json.dump(checks, f, indent=2)
    print(f"Saved extracted checks: {checks_json_file}")

    return {
        'name': container_config['name'],
        'dir': output_dir,
        'total_checks': len(checks),
        'bash_scripts': bash_count,
        'python_scripts': python_count,
        'total_files': bash_count + python_count + 2,  # +2 for README and config
        'report_file': report_file,
        'fully_automatable': fully_auto,
        'partially_automatable': partial_auto,
        'manual_only': manual
    }

def main():
    """Main execution"""
    print("\n" + "="*80)
    print("Container Technologies STIG Automation Framework Generator")
    print("="*80)
    print(f"\nGenerating frameworks for {len(CONTAINER_STIGS)} container platforms:")
    for ct in CONTAINER_STIGS:
        print(f"  - {ct['name']} ({ct['version']})")

    base_dir = Path(__file__).parent
    results = []

    # Generate frameworks for all container platforms
    for container in CONTAINER_STIGS:
        result = generate_container_framework(container, base_dir)
        if result:
            results.append(result)

    if not results:
        print("\nERROR: No frameworks generated. Check AllSTIGS2.json content.")
        sys.exit(1)

    # Generate consolidated summary report
    print(f"\n{'='*80}")
    print("CONSOLIDATED SUMMARY")
    print(f"{'='*80}\n")

    total_checks = sum(r['total_checks'] for r in results)
    total_files = sum(r['total_files'] for r in results)
    total_bash = sum(r['bash_scripts'] for r in results)
    total_python = sum(r['python_scripts'] for r in results)

    print(f"Container Platforms: {len(results)}")
    print(f"Total STIG Checks:   {total_checks}")
    print(f"Total Files Created: {total_files}")
    print(f"  - Bash Scripts:    {total_bash}")
    print(f"  - Python Scripts:  {total_python}")
    print(f"  - README Files:    {len(results)}")
    print(f"  - Config Examples: {len(results)}")

    print(f"\n{'='*80}")
    print("AUTOMATION STATISTICS")
    print(f"{'='*80}\n")

    for result in results:
        print(f"{result['name']}:")
        print(f"  Total Checks:            {result['total_checks']}")
        if result['total_checks'] > 0:
            print(f"  Fully Automatable:       {result['fully_automatable']} ({result['fully_automatable']/result['total_checks']*100:.1f}%)")
            print(f"  Partially Automatable:   {result['partially_automatable']} ({result['partially_automatable']/result['total_checks']*100:.1f}%)")
            print(f"  Manual Review Required:  {result['manual_only']} ({result['manual_only']/result['total_checks']*100:.1f}%)")
        print()

    print(f"{'='*80}")
    print("REPORT FILE PATHS")
    print(f"{'='*80}\n")

    for result in results:
        print(f"{result['name']}:")
        print(f"  {result['report_file']}")
        print()

    print(f"{'='*80}")
    print("GENERATION COMPLETE - Priority 8: 100% COMPLETE!")
    print(f"{'='*80}\n")
    print("All container STIG automation frameworks have been generated successfully.")
    print("\nNext steps:")
    print("1. Review generated framework scripts in checks/container/")
    print("2. Review automation reports in reports/")
    print("3. Implement platform-specific check logic (TODO placeholders)")
    print("4. Test with actual Docker/Kubernetes environments")
    print("5. Secure configuration files (chmod 600)")
    print("\nNote: All scripts are stub implementations requiring container domain expertise.")
    print("\n🎉 PROJECT COMPLETE: All 8 priorities (32 STIGs) frameworks generated!")

if __name__ == '__main__':
    main()
