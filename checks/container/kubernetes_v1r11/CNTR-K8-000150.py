#!/usr/bin/env python3
"""
STIG Check: V-242376
Severity: medium
Rule Title: The Kubernetes Controller Manager must use TLS 1.2, at a minimum, to protect the confidentiality of sensitive data during electronic dissemination.
STIG ID: CNTR-K8-000150
Rule ID: SV-242376r960759

Description:
    The Kubernetes Controller Manager will prohibit the use of SSL and unauthorized versions of TLS protocols to properly secure communication.

The use of unsupported protocol exposes vulnerabilities to the Kubernetes by rogue traffic interceptions, man-in-the-middle attacks, and impersonation of users or services from the container platform runtime, registry, and key store. To enable the minimum version of TLS to be used by the Kubernetes Controller Manager, the setting "tls-min-version" must be s

Check Content:
    Change to the /etc/kubernetes/manifests/ directory on the Kubernetes Control Plane. Run the command:

grep -i tls-min-version * 

If the setting "tls-min-version" is not configured in the Kubernetes Controller Manager manifest file or it is set to "VersionTLS10" or "VersionTLS11", this is a finding.

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
VULN_ID = "V-242376"
STIG_ID = "CNTR-K8-000150"
SEVERITY = "medium"
PRIMARY_COMMAND = "kubectl"

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
    stdout, error = run_command(f"docker {command}")
    return stdout, error

def kubectl_exec(command, namespace=None, context=None, kubeconfig=None):
    """Execute kubectl command"""
    cmd_parts = ["kubectl"]

    if kubeconfig:
        cmd_parts.append(f"--kubeconfig={kubeconfig}")
    if context:
        cmd_parts.append(f"--context={context}")
    if namespace:
        cmd_parts.append(f"--namespace={namespace}")

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
        print(f"ERROR: Failed to load config file: {e}", file=sys.stderr)
        sys.exit(3)

def output_json(output_file, status, message, details=""):
    """Output results in JSON format"""
    result = {
        "vuln_id": VULN_ID,
        "stig_id": STIG_ID,
        "severity": SEVERITY,
        "status": status,
        "message": message,
        "details": details,
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }

    try:
        with open(output_file, 'w') as f:
            json.dump(result, f, indent=2)
    except Exception as e:
        print(f"ERROR: Failed to write JSON output: {e}", file=sys.stderr)

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
    """
    Perform the actual STIG check
    """

    # Execute check based on type

    # TODO: Implement specific check logic
    # STIG ID: CNTR-K8-000150
    # Check Type: file_check
    # Check Content: Change to the /etc/kubernetes/manifests/ directory on the Kubernetes Control Plane. Run the command:

grep -i tls-min-version * 

If the setting "tls-min-version" is not configured in the Kubernetes C...

    return (3, "Not implemented - Requires domain expertise", "Stub implementation")

    return (3, "Not implemented - Stub implementation",
            "This check requires container domain expertise to implement")

def main():
    parser = argparse.ArgumentParser(
        description=f"STIG Check {STIG_ID} - The Kubernetes Controller Manager must use TLS 1.2, at a minimum, to protect the confidentiality of sensitive data during electronic dissemination.",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('--config', help='Configuration file (JSON)')
    parser.add_argument('--output-json', help='Output results in JSON format')
    parser.add_argument('--namespace', help='Kubernetes namespace (if applicable)')
    parser.add_argument('--context', help='Kubernetes context (if applicable)')
    parser.add_argument('--kubeconfig', help='Path to kubeconfig file')

    args = parser.parse_args()

    # Load configuration
    config = {}
    if args.config:
        config = load_config(args.config)

    # Override with command-line arguments
    if args.namespace:
        config.setdefault('kubernetes', {})['namespace'] = args.namespace
    if args.context:
        config.setdefault('kubernetes', {})['context'] = args.context
    if args.kubeconfig:
        config.setdefault('kubernetes', {})['kubeconfig'] = args.kubeconfig

    # Check if required command is available
    stdout, error = run_command(f"command -v {PRIMARY_COMMAND}", check_error=False)
    if not stdout or error:
        print(f"ERROR: {PRIMARY_COMMAND} command not found", file=sys.stderr)
        if args.output_json:
            output_json(args.output_json, "ERROR",
                       f"{PRIMARY_COMMAND} not available")
        sys.exit(3)

    # Perform the check
    exit_code, message, details = perform_check(config)

    # Output results
    print(f"{message}")
    if details:
        print(f"Details: {details}")

    if args.output_json:
        status_map = {0: "PASS", 1: "FAIL", 2: "N/A", 3: "ERROR"}
        output_json(args.output_json, status_map.get(exit_code, "ERROR"),
                   message, details)

    sys.exit(exit_code)

if __name__ == '__main__':
    main()
