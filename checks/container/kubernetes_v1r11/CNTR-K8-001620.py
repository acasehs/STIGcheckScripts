#!/usr/bin/env python3
"""
STIG Check: V-242434
Severity: high
Rule Title: Kubernetes Kubelet must enable kernel protection.
STIG ID: CNTR-K8-001620
Rule ID: SV-242434r961131

Description:
    System kernel is responsible for memory, disk, and task management. The kernel provides a gateway between the system hardware and software. Kubernetes requires kernel access to allocate resources to the Control Plane. Threat actors that penetrate the system kernel can inject malicious code or hijack the Kubernetes architecture. It is vital to implement protections through Kubernetes components to reduce the attack surface.

Check Content:
    On the Control Plane, run the command:
ps -ef | grep kubelet

If the "--protect-kernel-defaults" option exists, this is a finding.

Note the path to the config file (identified by --config).

Run the command:
grep -i protectKernelDefaults <path_to_config_file>

If the setting "protectKernelDefaults" is not set or is set to false, this is a finding.

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
VULN_ID = "V-242434"
STIG_ID = "CNTR-K8-001620"
SEVERITY = "high"
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

    # Check docker daemon process
    stdout, error = run_command("ps -ef | grep dockerd | grep -v grep")

    if error:
        return (3, f"Error checking docker process: {error}", "")

    # Check for TCP binding
    if "-H TCP://" in stdout:
        return (1, "FAIL: Docker daemon configured with TCP binding", stdout)
    elif "-H UNIX://" in stdout or "/var/run/docker.sock" in stdout:
        return (0, "PASS: Docker daemon using UNIX socket (compliant)", stdout)
    else:
        return (1, "FAIL: Unable to determine docker daemon configuration", stdout)

    return (3, "Not implemented - Stub implementation",
            "This check requires container domain expertise to implement")

def main():
    parser = argparse.ArgumentParser(
        description=f"STIG Check {STIG_ID} - Kubernetes Kubelet must enable kernel protection.",
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
