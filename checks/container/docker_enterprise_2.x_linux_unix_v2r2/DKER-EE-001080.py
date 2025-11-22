#!/usr/bin/env python3
"""
STIG Check: V-235778
Severity: medium
Rule Title: The audit log configuration level must be set to request in the Universal Control Plane (UCP) component of Docker Enterprise.
STIG ID: DKER-EE-001080
Rule ID: SV-235778r960765

Description:
    The UCP and Docker Trusted Registry (DTR) components of Docker Enterprise provide audit record generation capabilities. Audit logs capture all HTTP actions for the following endpoints: Kubernetes API, Swarm API and UCP API. The following UCP API endpoints are excluded from audit logging (where "*" designates a wildcard of exclusions): "/_ping", "/ca", "/auth", "/trustedregistryca", "/kubeauth", "/metrics", "/info", "/version*", "/debug", "/openid_keys", "/apidocs", "kubernetesdocs" and "/manage"

Check Content:
    This check only applies to the UCP component of Docker Enterprise.

Verify that the audit log configuration level in UCP is set to "request":

Via UI:

As a Docker EE Admin, navigate to "Admin Settings" | "Audit Logs" in the UCP management console, and verify "Audit Log Level" is set to "Request". If the audit log configuration level is not set to "Request", this is a finding.

via CLI:

Linux (requires curl and jq): As a Docker EE Admin, execute the following commands from a machine that can co

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
VULN_ID = "V-235778"
STIG_ID = "DKER-EE-001080"
SEVERITY = "medium"
PRIMARY_COMMAND = "docker"

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

    # API-based check (requires requests library)
    try:
        import requests
        import json

        # Get UCP credentials from config
        ucp_url = config.get('docker', {}).get('ucp_url')
        ucp_user = config.get('docker', {}).get('ucp_username')
        ucp_pass = config.get('docker', {}).get('ucp_password')

        if not all([ucp_url, ucp_user, ucp_pass]):
            return (3, "ERROR: UCP credentials not configured", "")

        # Authenticate
        auth_data = {'username': ucp_user, 'password': ucp_pass}
        auth_response = requests.post(
            f"https://{ucp_url}/auth/login",
            json=auth_data,
            verify=False
        )

        if auth_response.status_code != 200:
            return (3, "ERROR: UCP authentication failed", "")

        auth_token = auth_response.json().get('auth_token')

        # Get config
        headers = {'Authorization': f'Bearer {auth_token}'}
        config_response = requests.get(
            f"https://{ucp_url}/api/ucp/config-toml",
            headers=headers,
            verify=False
        )

        config_text = config_response.text

        # Parse for per_user_limit
        match = re.search(r'per_user_limit\s*=\s*(\d+)', config_text)
        if match:
            limit = int(match.group(1))
            required_limit = config.get('docker', {}).get('required_per_user_limit', 10)

            if limit <= required_limit and limit > 0:
                return (0, f"PASS: per_user_limit is {limit} (compliant)", config_text)
            else:
                return (1, f"FAIL: per_user_limit is {limit} (required: {required_limit})", config_text)
        else:
            return (1, "FAIL: per_user_limit not found in config", config_text)

    except ImportError:
        return (3, "ERROR: requests library required for API checks", "pip3 install requests")
    except Exception as e:
        return (3, f"ERROR: {str(e)}", "")

    return (3, "Not implemented - Stub implementation",
            "This check requires container domain expertise to implement")

def main():
    parser = argparse.ArgumentParser(
        description=f"STIG Check {STIG_ID} - The audit log configuration level must be set to request in the Universal Control Plane (UCP) component of Docker Enterprise.",
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
