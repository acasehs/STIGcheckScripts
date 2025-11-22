#!/usr/bin/env python3
"""
STIG Check: V-234213
Severity: medium
Rule Title: The FortiGate device must terminate idle sessions after 10 minutes of inactivity.
STIG ID: FGFW-ND-000270
Rule ID: SV-234213r879621

Description:
    If a device management session or connection remains open after management is completed, it may be hijacked by an attacker and used to compromise or damage the network device.

Nonlocal device management and diagnostic activities are those activities conducted by individuals communicating through a network, either an external network (e.g., the internet) or an internal network. 

In the event the remote node has abnormally terminated or an upstream link from the managed device is down, the management session will be terminated, thereby freeing device resources and eliminating any possibility of an unauthorized user being orphaned to an open idle session of the managed device.

Check Content:
    Verify the FortiGate device terminates all network connections when non-local device maintenance is complete.

Log in to the FortiGate GUI with Super-Admin privilege.

1. Click System.
2. Click Settings.
3. Go to Administrative Settings.
4. Verify Idle Timeout is configured to 10 minutes.

If the idle-timeout value is not 10 minutes, this is a finding.

or 

1. Open a CLI console, via SSH or available from the GUI.
2. Run the following command:
     # show full-configuration sys global | grep -i admintimeout

The output should be:         
          set admintimeout 10

If the admintimeout parameter is not set to 10 minutes, this is a finding.

Exit Codes:
    0 = Check Passed (Compliant)
    1 = Check Failed (Finding)
    2 = Check Not Applicable
    3 = Check Error
"""

import sys
import json
import argparse
from datetime import datetime
from pathlib import Path

# Try to import paramiko for SSH connections
try:
    import paramiko
    PARAMIKO_AVAILABLE = True
except ImportError:
    PARAMIKO_AVAILABLE = False

# Try to import requests for API connections
try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

# Configuration
VULN_ID = "V-234213"
STIG_ID = "FGFW-ND-000270"
SEVERITY = "medium"
DEFAULT_PORT = 22

class DeviceConnection:
    """Handle SSH/API connections to network devices"""

    def __init__(self, host, port=DEFAULT_PORT, username=None, password=None,
                 key_file=None, api_key=None):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.key_file = key_file
        self.api_key = api_key
        self.ssh_client = None

    def connect_ssh(self):
        """Establish SSH connection to device"""
        if not PARAMIKO_AVAILABLE:
            raise RuntimeError("paramiko library not available for SSH connections")

        self.ssh_client = paramiko.SSHClient()
        self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        try:
            if self.key_file:
                key = paramiko.RSAKey.from_private_key_file(self.key_file)
                self.ssh_client.connect(
                    self.host,
                    port=self.port,
                    username=self.username,
                    pkey=key
                )
            else:
                self.ssh_client.connect(
                    self.host,
                    port=self.port,
                    username=self.username,
                    password=self.password
                )
            return True
        except Exception as e:
            print(f"ERROR: SSH connection failed: {e}", file=sys.stderr)
            return False

    def execute_command(self, command):
        """Execute command via SSH"""
        if not self.ssh_client:
            raise RuntimeError("Not connected to device")

        stdin, stdout, stderr = self.ssh_client.exec_command(command)
        output = stdout.read().decode('utf-8')
        error = stderr.read().decode('utf-8')
        exit_code = stdout.channel.recv_exit_status()

        return output, error, exit_code

    def close(self):
        """Close SSH connection"""
        if self.ssh_client:
            self.ssh_client.close()

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

def perform_check(device_config):
    """
    Perform the actual STIG check

    TODO: Implement actual check logic
    This is a stub implementation requiring firewall domain expertise

    Implementation notes:
    1. Connect to device via SSH or API
    2. Execute appropriate show/get commands
    3. Parse output to verify compliance
    4. Return (exit_code, message, details)

    Returns:
        tuple: (exit_code, message, details)
               exit_code: 0=PASS, 1=FAIL, 2=N/A, 3=ERROR
               message: Human-readable status message
               details: Additional details about the check
    """

    # Example implementation structure:
    # conn = DeviceConnection(
    #     host=device_config.get('host'),
    #     port=device_config.get('port', DEFAULT_PORT),
    #     username=device_config.get('username'),
    #     password=device_config.get('password'),
    #     key_file=device_config.get('ssh_key_file')
    # )
    #
    # if not conn.connect_ssh():
    #     return (3, "Failed to connect to device", "")
    #
    # try:
    #     output, error, exit_code = conn.execute_command("show running-config")
    #
    #     # Analyze output for compliance
    #     if "expected_pattern" in output:
    #         return (0, "Compliant", output)
    #     else:
    #         return (1, "Non-compliant - Finding", output)
    # except Exception as e:
    #     return (3, f"Error executing check: {e}", "")
    # finally:
    #     conn.close()

    return (3, "Not implemented - Stub implementation",
            "This check requires firewall domain expertise to implement")

def main():
    parser = argparse.ArgumentParser(
        description=f"STIG Check {STIG_ID} - The FortiGate device must terminate idle sessions after 10 minutes of inactivity.",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('--config', help='Configuration file (JSON)')
    parser.add_argument('--output-json', help='Output results in JSON format')
    parser.add_argument('--host', help='Device hostname or IP address')
    parser.add_argument('--port', type=int, default=DEFAULT_PORT,
                       help=f'Device SSH/API port (default: {DEFAULT_PORT})')
    parser.add_argument('--user', help='Device username')

    args = parser.parse_args()

    # Load configuration
    device_config = {}
    if args.config:
        config = load_config(args.config)
        device_config = config.get('device', {})

    # Override with command-line arguments
    if args.host:
        device_config['host'] = args.host
    if args.port:
        device_config['port'] = args.port
    if args.user:
        device_config['username'] = args.user

    # Validate required parameters
    if not device_config.get('host'):
        print("ERROR: Device host not specified (use --host or --config)",
              file=sys.stderr)
        if args.output_json:
            output_json(args.output_json, "ERROR",
                       "Device host not specified")
        sys.exit(3)

    # Perform the check
    exit_code, message, details = perform_check(device_config)

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
