#!/usr/bin/env python3
"""
Complete Firewall STIG Automation Framework Generator

Generates automation frameworks for all 3 firewall STIG benchmarks:
- Palo Alto Networks NDM (34 checks)
- Cisco ASA NDM (47 checks)
- Fortinet FortiGate Firewall NDM (60 checks)

Tool Priority: bash > python > third-party
Platform: Network devices (SSH/API access required)

Exit Codes: 0=PASS, 1=FAIL, 2=N/A, 3=ERROR
"""

import json
import sys
from pathlib import Path
from datetime import datetime
import stat
import re

# Firewall STIG products configuration
FIREWALL_STIGS = [
    {
        "name": "Palo Alto Networks NDM",
        "benchmark_id": "Palo_Alto_Networks_NDM_STIG",
        "json_file": "palo_alto_ndm_checks.json",
        "dir_name": "palo_alto_ndm",
        "total_checks": 34,
        "default_port": 22,
        "connection_type": "SSH/API"
    },
    {
        "name": "Cisco ASA NDM",
        "benchmark_id": "Cisco_ASA_NDM_STIG",
        "json_file": "cisco_asa_ndm_checks.json",
        "dir_name": "cisco_asa_ndm",
        "total_checks": 47,
        "default_port": 22,
        "connection_type": "SSH"
    },
    {
        "name": "Fortinet FortiGate Firewall NDM",
        "benchmark_id": "FN_FortiGate_Firewall_NDM_STIG",
        "json_file": "fortinet_fortigate_ndm_checks.json",
        "dir_name": "fortinet_fortigate_ndm",
        "total_checks": 60,
        "default_port": 22,
        "connection_type": "SSH/API"
    }
]

# ============================================================================
# BASH SCRIPT TEMPLATE (Primary for Network Devices)
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

# Default connection parameters (override with config file)
DEVICE_HOST=""
DEVICE_PORT="{default_port}"
DEVICE_USER=""
DEVICE_PASSWORD=""
SSH_KEY_FILE=""
USE_API=false
API_KEY=""

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
        --host)
            DEVICE_HOST="$2"
            shift 2
            ;;
        --port)
            DEVICE_PORT="$2"
            shift 2
            ;;
        --user)
            DEVICE_USER="$2"
            shift 2
            ;;
        -h|--help)
            cat << 'EOF'
Usage: $0 [OPTIONS]

Options:
  --config <file>         Configuration file (JSON)
  --output-json <file>    Output results in JSON format
  --host <hostname>       Device hostname or IP address
  --port <port>           Device SSH/API port (default: {default_port})
  --user <username>       Device username
  -h, --help             Show this help message

Exit Codes:
  0 = Pass (Compliant)
  1 = Fail (Finding)
  2 = Not Applicable
  3 = Error

Configuration File Format (JSON):
{{
  "device": {{
    "host": "firewall.example.com",
    "port": {default_port},
    "username": "admin",
    "auth_method": "key",
    "ssh_key_file": "/path/to/key",
    "api_key": "optional_api_key"
  }}
}}

Example:
  $0 --config device-config.json
  $0 --host 192.168.1.1 --user admin --output-json results.json
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

    # Load device connection parameters from JSON config
    if command -v jq &> /dev/null; then
        DEVICE_HOST=$(jq -r '.device.host // empty' "$CONFIG_FILE")
        DEVICE_PORT=$(jq -r '.device.port // {default_port}' "$CONFIG_FILE")
        DEVICE_USER=$(jq -r '.device.username // empty' "$CONFIG_FILE")
        SSH_KEY_FILE=$(jq -r '.device.ssh_key_file // empty' "$CONFIG_FILE")
        API_KEY=$(jq -r '.device.api_key // empty' "$CONFIG_FILE")
    else
        echo "WARNING: jq not found, cannot parse config file"
    fi
fi

################################################################################
# NETWORK DEVICE HELPER FUNCTIONS
################################################################################

# Execute SSH command on device
ssh_exec() {{
    local command="$1"
    local result=""

    if [[ -z "$DEVICE_HOST" ]] || [[ -z "$DEVICE_USER" ]]; then
        echo "ERROR: Device host and user must be specified"
        return 3
    fi

    # Build SSH command with appropriate authentication
    local ssh_cmd="ssh -p $DEVICE_PORT"

    if [[ -n "$SSH_KEY_FILE" ]]; then
        ssh_cmd="$ssh_cmd -i $SSH_KEY_FILE"
    fi

    ssh_cmd="$ssh_cmd $DEVICE_USER@$DEVICE_HOST"

    # Execute command
    result=$($ssh_cmd "$command" 2>&1)
    local exit_code=$?

    echo "$result"
    return $exit_code
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
  "timestamp": "$TIMESTAMP",
  "device": {{
    "host": "$DEVICE_HOST",
    "port": "$DEVICE_PORT"
  }}
}}
EOF
}}

################################################################################
# MAIN CHECK LOGIC
################################################################################

main() {{
    # Validate prerequisites
    if [[ -z "$DEVICE_HOST" ]]; then
        echo "ERROR: Device host not specified (use --host or --config)"
        [[ -n "$OUTPUT_JSON" ]] && output_json "ERROR" "Device host not specified" ""
        exit 3
    fi

    # TODO: Implement actual STIG check logic
    # This is a stub implementation requiring firewall domain expertise
    #
    # Implementation notes:
    # 1. Connect to device via SSH or API
    # 2. Execute appropriate show/get commands
    # 3. Parse output to verify compliance
    # 4. Return appropriate exit code
    #
    # Example for SSH-based check:
    # output=$(ssh_exec "show running-config | grep <pattern>")
    # if [[ $? -ne 0 ]]; then
    #     echo "ERROR: Failed to connect to device"
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
    echo "This check requires firewall domain expertise to implement"

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
VULN_ID = "{vuln_id}"
STIG_ID = "{stig_id}"
SEVERITY = "{severity}"
DEFAULT_PORT = {default_port}

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
            print(f"ERROR: SSH connection failed: {{e}}", file=sys.stderr)
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
    #     return (3, f"Error executing check: {{e}}", "")
    # finally:
    #     conn.close()

    return (3, "Not implemented - Stub implementation",
            "This check requires firewall domain expertise to implement")

def main():
    parser = argparse.ArgumentParser(
        description=f"STIG Check {{STIG_ID}} - {rule_title}",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('--config', help='Configuration file (JSON)')
    parser.add_argument('--output-json', help='Output results in JSON format')
    parser.add_argument('--host', help='Device hostname or IP address')
    parser.add_argument('--port', type=int, default=DEFAULT_PORT,
                       help=f'Device SSH/API port (default: {{DEFAULT_PORT}})')
    parser.add_argument('--user', help='Device username')

    args = parser.parse_args()

    # Load configuration
    device_config = {{}}
    if args.config:
        config = load_config(args.config)
        device_config = config.get('device', {{}})

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
- **Total Checks**: {total_checks}
- **Connection Type**: {connection_type}
- **Default Port**: {default_port}
- **Tool Priority**: bash > python > third-party

## Directory Structure

```
{dir_name}/
├── README.md                    # This file
├── config-example.json          # Example configuration file
├── <STIG-ID>.sh                # Bash scripts for each check
└── <STIG-ID>.py                # Python scripts for each check
```

## Device Connection Requirements

### SSH Access
- SSH connectivity to the firewall device
- Valid credentials (username/password or SSH key)
- Appropriate privilege level for read-only commands
- Default port: {default_port} (configurable)

### API Access (if supported)
- API endpoint URL
- Valid API key or token
- Network connectivity to management interface

### Security Considerations
- **Never** store credentials in scripts
- Use configuration files with restricted permissions (chmod 600)
- Consider using SSH keys instead of passwords
- Use encrypted vaults (Ansible Vault, HashiCorp Vault) for sensitive data
- Rotate credentials regularly
- Use read-only accounts when possible

## Configuration File

Create a configuration file (e.g., `device-config.json`) with device connection parameters:

```json
{{
  "device": {{
    "host": "firewall.example.com",
    "port": {default_port},
    "username": "readonly-user",
    "auth_method": "key",
    "ssh_key_file": "/secure/path/to/ssh-key",
    "password": null,
    "api_key": null
  }},
  "output": {{
    "format": "json",
    "directory": "./results"
  }}
}}
```

**Important**: Set restrictive permissions on configuration files:
```bash
chmod 600 device-config.json
```

## Quick Start

### Individual Check Execution

Run a single STIG check using bash (primary):
```bash
# Using configuration file
./STIG-ID-001.sh --config device-config.json

# Using command-line arguments
./STIG-ID-001.sh --host 192.168.1.1 --user admin

# With JSON output
./STIG-ID-001.sh --config device-config.json --output-json results.json
```

Run using Python (fallback):
```bash
# Requires: paramiko for SSH, requests for API
pip3 install paramiko requests

python3 STIG-ID-001.py --config device-config.json
python3 STIG-ID-001.py --host 192.168.1.1 --user admin --output-json results.json
```

### Batch Execution

Run all checks in the directory:
```bash
#!/bin/bash
# Example batch execution script

CONFIG_FILE="device-config.json"
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
- `--host <hostname>` - Device hostname or IP address
- `--port <port>` - Device SSH/API port (default: {default_port})
- `--user <username>` - Device username
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
  "timestamp": "2025-11-22T12:34:56Z",
  "device": {{
    "host": "firewall.example.com",
    "port": {default_port}
  }}
}}
```

## Implementation Status

**Current Status**: Framework/Stub Implementation

All scripts in this directory are **framework implementations** with TODO placeholders. They provide:
- ✓ Complete script structure and argument parsing
- ✓ Device connection helper functions (SSH/API placeholders)
- ✓ Configuration file support
- ✓ JSON output formatting
- ✓ Standardized exit codes
- ✗ Actual STIG check logic (requires firewall domain expertise)

### To Complete Implementation

Each script requires:
1. Device-specific command execution (show, get, etc.)
2. Output parsing and compliance verification
3. Error handling for device connectivity issues
4. Testing against actual firewall devices

## Dependencies

### Bash Scripts
- bash 4.0+
- ssh client
- jq (optional, for JSON parsing)
- Standard UNIX utilities (grep, awk, sed)

### Python Scripts
- Python 3.6+
- paramiko (for SSH connections): `pip3 install paramiko`
- requests (for API connections): `pip3 install requests`

## Network Device Specifics

### Palo Alto Networks
- Connection: SSH (port 22) or XML API (port 443)
- Commands: `show`, `configure`
- API: REST/XML API with API key authentication
- Documentation: https://docs.paloaltonetworks.com/

### Cisco ASA
- Connection: SSH (port 22) or ASDM (port 443)
- Commands: `show running-config`, `show version`
- Privilege levels: User EXEC, Privileged EXEC
- Documentation: https://www.cisco.com/c/en/us/support/security/asa-5500-series-next-generation-firewalls/

### Fortinet FortiGate
- Connection: SSH (port 22) or HTTPS API (port 443)
- Commands: `get`, `show`, `diagnose`
- API: FortiOS REST API with API token
- Documentation: https://docs.fortinet.com/

## Troubleshooting

### SSH Connection Issues
```bash
# Test SSH connectivity
ssh -p {default_port} user@firewall.example.com

# Test with specific key
ssh -i /path/to/key -p {default_port} user@firewall.example.com

# Enable verbose mode
ssh -v -p {default_port} user@firewall.example.com
```

### Permission Errors
```bash
# Make scripts executable
chmod +x *.sh

# Check file permissions
ls -l *.sh

# Secure configuration file
chmod 600 device-config.json
```

### Python Dependencies
```bash
# Install required packages
pip3 install paramiko requests

# Verify installation
python3 -c "import paramiko; import requests; print('OK')"
```

## Additional Resources

- DISA STIG Viewer: https://public.cyber.mil/stigs/srg-stig-tools/
- STIG Documentation: https://public.cyber.mil/stigs/downloads/
- Automation Guide: See main repository README

## Support

For issues or questions:
1. Check script help: `./script.sh --help`
2. Review STIG documentation
3. Verify device connectivity and credentials
4. Check script implementation status (stub vs. complete)

---

**Note**: This is an automation framework. All scripts require domain expertise to complete implementation with actual device-specific logic.
'''

# ============================================================================
# REPORT GENERATION
# ============================================================================

def generate_automation_report(firewall_config, checks, output_file):
    """Generate automation analysis report for a firewall STIG"""

    # Analyze automation feasibility
    fully_automatable = 0
    partially_automatable = 0
    manual_only = 0

    for check in checks:
        check_content = check.get('Check Content', '').lower()

        # Keywords indicating automation feasibility
        if any(keyword in check_content for keyword in ['show', 'config', 'get', 'display']):
            fully_automatable += 1
        elif any(keyword in check_content for keyword in ['review', 'verify', 'interview', 'examine']):
            if any(keyword in check_content for keyword in ['log', 'file', 'configuration']):
                partially_automatable += 1
            else:
                manual_only += 1
        else:
            partially_automatable += 1

    # Generate report
    report = f"""
{'='*80}
{firewall_config['name']} STIG Automation Analysis v3
{'='*80}

Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Benchmark: {firewall_config['benchmark_id']}
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
    report += f"Output Directory: checks/network/{firewall_config['dir_name']}/\n"
    report += f"Scripts Generated: {len(checks) * 2} ({len(checks)} bash + {len(checks)} Python)\n"
    report += f"Connection Type: {firewall_config['connection_type']}\n"
    report += f"Default Port: {firewall_config['default_port']}\n"
    report += f"Tool Priority: bash > python > third-party\n"

    report += f"\n{'='*80}\n"
    report += "IMPLEMENTATION NOTES\n"
    report += f"{'='*80}\n\n"
    report += "All scripts are STUB/FRAMEWORK implementations with:\n"
    report += "  ✓ Complete argument parsing and configuration support\n"
    report += "  ✓ Device connection helper functions (SSH/API)\n"
    report += "  ✓ JSON output formatting\n"
    report += "  ✓ Standardized exit codes (0=PASS, 1=FAIL, 2=N/A, 3=ERROR)\n"
    report += "  ✗ Actual check logic (TODO - requires firewall expertise)\n\n"
    report += "Network Device Requirements:\n"
    report += "  - SSH access with appropriate credentials\n"
    report += "  - Read-only privilege level (minimum)\n"
    report += "  - Network connectivity to management interface\n"
    report += "  - Optional: API access for programmatic queries\n\n"
    report += "Security Considerations:\n"
    report += "  - Never store credentials in scripts\n"
    report += "  - Use configuration files with chmod 600\n"
    report += "  - Prefer SSH keys over passwords\n"
    report += "  - Use credential vaults for production\n"
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
    report += f"Testing Status:       NOT TESTED (requires actual devices)\n"
    report += f"Production Ready:     NO (implementation incomplete)\n"

    report += f"\n{'='*80}\n"
    report += "NEXT STEPS\n"
    report += f"{'='*80}\n\n"
    report += "1. Review generated framework scripts\n"
    report += "2. Implement device-specific check logic for each STIG\n"
    report += "3. Test against actual firewall devices\n"
    report += "4. Create device configuration files (chmod 600)\n"
    report += "5. Validate all exit codes and error handling\n"
    report += "6. Document any device-specific requirements\n"
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

def generate_firewall_framework(firewall_config, base_dir):
    """Generate complete automation framework for a firewall STIG"""

    print(f"\n{'='*80}")
    print(f"Generating {firewall_config['name']} STIG Framework")
    print(f"{'='*80}\n")

    # Load checks from JSON
    json_file = base_dir / firewall_config['json_file']
    print(f"Loading checks from: {json_file}")

    try:
        with open(json_file, 'r') as f:
            checks = json.load(f)
        print(f"Loaded {len(checks)} checks")
    except Exception as e:
        print(f"ERROR: Failed to load {json_file}: {e}")
        return None

    # Create output directory
    output_dir = base_dir / "checks" / "network" / firewall_config['dir_name']
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
        description = discussion.replace('\n', '\n#     ')
        check_text = check_content.replace('\n', '\n#     ')

        # Generate bash script
        bash_content = BASH_TEMPLATE.format(
            vuln_id=vuln_id,
            stig_id=stig_id,
            severity=severity,
            rule_title=rule_title.replace("'", "'\\''"),
            rule_id=rule_id,
            description=description,
            check_content=check_text,
            default_port=firewall_config['default_port']
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
            description=discussion,
            check_content=check_content,
            default_port=firewall_config['default_port']
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
        name=firewall_config['name'],
        benchmark_id=firewall_config['benchmark_id'],
        total_checks=len(checks),
        connection_type=firewall_config['connection_type'],
        default_port=firewall_config['default_port'],
        dir_name=firewall_config['dir_name']
    )

    readme_file = output_dir / "README.md"
    with open(readme_file, 'w') as f:
        f.write(readme_content)
    print(f"Generated README: {readme_file}")

    # Generate example configuration file
    config_example = {
        "device": {
            "host": "firewall.example.com",
            "port": firewall_config['default_port'],
            "username": "readonly-user",
            "auth_method": "key",
            "ssh_key_file": "/secure/path/to/ssh-key",
            "password": None,
            "api_key": None
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

    report_file = reports_dir / f"{firewall_config['dir_name']}_automation_analysis_v3.txt"
    fully_auto, partial_auto, manual = generate_automation_report(
        firewall_config, checks, report_file
    )
    print(f"Generated automation report: {report_file}")

    return {
        'name': firewall_config['name'],
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
    print("Firewall STIG Automation Framework Generator")
    print("="*80)
    print(f"\nGenerating frameworks for {len(FIREWALL_STIGS)} firewall platforms:")
    for fw in FIREWALL_STIGS:
        print(f"  - {fw['name']} ({fw['total_checks']} checks)")

    base_dir = Path(__file__).parent
    results = []

    # Generate frameworks for all firewalls
    for firewall in FIREWALL_STIGS:
        result = generate_firewall_framework(firewall, base_dir)
        if result:
            results.append(result)

    # Generate consolidated summary report
    print(f"\n{'='*80}")
    print("CONSOLIDATED SUMMARY")
    print(f"{'='*80}\n")

    total_checks = sum(r['total_checks'] for r in results)
    total_files = sum(r['total_files'] for r in results)
    total_bash = sum(r['bash_scripts'] for r in results)
    total_python = sum(r['python_scripts'] for r in results)

    print(f"Firewall Platforms:  {len(results)}")
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
        print(f"  Fully Automatable:       {result['fully_automatable']} ({result['fully_automatable']/result['total_checks']*100:.1f}%)")
        print(f"  Partially Automatable:   {result['partially_automatable']} ({result['partially_automatable']/result['total_checks']*100:.1f}%)")
        print(f"  Manual Review Required:  {result['manual_only']} ({result['manual_only']/result['total_checks']*100:.1f}%)")
        print()

    print(f"{'='*80}")
    print("SAMPLE SCRIPT PATHS")
    print(f"{'='*80}\n")

    for result in results:
        # Find first check file
        scripts = list(result['dir'].glob("*.sh"))
        if scripts:
            print(f"{result['name']}:")
            print(f"  Bash:   {scripts[0]}")
            py_script = scripts[0].with_suffix('.py')
            print(f"  Python: {py_script}")
            print()

    print(f"{'='*80}")
    print("REPORT FILE PATHS")
    print(f"{'='*80}\n")

    for result in results:
        print(f"{result['name']}:")
        print(f"  {result['report_file']}")
        print()

    print(f"{'='*80}")
    print("GENERATION COMPLETE")
    print(f"{'='*80}\n")
    print("All firewall STIG automation frameworks have been generated successfully.")
    print("\nNext steps:")
    print("1. Review generated framework scripts in checks/network/")
    print("2. Review automation reports in reports/")
    print("3. Implement device-specific check logic (TODO placeholders)")
    print("4. Test with actual firewall devices")
    print("5. Secure configuration files (chmod 600)")
    print("\nNote: All scripts are stub implementations requiring firewall domain expertise.")

if __name__ == '__main__':
    main()
