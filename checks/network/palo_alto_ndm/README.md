# Palo Alto Networks NDM STIG Automation Framework

## Overview

This directory contains automation scripts for the **Palo Alto Networks NDM** Security Technical Implementation Guide (STIG).

- **Benchmark ID**: Palo_Alto_Networks_NDM_STIG
- **Total Checks**: 34
- **Connection Type**: SSH/API
- **Default Port**: 22
- **Tool Priority**: bash > python > third-party

## Directory Structure

```
palo_alto_ndm/
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
- Default port: 22 (configurable)

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
{
  "device": {
    "host": "firewall.example.com",
    "port": 22,
    "username": "readonly-user",
    "auth_method": "key",
    "ssh_key_file": "/secure/path/to/ssh-key",
    "password": null,
    "api_key": null
  },
  "output": {
    "format": "json",
    "directory": "./results"
  }
}
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
    stig_id="${script%.sh}"
    echo "Running check: $stig_id"

    ./"$script" --config "$CONFIG_FILE" \
        --output-json "$RESULTS_DIR/${stig_id}.json"

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
- `--port <port>` - Device SSH/API port (default: 22)
- `--user <username>` - Device username
- `-h, --help` - Display help message

### JSON Output Format

When using `--output-json`, results are written in this format:

```json
{
  "vuln_id": "V-XXXXX",
  "stig_id": "STIG-ID-XXX",
  "severity": "medium",
  "status": "PASS|FAIL|N/A|ERROR",
  "message": "Human-readable status message",
  "details": "Additional check details",
  "timestamp": "2025-11-22T12:34:56Z",
  "device": {
    "host": "firewall.example.com",
    "port": 22
  }
}
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
ssh -p 22 user@firewall.example.com

# Test with specific key
ssh -i /path/to/key -p 22 user@firewall.example.com

# Enable verbose mode
ssh -v -p 22 user@firewall.example.com
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
