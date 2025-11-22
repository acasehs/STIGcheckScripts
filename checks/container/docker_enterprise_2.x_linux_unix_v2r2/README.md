# Docker Enterprise 2.x Linux/UNIX STIG Automation Framework

## Overview

This directory contains automation scripts for the **Docker Enterprise 2.x Linux/UNIX** Security Technical Implementation Guide (STIG).

- **Benchmark ID**: Docker_Enterprise_2-x_Linux-UNIX_STIG
- **Version**: v2r2
- **Platform**: Linux/UNIX
- **Primary Command**: `docker`
- **Tool Priority**: bash > python > third-party

## Directory Structure

```
docker_enterprise_2.x_linux_unix_v2r2/
├── README.md                    # This file
├── config-example.json          # Example configuration file
├── <STIG-ID>.sh                # Bash scripts for each check
└── <STIG-ID>.py                # Python scripts for each check
```

## Requirements

### Command-Line Tools
- `docker` - Primary tool for Docker Enterprise 2.x Linux/UNIX
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
{
  "kubernetes": {
    "kubeconfig": "/home/user/.kube/config",
    "context": "production-cluster",
    "namespace": "default"
  },
  "docker": {
    "socket": "/var/run/docker.sock",
    "tls_verify": true,
    "cert_path": "/path/to/certs"
  },
  "output": {
    "format": "json",
    "directory": "./results"
  }
}
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
- `--namespace <name>` - Kubernetes namespace (if applicable)
- `--context <name>` - Kubernetes context (if applicable)
- `--kubeconfig <file>` - Path to kubeconfig file
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
  "timestamp": "2025-11-22T12:34:56Z"
}
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
1. Specific CLI commands for the check (docker)
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
