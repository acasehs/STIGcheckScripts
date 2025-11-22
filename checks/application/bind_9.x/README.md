# BIND 9.x DNS - STIG Automation Framework

## Overview

Automated STIG compliance checks for **BIND 9.x DNS Server**.

- **Total Checks**: 70
- **Platform**: UNIX/Linux
- **STIG Version**: Release 3 (15 May 2024)
- **Generated**: 2025-11-22

## Tool Priority

For BIND 9.x on UNIX/Linux systems:

1. **Bash** (.sh) - Primary automation tool
2. **Python** (.py) - Fallback/cross-platform option

## Quick Start

### Running Individual Checks

```bash
# Run bash version (primary)
bash BIND-9X-000001.sh

# Run python version (fallback)
python3 BIND-9X-000001.py

# With JSON output
bash BIND-9X-000001.sh --output-json results.json

# With configuration file
bash BIND-9X-000001.sh --config bind-config.json
```

### Running All Checks

```bash
# Create results directory
mkdir -p results

# Run all bash checks
for check in *.sh; do
    bash "$check" --output-json "results/${check%.sh}.json"
done

# Or run all python checks
for check in *.py; do
    python3 "$check" --output-json "results/${check%.py}.json"
done
```

## Exit Codes

- **0** = PASS (Compliant)
- **1** = FAIL (Finding)
- **2** = N/A (Not Applicable)
- **3** = ERROR (Check execution error)

## Tool Requirements

### Bash Checks (Primary)
- bash 4.0+
- Standard UNIX utilities (grep, sed, awk, cat, ps)
- BIND 9.x installed (named)
- Optional: jq (for config file parsing)

### Python Checks (Fallback)
- Python 3.6+
- Standard library only
- BIND 9.x installed (named)

## Configuration File Support

Checks support a `bind-config.json` file for environment-specific values.

Example:
```json
{
  "bind": {
    "config_file": "/etc/named.conf",
    "chroot_path": "/var/named/chroot",
    "zone_directory": "/var/named",
    "pid_file": "/var/run/named/named.pid"
  },
  "organization": {
    "name": "Your Organization",
    "contact": "security@example.com"
  }
}
```

## BIND Detection

The scripts automatically detect BIND installation using:
1. `named -v` (version detection)
2. `ps -ef | grep named` (process detection)
3. Common config file locations:
   - `/etc/named.conf`
   - `/etc/bind/named.conf`
   - `/var/named/chroot/etc/named.conf`
   - `/usr/local/etc/namedb/named.conf`

## Check Structure

Each check script includes:
- STIG metadata (Vuln ID, STIG ID, Severity)
- BIND configuration detection helpers
- Configuration file support (`--config`)
- JSON output support (`--output-json`)
- Help text (`--help`)
- Standardized exit codes

## Implementation Status

**Status**: Framework generated - implementation required

All checks are currently stubs with TODO comments. Full implementation requires:
1. BIND domain expertise
2. Access to BIND DNS systems for testing
3. Organization-specific configuration
4. Understanding of BIND named.conf directives and zone configurations

## Common BIND STIG Checks

These checks typically cover:
- Chroot environment configuration
- BIND version compliance
- Zone transfer restrictions
- Query access controls
- Logging and auditing
- DNSSEC configuration
- File and directory permissions
- Non-essential services on DNS server
- Recursion controls
- Transaction signatures (TSIG)

## Contributing

To implement a check:
1. Open the check script (BIND-9X-000001.sh or BIND-9X-000001.py)
2. Review STIG requirements in header
3. Implement check logic in TODO section
4. Test on actual BIND systems
5. Update documentation

## References

- [Official STIG Documentation](https://public.cyber.mil/stigs/)
- [BIND 9 Documentation](https://bind9.readthedocs.io/)
- [ISC BIND Download](https://www.isc.org/bind/)
- [STIG Viewer](https://www.stigviewer.com/)

## Directory Structure

```
bind_9.x/
├── README.md (this file)
├── BIND-9X-000001.sh (bash check - primary)
├── BIND-9X-000001.py (python check - fallback)
└── ... (70 checks total, 2 scripts each)
```

## Sample Checks

- **BIND-9X-000001**: Verify BIND running in chroot environment
- **BIND-9X-001000**: Verify BIND version is Current-Stable per ISC
- **BIND-9X-001002**: Verify only DNS processes running on server
- **BIND-9X-001003**: Verify separate DNS server roles (primary/secondary)
- **BIND-9X-001004**: Verify zone files not world-readable
- **BIND-9X-001005**: Verify DNSSEC enabled for hosted zones

---

**Generated**: 2025-11-22
**STIG Version**: Release 3 (15 May 2024)
**Total Checks**: 70
**Platform**: UNIX/Linux
**Tool Priority**: Bash (primary) > Python (fallback)
