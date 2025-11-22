# Apache 2.4 UNIX Server v2r6 - STIG Automation Framework

## Overview

Automated STIG compliance checks for **Apache 2.4 UNIX Server Version 2 Release 6**.

- **Total Checks**: 47
- **Platform**: UNIX/Linux
- **STIG Version**: v2r6
- **Generated**: 2025-11-22

## Tool Priority

For Apache on UNIX/Linux systems:

1. **Bash** (.sh) - Primary automation tool
2. **Python** (.py) - Fallback/cross-platform option

## Quick Start

### Running Individual Checks

```bash
# Run bash version (primary)
bash V-214228.sh

# Run python version (fallback)
python3 V-214228.py

# With JSON output
bash V-214228.sh --output-json results.json

# With configuration file
bash V-214228.sh --config apache-config.json
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
- Standard UNIX utilities (grep, sed, awk, cat)
- Apache httpd installed (apachectl, apache2ctl, or httpd)
- Optional: jq (for config file parsing)

### Python Checks (Fallback)
- Python 3.6+
- Standard library only
- Apache httpd installed

## Configuration File Support

Checks support an `apache-config.json` file for environment-specific values.

Example:
```json
{
  "apache": {
    "httpd_root": "/etc/httpd",
    "config_file": "/etc/httpd/conf/httpd.conf",
    "modules_dir": "/etc/httpd/modules"
  },
  "organization": {
    "name": "Your Organization",
    "contact": "security@example.com"
  }
}
```

## Apache Detection

The scripts automatically detect Apache installation using:
1. `apachectl -V` (preferred)
2. `apache2ctl -V` (Debian/Ubuntu)
3. `httpd -V` (direct binary)

## Check Structure

Each check script includes:
- STIG metadata (Vuln ID, STIG ID, Severity)
- Apache configuration detection helpers
- Configuration file support (`--config`)
- JSON output support (`--output-json`)
- Help text (`--help`)
- Standardized exit codes

## Implementation Status

**Status**: Framework generated - implementation required

All checks are currently stubs with TODO comments. Full implementation requires:
1. Apache domain expertise
2. Access to Apache systems for testing
3. Organization-specific configuration
4. Understanding of Apache directives and modules

## Common Apache STIG Checks

These checks typically cover:
- Session management (KeepAlive, MaxKeepAliveRequests)
- TLS/SSL configuration
- Directory permissions and access controls
- Logging and auditing
- Module security
- Error handling and disclosure
- CGI/Script execution controls

## Contributing

To implement a check:
1. Open the check script (V-214228.sh or V-214228.py)
2. Review STIG requirements in header
3. Implement check logic in TODO section
4. Test on actual Apache systems
5. Update documentation

## References

- [Official STIG Documentation](https://public.cyber.mil/stigs/)
- [Apache HTTP Server Documentation](https://httpd.apache.org/docs/)
- [STIG Viewer](https://www.stigviewer.com/)

## Directory Structure

```
apache_2.4_unix_server_v2r6/
├── README.md (this file)
├── V-214228.sh (bash check - primary)
├── V-214228.py (python check - fallback)
└── ... (47 checks total)
```

---

**Generated**: 2025-11-22
**STIG Version**: v2r6
**Total Checks**: 47
**Platform**: UNIX/Linux
**Tool Priority**: Bash (primary) > Python (fallback)
