# Red Hat Enterprise Linux 9 v2r5 - STIG Automation Framework

## Overview

Automated STIG compliance checks for **Red Hat Enterprise Linux 9 Version 2 Release 5**.

- **Total Checks**: 450
- **Category**: os
- **STIG Version**: v2r5
- **Generated**: 2025-11-22

## Quick Start

### Running Individual Checks

```bash
# Run bash version (primary)
bash V-257777.sh

# Run python version (fallback)
python3 V-257777.py

# With JSON output
bash V-257777.sh --output-json results.json

# With configuration file
bash V-257777.sh --config stig-config.json
```

### Running All Checks

```bash
# Create results directory
mkdir -p results

# Run all bash checks
for check in *.sh; do
    bash "$check" --output-json "results/${check%.sh}.json"
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
- Standard UNIX utilities (grep, sed, awk)
- Optional: jq (for config file parsing)

### Python Checks (Fallback)
- Python 3.6+
- Standard library only

## Configuration File Support

Checks support a `stig-config.json` file for environment-specific values.

Example:
```json
{
  "organization": {
    "name": "Your Organization",
    "contact": "security@example.com"
  }
}
```

## Tool Priority

Following STIG automation best practices:
1. **bash** (1st priority for Linux/UNIX)
2. **python** (2nd priority - fallback)
3. third-party tools (avoided when possible)

## Check Structure

Each check script includes:
- STIG metadata (Vuln ID, STIG ID, Severity)
- Configuration file support (`--config`)
- JSON output support (`--output-json`)
- Help text (`--help`)
- Standardized exit codes

## Implementation Status

**Status**: Framework generated - implementation required

All checks are currently stubs with TODO comments. Full implementation requires:
1. Domain expertise for Red Hat Enterprise Linux 9
2. Access to target systems for testing
3. Organization-specific configuration

## Contributing

To implement a check:
1. Open the check script (V-257777.sh or V-257777.py)
2. Review STIG requirements in header
3. Implement check logic in TODO section
4. Test on actual systems
5. Update documentation

## References

- [Official STIG Documentation](https://public.cyber.mil/stigs/)
- [STIG Viewer](https://www.stigviewer.com/)

## Directory Structure

```
rhel_9_v2r5/
├── README.md (this file)
├── V-257777.sh (bash check)
├── V-257777.py (python check)
└── ... (450 checks total)
```

---

**Generated**: 2025-11-22
**STIG Version**: v2r5
**Total Checks**: 450
