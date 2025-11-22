# Oracle Database 19c v1r2 - STIG Automation Framework

## Overview

Automated STIG compliance checks for **Oracle Database 19c Version 1 Release 2**.

- **Total Checks**: 96
- **Category**: database
- **STIG Version**: v1r2
- **Generated**: 2025-11-22

## Quick Start

### Running Individual Checks

```bash
# Run bash version (primary)
bash V-270495.sh

# Run python version (fallback)
python3 V-270495.py

# With JSON output
bash V-270495.sh --output-json results.json

# With configuration file
bash V-270495.sh --config stig-config.json
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
1. Domain expertise for Oracle Database 19c
2. Access to target systems for testing
3. Organization-specific configuration

## Contributing

To implement a check:
1. Open the check script (V-270495.sh or V-270495.py)
2. Review STIG requirements in header
3. Implement check logic in TODO section
4. Test on actual systems
5. Update documentation

## References

- [Official STIG Documentation](https://public.cyber.mil/stigs/)
- [STIG Viewer](https://www.stigviewer.com/)

## Directory Structure

```
oracle_database_19c_v1r2/
├── README.md (this file)
├── V-270495.sh (bash check)
├── V-270495.py (python check)
└── ... (96 checks total)
```

---

**Generated**: 2025-11-22
**STIG Version**: v1r2
**Total Checks**: 96
