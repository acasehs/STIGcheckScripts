# Example Check Outputs with Audit Evidence - Oracle Linux 8

This document shows example outputs from Oracle Linux 8 STIG checks, demonstrating the detailed audit evidence provided for both passing and failing scenarios.

**STIG Version**: Oracle Linux 8 Security Technical Implementation Guide v1r7
**Benchmark Date**: 26 Jul 2023

## Table of Contents
- [Example 1: FAIL - Package Not Installed](#example-1-fail---package-not-installed)
- [Example 2: PASS - Package Installed](#example-2-pass---package-installed)
- [Example 3: JSON Output Format](#example-3-json-output-format)
- [Example 4: Configuration File Usage](#example-4-configuration-file-usage)

---

## Example 1: FAIL - Package Not Installed

### Command
```bash
bash V-248519.sh
```

### Human-Readable Output

```
================================================================================
STIG Check: V-248519 - OL08-00-030180
STIG Version: Oracle Linux 8 v1r7
Severity: MEDIUM
================================================================================
Rule: The OL 8 audit package must be installed.
Status: Open
Timestamp: 2025-11-22T03:46:45Z
Requires Elevation: No
Third-Party Tools: None (uses yum/rpm)
Check Method: Bash - Native package manager query

--------------------------------------------------------------------------------
Finding Details:
--------------------------------------------------------------------------------

Package: audit
  Status: FAIL
  Reason: Required audit package is not installed

  What Was Checked:
    Audit package installation status
  Requirement:
    The audit package must be installed for security auditing

  Compliance Issues (1):

    Issue #1: Audit package not installed
      Evidence Found: Package 'audit' is not present on the system
      Expected: Package 'audit' must be installed
      Risk: Without the audit package, the system cannot perform security auditing, making it difficult to investigate security incidents and maintain compliance
      Remediation: Install the audit package using: sudo yum install audit

  Recommendation: Install the audit package immediately to enable security auditing

  Actual Configuration:
    - package_name: audit
    - installed: false
    - version: N/A
  Expected Configuration:
    - package_name: audit
    - installed: true
    - version: any

================================================================================

Exit Code: 1 (FAIL)
```

**Key Audit Evidence Elements:**
- ❌ **Compliance Issues**: Specific violation identified
- ❌ **Evidence Found**: Actual state of the system (package not present)
- ❌ **Expected**: Required configuration (package must be installed)
- ❌ **Risk**: Security impact of the misconfiguration
- ❌ **Remediation**: Exact command to fix the issue
- ❌ **Recommendation**: Overall guidance for achieving compliance

---

## Example 2: PASS - Package Installed

### Command
```bash
bash V-248519.sh
```

### Human-Readable Output

```
================================================================================
STIG Check: V-248519 - OL08-00-030180
STIG Version: Oracle Linux 8 v1r7
Severity: MEDIUM
================================================================================
Rule: The OL 8 audit package must be installed.
Status: NotAFinding
Timestamp: 2025-11-22T04:15:30Z
Requires Elevation: No
Third-Party Tools: None (uses yum/rpm)
Check Method: Bash - Native package manager query

--------------------------------------------------------------------------------
Finding Details:
--------------------------------------------------------------------------------

Package: audit
  Status: PASS
  Reason: Required audit package is installed

  What Was Checked:
    Audit package installation status
  Requirement:
    The audit package must be installed for security auditing

  Evidence Supporting PASS:
    ✓ Package 'audit' is installed
    ✓ Version: audit-3.0-0.17.20191104git1c2f876.el8.x86_64
    ✓ Verified using yum/rpm package manager

  Conclusion: System meets audit package installation requirements

  Actual Configuration:
    - package_name: audit
    - installed: true
    - version: audit-3.0-0.17.20191104git1c2f876.el8.x86_64
  Expected Configuration:
    - package_name: audit
    - installed: true
    - version: any

================================================================================

Exit Code: 0 (PASS)
```

**Key Audit Evidence Elements:**
- ✅ **What Was Checked**: Clear statement of what was examined
- ✅ **Requirement**: Explicit compliance requirement
- ✅ **Evidence**: Actual configuration values proving compliance
- ✅ **Conclusion**: Summary of why it passes
- ✅ **Actual vs Expected**: Side-by-side comparison

---

## Example 3: JSON Output Format

### Command
```bash
python3 V-248519.py --output-json results.json
```

### JSON Output (results.json) - FAIL Scenario

```json
{
  "vuln_id": "V-248519",
  "severity": "medium",
  "stig_id": "OL08-00-030180",
  "stig_version": "Oracle Linux 8 v1r7",
  "rule_title": "The OL 8 audit package must be installed.",
  "status": "Open",
  "finding_details": [
    {
      "package": "audit",
      "status": "FAIL",
      "reason": "Required audit package is not installed",
      "check_details": {
        "what_was_checked": "Audit package installation status",
        "requirement": "The audit package must be installed for security auditing",
        "actual_configuration": {
          "package_name": "audit",
          "installed": "false",
          "version": "N/A"
        },
        "expected_configuration": {
          "package_name": "audit",
          "installed": "true",
          "version": "any"
        }
      },
      "compliance_issues": [
        {
          "issue": "Audit package not installed",
          "evidence": "Package 'audit' is not present on the system",
          "expected": "Package 'audit' must be installed",
          "risk": "Without the audit package, the system cannot perform security auditing, making it difficult to investigate security incidents and maintain compliance",
          "remediation": "Install the audit package using: sudo yum install audit"
        }
      ],
      "recommendation": "Install the audit package immediately to enable security auditing"
    }
  ],
  "timestamp": "2025-11-22T03:46:45.544606Z",
  "requires_elevation": false,
  "third_party_tools": "None (uses Python stdlib)",
  "check_method": "Python - subprocess package manager query",
  "config_file": "None (using defaults)",
  "exit_code": 1
}
```

### JSON Output - PASS Scenario

```json
{
  "vuln_id": "V-248519",
  "severity": "medium",
  "stig_id": "OL08-00-030180",
  "stig_version": "Oracle Linux 8 v1r7",
  "rule_title": "The OL 8 audit package must be installed.",
  "status": "NotAFinding",
  "finding_details": [
    {
      "package": "audit",
      "status": "PASS",
      "reason": "Required audit package is installed",
      "check_details": {
        "what_was_checked": "Audit package installation status",
        "requirement": "The audit package must be installed for security auditing",
        "actual_configuration": {
          "package_name": "audit",
          "installed": "true",
          "version": "audit-3.0-0.17.20191104git1c2f876.el8.x86_64"
        },
        "expected_configuration": {
          "package_name": "audit",
          "installed": "true",
          "version": "any"
        }
      },
      "evidence": {
        "package_installed": "Package 'audit' is installed",
        "package_version": "Version: audit-3.0-0.17.20191104git1c2f876.el8.x86_64",
        "verification_method": "Verified using yum/rpm package manager",
        "conclusion": "System meets audit package installation requirements"
      }
    }
  ],
  "timestamp": "2025-11-22T04:15:30.123456Z",
  "requires_elevation": false,
  "third_party_tools": "None (uses Python stdlib)",
  "check_method": "Python - subprocess package manager query",
  "config_file": "None (using defaults)",
  "exit_code": 0
}
```

---

## Example 4: Configuration File Usage

### Command
```bash
bash V-248519.sh --config stig-config.json --output-json results-with-config.json
```

### Output (with configuration file)

```
INFO: Loaded configuration from stig-config.json
  - Required package: audit (verified in config)

================================================================================
STIG Check: V-248519 - OL08-00-030180
STIG Version: Oracle Linux 8 v1r7
Severity: MEDIUM
================================================================================
Rule: The OL 8 audit package must be installed.
Status: NotAFinding
Timestamp: 2025-11-22T04:20:15Z
Requires Elevation: No
Third-Party Tools: None (uses yum/rpm)
Check Method: Bash - Native package manager query

[... rest of output ...]
```

**JSON Output Snippet:**
```json
{
  "vuln_id": "V-248519",
  "config_file": "/path/to/stig-config.json",
  "finding_details": [
    {
      "package": "audit",
      "status": "PASS",
      "reason": "Required audit package is installed (verified against config)"
    }
  ]
}
```

---

## Audit Evidence Fields Explained

### For PASSING Checks

| Field | Purpose | Example |
|-------|---------|---------|
| `what_was_checked` | Configuration examined | "Audit package installation status" |
| `requirement` | STIG compliance requirement | "The audit package must be installed" |
| `evidence` | Proof of compliance | {"package_installed": "Package 'audit' is installed"} |
| `actual_configuration` | Current system values | {"installed": "true", "version": "audit-3.0-0.17..."} |
| `expected_configuration` | Required values | {"installed": "true", "version": "any"} |
| `conclusion` | Summary statement | "System meets audit package installation requirements" |

### For FAILING Checks

| Field | Purpose | Example |
|-------|---------|---------|
| `what_was_checked` | Configuration examined | "Audit package installation status" |
| `requirement` | STIG compliance requirement | "The audit package must be installed" |
| `compliance_issues` | List of violations | [{"issue": "Audit package not installed", ...}] |
| `issue` | Name of the violation | "Audit package not installed" |
| `evidence` | Proof of violation | "Package 'audit' is not present on the system" |
| `expected` | Required configuration | "Package 'audit' must be installed" |
| `risk` | Security risk explanation | "Without audit package, cannot perform security auditing..." |
| `remediation` | How to fix | "Install using: sudo yum install audit" |
| `actual_configuration` | Current (non-compliant) values | {"installed": "false", "version": "N/A"} |
| `expected_configuration` | Required compliant values | {"installed": "true", "version": "any"} |
| `recommendation` | Overall guidance | "Install the audit package immediately..." |

---

## Using Results for Auditing

### Compliance Reporting

```bash
# Run all checks and collect results
for check in samples/V-*.sh; do
    bash "$check" \
        --config stig-config.json \
        --output-json "results/$(basename ${check%.sh}).json"
done

# Generate compliance summary
python3 generate_compliance_report.py results/
```

### Evidence Collection

The JSON output provides complete audit trail:
- **When**: `timestamp` field
- **What**: `what_was_checked` and `requirement` fields
- **How**: `check_method` field
- **Result**: `status` field (NotAFinding/Open)
- **Why**: `evidence` or `compliance_issues` fields
- **Config**: `config_file` field (which policy was used)
- **Version**: `stig_version` field (STIG version/release)

### Remediation Tracking

For failing checks, use the `remediation` fields:
```bash
# Extract all remediation actions
jq '.finding_details[].compliance_issues[]?.remediation' results/*.json \
    | sort -u > remediation_actions.txt
```

### Trend Analysis

Track compliance over time:
```bash
# Run weekly
./run_all_checks.sh > weekly_results_$(date +%Y%m%d).json

# Compare to previous week
diff <(jq '.status' weekly_results_20251115.json) \
     <(jq '.status' weekly_results_20251122.json)
```

### Generating Reports for Auditors

```bash
# Extract key information for audit report
jq '{
  vuln_id: .vuln_id,
  stig_version: .stig_version,
  status: .status,
  timestamp: .timestamp,
  evidence: .finding_details[].evidence // .finding_details[].compliance_issues
}' results/*.json > audit_report.json
```

---

## Exit Codes

All checks return standardized exit codes:

| Exit Code | Status | Meaning | Use Case |
|-----------|--------|---------|----------|
| 0 | PASS | All requirements met | Compliance achieved |
| 1 | FAIL | One or more violations found | Remediation required |
| 2 | N/A | Not applicable or manual review needed | Document exception |
| 3 | ERROR | Check execution failed | Troubleshoot check |

### Automation Examples

```bash
# Simple pass/fail check
bash V-248519.sh
if [ $? -eq 0 ]; then
    echo "COMPLIANT"
else
    echo "NON-COMPLIANT - Review findings"
fi

# Detailed error handling
bash V-248519.sh
exit_code=$?
case $exit_code in
    0) echo "✓ PASS: No findings" ;;
    1) echo "✗ FAIL: Compliance issues detected" ;;
    2) echo "⚠ N/A: Manual review required" ;;
    3) echo "⨯ ERROR: Check execution failed" ;;
esac
```

---

## Best Practices for Auditors

1. **Always Use JSON Output**: Structured data for reports
   ```bash
   --output-json results.json
   ```

2. **Archive Results**: Keep historical compliance data
   ```bash
   mkdir -p /audit/stig-results/ol8-v1r7/$(date +%Y-%m)
   ```

3. **Verify STIG Version**: Document which STIG version was used
   ```bash
   jq '.stig_version' results.json
   ```

4. **Review Evidence**: Don't just check pass/fail, review evidence
   ```bash
   jq '.finding_details[].evidence' results.json
   ```

5. **Track Remediation**: Monitor fixing of compliance issues
   ```bash
   jq '.finding_details[].compliance_issues[].remediation' results.json
   ```

6. **Document Exceptions**: For N/A results, document why
   ```bash
   # Add to exception log
   echo "V-248519: N/A - System uses alternative auditing solution, exception granted until Q2 2026"
   ```

7. **Verify Configuration**: Ensure correct config file is used
   ```bash
   jq '.config_file' results.json
   ```

---

## Support

For questions about output format or audit evidence:
1. Review this document
2. Check `README.md` for general usage
3. Check `CONFIG-GUIDE.md` for configuration help
4. Run checks with `--output-json` for structured data
5. Review Oracle Linux 8 STIG v1r7 documentation

---

## Additional Examples

### Example: Multiple Check Execution

```bash
#!/bin/bash
# run_all_ol8_checks.sh

CONFIG_FILE="stig-config.json"
RESULTS_DIR="results/$(date +%Y%m%d_%H%M%S)"

mkdir -p "$RESULTS_DIR"

# Run all checks
for check in samples/V-*.sh; do
    vuln_id=$(basename "$check" .sh)
    bash "$check" \
        --config "$CONFIG_FILE" \
        --output-json "$RESULTS_DIR/${vuln_id}.json"

    exit_code=$?
    case $exit_code in
        0) status="PASS" ;;
        1) status="FAIL" ;;
        2) status="N/A" ;;
        3) status="ERROR" ;;
    esac

    echo "$vuln_id: $status"
done

# Generate summary
echo ""
echo "=== Summary ==="
echo "PASS:  $(grep -l '\"exit_code\": 0' $RESULTS_DIR/*.json | wc -l)"
echo "FAIL:  $(grep -l '\"exit_code\": 1' $RESULTS_DIR/*.json | wc -l)"
echo "N/A:   $(grep -l '\"exit_code\": 2' $RESULTS_DIR/*.json | wc -l)"
echo "ERROR: $(grep -l '\"exit_code\": 3' $RESULTS_DIR/*.json | wc -l)"
```

### Example: OpenSCAP Integration

```bash
# Generate XCCDF results from JSON checks
python3 convert_json_to_xccdf.py \
    --input results/ \
    --output stig_results.xml \
    --stig-version "Oracle Linux 8 v1r7"

# View in SCAP Workbench
scap-workbench stig_results.xml
```

---

## Version History

| Version | Date | Changes | STIG Version |
|---------|------|---------|--------------|
| 1.0 | 2025-11-22 | Initial example outputs for OL8 | v1r7 |

