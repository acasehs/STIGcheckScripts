# Example Check Outputs with Audit Evidence

This document shows example outputs from STIG checks, demonstrating the detailed audit evidence provided for both passing and failing scenarios.

## Table of Contents
- [Example 1: PASS - Compliant Configuration](#example-1-pass---compliant-configuration)
- [Example 2: FAIL - Multiple Issues](#example-2-fail---multiple-issues)
- [Example 3: JSON Output Format](#example-3-json-output-format)

---

## Example 1: PASS - Compliant Configuration

### Command
```bash
python3 V-235928.py \
  --domain-home /u01/oracle/user_projects/domains/base_domain \
  --config stig-config.json
```

### Human-Readable Output

```
================================================================================
STIG Check: V-235928 - WBLC-01-000009
Severity: MEDIUM
================================================================================
Rule: Oracle WebLogic must utilize cryptography to protect the confidentiality
      of remote access management sessions.
Status: NotAFinding
Timestamp: 2025-11-22T05:30:15Z
Requires Elevation: True
Third-Party Tools: None (uses Python stdlib)
Check Method: Python - Direct config.xml parsing

--------------------------------------------------------------------------------
Finding Details:
--------------------------------------------------------------------------------

Server: AdminServer
  Status: PASS
  Reason: SSL enabled and properly configured, non-SSL port disabled

  What Was Checked:
    SSL/TLS configuration for server
  Requirement:
    SSL must be enabled AND non-SSL listen port must be disabled

  Evidence Supporting PASS:
    ✓ SSL is enabled (ssl.enabled = true)
    ✓ SSL port configured: 7002
    ✓ Non-SSL port disabled (listen-port-enabled = false)

  Conclusion: Server meets cryptographic protection requirements

  Actual Configuration:
    - listen_port_enabled: false
    - ssl_enabled: true
    - ssl_port: 7002
  Expected Configuration:
    - listen_port_enabled: false
    - ssl_enabled: true
    - ssl_port: Valid port number (e.g., 7002, 9002)

Server: ManagedServer1
  Status: PASS
  Reason: SSL enabled and properly configured, non-SSL port disabled

  What Was Checked:
    SSL/TLS configuration for server
  Requirement:
    SSL must be enabled AND non-SSL listen port must be disabled

  Evidence Supporting PASS:
    ✓ SSL is enabled (ssl.enabled = true)
    ✓ SSL port configured: 9002
    ✓ Non-SSL port disabled (listen-port-enabled = false)

  Conclusion: Server meets cryptographic protection requirements

  Actual Configuration:
    - listen_port_enabled: false
    - ssl_enabled: true
    - ssl_port: 9002
  Expected Configuration:
    - listen_port_enabled: false
    - ssl_enabled: true
    - ssl_port: Valid port number (e.g., 7002, 9002)

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

## Example 2: FAIL - Multiple Issues

### Command
```bash
python3 V-235928.py \
  --domain-home /u01/oracle/user_projects/domains/legacy_domain \
  --config stig-config.json
```

### Human-Readable Output

```
================================================================================
STIG Check: V-235928 - WBLC-01-000009
Severity: MEDIUM
================================================================================
Rule: Oracle WebLogic must utilize cryptography to protect the confidentiality
      of remote access management sessions.
Status: Open
Timestamp: 2025-11-22T05:35:42Z
Requires Elevation: True
Third-Party Tools: None (uses Python stdlib)
Check Method: Python - Direct config.xml parsing

--------------------------------------------------------------------------------
Finding Details:
--------------------------------------------------------------------------------

Server: AdminServer
  Status: FAIL
  Reason: Found 2 compliance issue(s)

  What Was Checked:
    SSL/TLS configuration for server
  Requirement:
    SSL must be enabled AND non-SSL listen port must be disabled

  Compliance Issues (2):

    Issue #1: Non-SSL listen port is enabled
      Evidence Found: listen-port-enabled = true
      Expected: listen-port-enabled = false
      Risk: Allows unencrypted administrative connections
      Remediation: Disable non-SSL listen port in WebLogic config

    Issue #2: SSL is not enabled for this server
      Evidence Found: SSL enabled = false
      Expected: SSL enabled = true
      Risk: Server cannot accept encrypted connections
      Remediation: Enable SSL and configure keystore/truststore

  Recommendation: Configure SSL properly and disable non-SSL listen port

  Actual Configuration:
    - listen_port_enabled: true
    - ssl_enabled: false
    - ssl_port: N/A
  Expected Configuration:
    - listen_port_enabled: false
    - ssl_enabled: true
    - ssl_port: Valid port number (e.g., 7002, 9002)

Server: ManagedServer1
  Status: FAIL
  Reason: Found 1 compliance issue(s)

  What Was Checked:
    SSL/TLS configuration for server
  Requirement:
    SSL must be enabled AND non-SSL listen port must be disabled

  Compliance Issues (1):

    Issue #1: Non-SSL listen port is enabled
      Evidence Found: listen-port-enabled = true
      Expected: listen-port-enabled = false
      Risk: Allows unencrypted administrative connections
      Remediation: Disable non-SSL listen port in WebLogic config

  Recommendation: Configure SSL properly and disable non-SSL listen port

  Actual Configuration:
    - listen_port_enabled: true
    - ssl_enabled: true
    - ssl_port: 9002
  Expected Configuration:
    - listen_port_enabled: false
    - ssl_enabled: true
    - ssl_port: Valid port number (e.g., 7002, 9002)

================================================================================

Exit Code: 1 (FAIL)
```

**Key Audit Evidence Elements:**
- ❌ **Compliance Issues**: Numbered list of specific violations
- ❌ **Evidence Found**: Actual values that violate requirements
- ❌ **Expected**: What should be configured
- ❌ **Risk**: Security risk of the misconfiguration
- ❌ **Remediation**: Specific steps to fix the issue
- ❌ **Recommendation**: Overall guidance for compliance

---

## Example 3: JSON Output Format

### Command
```bash
python3 V-235928.py \
  --domain-home /u01/oracle/user_projects/domains/base_domain \
  --config stig-config.json \
  --output-json results.json
```

### JSON Output (results.json)

```json
{
  "vuln_id": "V-235928",
  "severity": "medium",
  "stig_id": "WBLC-01-000009",
  "rule_title": "Oracle WebLogic must utilize cryptography to protect the confidentiality of remote access management sessions.",
  "status": "NotAFinding",
  "finding_details": [
    {
      "server": "AdminServer",
      "listen_port_enabled": false,
      "ssl_enabled": true,
      "ssl_port": "7002",
      "check_details": {
        "what_was_checked": "SSL/TLS configuration for server",
        "requirement": "SSL must be enabled AND non-SSL listen port must be disabled",
        "actual_configuration": {
          "listen_port_enabled": "false",
          "ssl_enabled": "true",
          "ssl_port": "7002"
        },
        "expected_configuration": {
          "listen_port_enabled": "false",
          "ssl_enabled": "true",
          "ssl_port": "Valid port number (e.g., 7002, 9002)"
        }
      },
      "status": "PASS",
      "reason": "SSL enabled and properly configured, non-SSL port disabled",
      "evidence": {
        "ssl_enabled": "SSL is enabled (ssl.enabled = true)",
        "ssl_port": "SSL port configured: 7002",
        "non_ssl_disabled": "Non-SSL port disabled (listen-port-enabled = false)",
        "conclusion": "Server meets cryptographic protection requirements"
      }
    },
    {
      "server": "ManagedServer1",
      "listen_port_enabled": false,
      "ssl_enabled": true,
      "ssl_port": "9002",
      "check_details": {
        "what_was_checked": "SSL/TLS configuration for server",
        "requirement": "SSL must be enabled AND non-SSL listen port must be disabled",
        "actual_configuration": {
          "listen_port_enabled": "false",
          "ssl_enabled": "true",
          "ssl_port": "9002"
        },
        "expected_configuration": {
          "listen_port_enabled": "false",
          "ssl_enabled": "true",
          "ssl_port": "Valid port number (e.g., 7002, 9002)"
        }
      },
      "status": "PASS",
      "reason": "SSL enabled and properly configured, non-SSL port disabled",
      "evidence": {
        "ssl_enabled": "SSL is enabled (ssl.enabled = true)",
        "ssl_port": "SSL port configured: 9002",
        "non_ssl_disabled": "Non-SSL port disabled (listen-port-enabled = false)",
        "conclusion": "Server meets cryptographic protection requirements"
      }
    }
  ],
  "timestamp": "2025-11-22T05:30:15Z",
  "requires_elevation": true,
  "third_party_tools": "None (uses Python stdlib)",
  "check_method": "Python - Direct config.xml parsing",
  "config_file": "/path/to/stig-config.json",
  "exit_code": 0
}
```

### JSON Output (FAIL scenario)

```json
{
  "vuln_id": "V-235928",
  "severity": "medium",
  "stig_id": "WBLC-01-000009",
  "rule_title": "Oracle WebLogic must utilize cryptography to protect the confidentiality of remote access management sessions.",
  "status": "Open",
  "finding_details": [
    {
      "server": "AdminServer",
      "listen_port_enabled": true,
      "ssl_enabled": false,
      "ssl_port": "N/A",
      "check_details": {
        "what_was_checked": "SSL/TLS configuration for server",
        "requirement": "SSL must be enabled AND non-SSL listen port must be disabled",
        "actual_configuration": {
          "listen_port_enabled": "true",
          "ssl_enabled": "false",
          "ssl_port": "N/A"
        },
        "expected_configuration": {
          "listen_port_enabled": "false",
          "ssl_enabled": "true",
          "ssl_port": "Valid port number (e.g., 7002, 9002)"
        }
      },
      "status": "FAIL",
      "reason": "Found 2 compliance issue(s)",
      "compliance_issues": [
        {
          "issue": "Non-SSL listen port is enabled",
          "evidence": "listen-port-enabled = true",
          "expected": "listen-port-enabled = false",
          "risk": "Allows unencrypted administrative connections",
          "remediation": "Disable non-SSL listen port in WebLogic config"
        },
        {
          "issue": "SSL is not enabled for this server",
          "evidence": "SSL enabled = false",
          "expected": "SSL enabled = true",
          "risk": "Server cannot accept encrypted connections",
          "remediation": "Enable SSL and configure keystore/truststore"
        }
      ],
      "recommendation": "Configure SSL properly and disable non-SSL listen port"
    }
  ],
  "timestamp": "2025-11-22T05:35:42Z",
  "requires_elevation": true,
  "third_party_tools": "None (uses Python stdlib)",
  "check_method": "Python - Direct config.xml parsing",
  "config_file": "/path/to/stig-config.json",
  "exit_code": 1
}
```

---

## Audit Evidence Fields Explained

### For PASSING Checks

| Field | Purpose | Example |
|-------|---------|---------|
| `what_was_checked` | What configuration was examined | "SSL/TLS configuration for server" |
| `requirement` | STIG compliance requirement | "SSL must be enabled AND non-SSL port disabled" |
| `evidence` | Proof that requirements are met | {"ssl_enabled": "SSL is enabled..."} |
| `actual_configuration` | Current system values | {"ssl_enabled": "true"} |
| `expected_configuration` | Required values | {"ssl_enabled": "true"} |
| `conclusion` | Summary statement | "Server meets cryptographic protection requirements" |

### For FAILING Checks

| Field | Purpose | Example |
|-------|---------|---------|
| `what_was_checked` | What configuration was examined | "SSL/TLS configuration for server" |
| `requirement` | STIG compliance requirement | "SSL must be enabled AND non-SSL port disabled" |
| `compliance_issues` | List of specific violations | [{"issue": "SSL not enabled", ...}] |
| `issue` | Name of the violation | "Non-SSL listen port is enabled" |
| `evidence` | Proof of the violation | "listen-port-enabled = true" |
| `expected` | What should be configured | "listen-port-enabled = false" |
| `risk` | Security risk explanation | "Allows unencrypted admin connections" |
| `remediation` | How to fix the issue | "Disable non-SSL listen port in WebLogic config" |
| `actual_configuration` | Current (non-compliant) values | {"ssl_enabled": "false"} |
| `expected_configuration` | Required compliant values | {"ssl_enabled": "true"} |
| `recommendation` | Overall guidance | "Configure SSL properly..." |

---

## Using Results for Auditing

### Compliance Reporting

```bash
# Run all checks and collect results
for check in V-*.py; do
    python3 "$check" \
        --domain-home /path/to/domain \
        --config stig-config.json \
        --output-json "results/${check%.py}.json"
done

# Generate compliance summary
python3 generate_compliance_report.py results/
```

### Evidence Collection

The JSON output provides complete audit trail:
- **When**: `timestamp` field
- **What**: `what_was_checked` and `requirement` fields
- **How**: `check_method` field
- **Result**: `status` field (Pass/Fail)
- **Why**: `evidence` or `compliance_issues` fields
- **Config**: `config_file` field (which policy was used)

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
python3 V-235928.py --domain-home /path --config config.json
if [ $? -eq 0 ]; then
    echo "COMPLIANT"
else
    echo "NON-COMPLIANT - Review findings"
fi

# Detailed error handling
python3 V-235928.py --domain-home /path --config config.json
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
   mkdir -p /audit/stig-results/$(date +%Y-%m)
   ```

3. **Verify Config File**: Document which policy was used
   ```bash
   jq '.config_file' results.json
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
   echo "V-235928: N/A - Legacy system, exception granted until Q2 2026"
   ```

---

## Support

For questions about output format or audit evidence:
1. Review this document
2. Check `README.md` for general usage
3. Check `CONFIG-GUIDE.md` for configuration help
4. Run checks with `--output-json` for structured data
