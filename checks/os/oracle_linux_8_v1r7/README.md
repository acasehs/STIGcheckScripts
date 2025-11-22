# Oracle Linux 8 STIG Automated Checks - v1r7

## Overview

Automated STIG compliance checks for Oracle Linux 8, implementing the Security Technical Implementation Guide (STIG) Version 1, Release 7 requirements. This framework provides comprehensive, evidence-based security configuration validation with support for environment-specific requirements.

**STIG Information:**
- **Version**: v1r7
- **Benchmark Date**: 26 Jul 2023
- **Total Checks**: 1003
- **Automatable**: 931 (92.8%)

## Key Features

✅ **Native Tools Priority**: Bash → Python → Third-Party (minimizes dependencies)
✅ **Configuration File Support**: Environment-specific values in JSON
✅ **Detailed Audit Evidence**: Complete pass/fail justification
✅ **Multiple Output Formats**: JSON, human-readable, exit codes
✅ **High Automation Rate**: 92.8% of checks can be automated
✅ **Low Third-Party Dependency**: Only 1.2% require third-party tools

## Automation Statistics

| Metric | Count | Percentage |
|--------|-------|------------|
| Fully Automated | 675 | 67.3% |
| Potentially Automated | 256 | 25.5% |
| Manual Review Required | 72 | 7.2% |
| Environment-Specific | 54 | 5.4% |
| Requires Third-Party Tools | 12 | 1.2% |
| **Total Automatable** | **931** | **92.8%** |

### Severity Distribution

| Severity | Count | Percentage |
|----------|-------|------------|
| HIGH | 62 | 6.2% |
| MEDIUM | 860 | 85.7% |
| LOW | 81 | 8.1% |

## Quick Start

### Prerequisites

**Required:**
- Oracle Linux 8.x
- Bash 4.0+ or Python 3.6+

**Optional (Enhanced Features):**
- `jq` - JSON parsing for bash scripts
- Root/sudo access - Some checks require elevated privileges

**Installation:**
```bash
# Install optional tools
sudo yum install jq

# Clone repository
git clone <repository-url>
cd checks/os/oracle_linux_8_v1r7
```

### Basic Usage

#### Run a Single Check (Default Values)

```bash
# Bash (preferred)
bash samples/V-248519.sh

# Python (fallback)
python3 samples/V-248519.py
```

#### Run with Configuration File (Environment-Specific Values)

```bash
# Copy and customize config file
cp stig-config.json my-config.json
vi my-config.json

# Run with custom config
bash samples/V-248519.sh --config my-config.json

# With JSON output
bash samples/V-248519.sh --config my-config.json --output-json results.json
```

#### Run All Checks

```bash
# Create results directory
mkdir -p results/$(date +%Y%m%d)

# Run all sample checks
for check in samples/V-*.sh; do
    vuln_id=$(basename "$check" .sh)
    bash "$check" \
        --config stig-config.json \
        --output-json "results/$(date +%Y%m%d)/${vuln_id}.json"
    echo "$vuln_id: exit code $?"
done
```

## Configuration File Pattern

### Why Configuration Files?

**54 checks (5.4%)** are environment-specific, requiring values like:
- Authorized user lists
- Approved firewall ports/services
- Organizational cipher suites
- Site-defined security settings
- Custom audit requirements

Without configuration files, these checks would require **manual validation** or **hardcoded values**.

### Configuration File Format

Create `stig-config.json` with your environment-specific values:

```json
{
  "organization": {
    "name": "Your Organization",
    "environment": "Production"
  },
  "operating_system": {
    "authorized_users": {
      "values": ["oracle", "admin", "appuser"]
    },
    "privileged_users": {
      "values": ["oracle", "admin"]
    },
    "firewall_settings": {
      "approved_services": {
        "values": ["ssh", "https"]
      },
      "approved_ports": {
        "values": [22, 443]
      }
    },
    "ssh_settings": {
      "approved_ciphers": {
        "values": ["aes256-ctr", "aes192-ctr", "aes128-ctr"]
      }
    }
  }
}
```

**See [`CONFIG-GUIDE.md`](CONFIG-GUIDE.md) for detailed customization instructions.**

## Tool Requirements

### Native Tools (Bash - Preferred)

**Package Management:**
- `yum`, `dnf`, `rpm` - Package queries and management

**System Services:**
- `systemctl` - Service status and management
- `getenforce`, `sestatus`, `getsebool` - SELinux queries
- `firewall-cmd`, `iptables` - Firewall configuration

**Audit:**
- `auditctl`, `aureport`, `ausearch` - Audit subsystem

**User Management:**
- `getent`, `passwd`, `lastlog` - User and group queries

**System Configuration:**
- `sysctl` - Kernel parameter queries
- `openssl`, `update-crypto-policies` - Cryptographic configuration
- `sshd` - SSH configuration validation

**File System:**
- `find`, `ls`, `stat`, `chmod`, `chown` - File operations
- `grep`, `cat`, `awk`, `sed` - Text processing

**Networking:**
- `ip`, `ss`, `netstat` - Network configuration

**Logging:**
- `journalctl`, `rsyslog` - System logging

### Fallback (Python 3.6+)

**Standard Library Only:**
- `subprocess` - Execute system commands
- `os`, `pathlib` - File system operations
- `json` - Configuration file parsing
- `re` - Regular expressions

### Third-Party Tools (When Required - 1.2% of checks)

- `aide` - File integrity monitoring
- `usbguard` - USB device authorization

## Exit Codes

All checks return standardized exit codes:

| Exit Code | Status | Meaning | Action Required |
|-----------|--------|---------|-----------------|
| 0 | PASS | All requirements met | None - Compliant |
| 1 | FAIL | One or more violations found | Remediation required |
| 2 | N/A | Not applicable or manual review needed | Document exception |
| 3 | ERROR | Check execution failed | Troubleshoot check |

### Automation Example

```bash
#!/bin/bash
# Automated compliance checking with error handling

bash samples/V-248519.sh --config stig-config.json
exit_code=$?

case $exit_code in
    0)
        echo "✓ PASS: System is compliant"
        # Continue with other checks
        ;;
    1)
        echo "✗ FAIL: Compliance issues detected"
        # Log for remediation
        logger -t STIG "V-248519 failed - remediation required"
        ;;
    2)
        echo "⚠ N/A: Manual review required"
        # Document exception
        ;;
    3)
        echo "⨯ ERROR: Check execution failed"
        # Alert administrator
        ;;
esac
```

## Check Types and Examples

### Package Installation Checks

**Example**: V-248519 - Audit package must be installed

```bash
bash samples/V-248519.sh --config stig-config.json
```

**What it checks:**
- Package presence using `yum list installed` or `rpm -q`
- Package version information

**Audit evidence provided:**
- PASS: Package name, version, verification method
- FAIL: Missing package, security risk, remediation command

### Service Status Checks

**Example**: V-248520 - Auditd service must be running

```bash
bash samples/V-248520.sh --config stig-config.json
```

**What it checks:**
- Service active status using `systemctl status`
- Service enabled at boot

**Audit evidence provided:**
- PASS: Service status, enabled state
- FAIL: Service not running, remediation steps

### Configuration File Checks

**What they check:**
- SSH configuration (`/etc/ssh/sshd_config`)
- Audit configuration (`/etc/audit/auditd.conf`)
- System limits (`/etc/security/limits.conf`)
- Kernel parameters (`/etc/sysctl.conf`)

**Audit evidence provided:**
- PASS: Current setting, compliance confirmation
- FAIL: Current vs. required setting, risk, fix command

### User and Account Checks

**What they check:**
- Authorized user lists
- Password policy settings
- Account lockout configuration
- Privilege escalation (sudo)

**Audit evidence provided:**
- PASS: User list, policy settings
- FAIL: Unauthorized users, weak policy, remediation

### Firewall Checks

**What they check:**
- Firewall enabled status
- Approved services and ports
- Default deny policy

**Audit evidence provided:**
- PASS: Firewall status, approved rules
- FAIL: Firewall disabled, unauthorized ports, fix steps

### SELinux Checks

**What they check:**
- SELinux mode (Enforcing/Permissive/Disabled)
- SELinux policy type
- Boolean settings

**Audit evidence provided:**
- PASS: Current mode and policy
- FAIL: Incorrect mode, remediation (may require reboot)

## Environment-Specific Checks

**54 checks (5.4%)** require environment-specific configuration:

### Categories:

1. **Approved Protocols/Ports** (Firewall)
   - Organization-defined approved services
   - Documented approved ports

2. **Authorized Users** (User Management)
   - Organization-defined user lists
   - Privileged user identification

3. **Cipher Suites** (SSH/Crypto)
   - Organization-approved SSH ciphers
   - Approved MACs and KEX algorithms

4. **Audit Policies** (Auditing)
   - Organization-defined audit rules
   - Retention requirements

**Without a config file**, these checks will:
- Use conservative defaults (most secure settings)
- Mark findings as "Requires Manual Validation"
- Include warnings in output

**With a config file**, these checks will:
- Use organization-approved values
- Provide definitive pass/fail results
- Include configuration source in audit evidence

## Creating Your Configuration File

### Step 1: Copy Example

```bash
cp stig-config.json my-production-config.json
```

### Step 2: Customize for Your Environment

Edit `my-production-config.json` following the inline instructions:

```bash
# Review organizational security policies
# Consult with security team
# Document approved values
vi my-production-config.json
```

### Step 3: Validate Configuration

```bash
# Validate JSON syntax
python3 -m json.tool my-production-config.json

# Test with a check
bash samples/V-248519.sh \
    --config my-production-config.json \
    --output-json test.json

# Review results
cat test.json
```

### Step 4: Version Control

```bash
# Store config in version control
git add my-production-config.json
git commit -m "Add production STIG configuration for OL8 v1r7"
git tag -a "ol8-config-v1.0" -m "Oracle Linux 8 STIG v1r7 baseline"

# Keep environment-specific configs separate
# stig-config-prod.json
# stig-config-dev.json
# stig-config-test.json
```

**See [`CONFIG-GUIDE.md`](CONFIG-GUIDE.md) for detailed step-by-step customization.**

## Audit Evidence

All checks provide detailed audit evidence explaining WHY they pass or fail.

### For PASSING Checks:

```
Evidence Supporting PASS:
  ✓ Package 'audit' is installed
  ✓ Version: audit-3.0-0.17.20191104git1c2f876.el8.x86_64
  ✓ Verified using yum/rpm package manager

Conclusion: System meets audit package installation requirements
```

### For FAILING Checks:

```
Compliance Issues (1):

  Issue #1: Audit package not installed
    Evidence Found: Package 'audit' is not present on the system
    Expected: Package 'audit' must be installed
    Risk: Without the audit package, the system cannot perform security
          auditing, making it difficult to investigate security incidents
    Remediation: Install the audit package using: sudo yum install audit
```

**See [`EXAMPLE-OUTPUT.md`](EXAMPLE-OUTPUT.md) for complete examples.**

## Integration Examples

### Ansible Playbook

```yaml
---
- name: Run Oracle Linux 8 STIG Checks
  hosts: oracle_linux_servers
  vars:
    stig_config: stig-config-prod.json
    results_dir: /var/log/stig-checks

  tasks:
    - name: Create results directory
      file:
        path: "{{ results_dir }}/{{ ansible_date_time.date }}"
        state: directory
        mode: '0750'

    - name: Copy STIG configuration
      copy:
        src: "{{ stig_config }}"
        dest: /tmp/stig-config.json
        mode: '0600'

    - name: Run STIG checks
      shell: |
        for check in /opt/stig-checks/oracle_linux_8_v1r7/samples/V-*.sh; do
          vuln_id=$(basename "$check" .sh)
          bash "$check" \
            --config /tmp/stig-config.json \
            --output-json "{{ results_dir }}/{{ ansible_date_time.date }}/${vuln_id}.json"
        done
      register: check_results

    - name: Collect results
      fetch:
        src: "{{ results_dir }}/{{ ansible_date_time.date }}/"
        dest: ./stig-results/{{ inventory_hostname }}/
        flat: yes
```

### Continuous Compliance Monitoring

```bash
#!/bin/bash
# /etc/cron.weekly/stig-compliance-check

CONFIG_FILE="/etc/stig/stig-config-prod.json"
RESULTS_DIR="/var/log/stig-checks/$(date +%Y%m%d)"
CHECKS_DIR="/opt/stig-checks/oracle_linux_8_v1r7/samples"

mkdir -p "$RESULTS_DIR"

# Run all checks
for check in "$CHECKS_DIR"/V-*.sh; do
    vuln_id=$(basename "$check" .sh)

    bash "$check" \
        --config "$CONFIG_FILE" \
        --output-json "$RESULTS_DIR/${vuln_id}.json" \
        2>&1 | logger -t STIG
done

# Generate summary report
{
    echo "STIG Compliance Summary - $(date)"
    echo "================================="
    echo ""
    echo "PASS:  $(grep -l '\"exit_code\": 0' "$RESULTS_DIR"/*.json | wc -l)"
    echo "FAIL:  $(grep -l '\"exit_code\": 1' "$RESULTS_DIR"/*.json | wc -l)"
    echo "N/A:   $(grep -l '\"exit_code\": 2' "$RESULTS_DIR"/*.json | wc -l)"
    echo "ERROR: $(grep -l '\"exit_code\": 3' "$RESULTS_DIR"/*.json | wc -l)"
} | mail -s "Weekly STIG Compliance Report" security-team@example.com
```

### OpenSCAP Integration

```bash
# Convert results to XCCDF format for SCAP tools
python3 convert_to_xccdf.py \
    --input-dir results/ \
    --output stig-results.xml \
    --stig-version "Oracle Linux 8 v1r7"

# Import into SCAP Workbench
scap-workbench stig-results.xml
```

## Best Practices

1. ✅ **Use Configuration Files**: Don't rely on defaults in production
2. ✅ **Version Control**: Track config changes over time
3. ✅ **Environment-Specific**: Separate configs for prod/dev/test
4. ✅ **Regular Execution**: Weekly automated scans minimum
5. ✅ **Review Results**: Don't just collect, actively review findings
6. ✅ **Document Exceptions**: Track and justify any N/A results
7. ✅ **Remediate Promptly**: Address failures within SLA timeframes
8. ✅ **Archive Results**: Maintain compliance audit trail
9. ✅ **Test Before Production**: Validate checks in test environment first
10. ✅ **Track STIG Updates**: Monitor for new STIG releases

## Troubleshooting

### Issue: Check Returns Exit Code 3 (Error)

**Common Causes:**
- Insufficient permissions
- Missing dependencies (yum, systemctl, etc.)
- Invalid configuration file
- System command failures

**Solutions:**
```bash
# Run with elevated privileges if needed
sudo bash V-248519.sh --config stig-config.json

# Check for missing tools
which yum rpm systemctl

# Validate configuration file
python3 -m json.tool stig-config.json

# Check system logs
journalctl -xe
```

### Issue: Configuration File Not Loading

**Symptoms:**
```
WARNING: jq not installed, using default values
```

**Solutions:**
```bash
# Install jq for bash scripts
sudo yum install jq

# Or use Python scripts (don't require jq)
python3 V-248519.py --config stig-config.json

# Verify file exists and is readable
ls -l stig-config.json
cat stig-config.json
```

### Issue: Unexpected Findings

**Troubleshooting:**
```bash
# Run check and review detailed output
bash V-248519.sh --config stig-config.json | tee check-output.log

# Review JSON results
bash V-248519.sh --config stig-config.json --output-json results.json
jq '.' results.json

# Check what configuration was loaded
jq '.config_file' results.json

# Review audit evidence
jq '.finding_details[]' results.json
```

## Documentation

- **[README.md](README.md)** - This file, overview and quick start
- **[CONFIG-GUIDE.md](CONFIG-GUIDE.md)** - Detailed configuration customization guide
- **[EXAMPLE-OUTPUT.md](EXAMPLE-OUTPUT.md)** - Example check outputs with audit evidence
- **[Oracle_Linux_8_STIG_Analysis.md](Oracle_Linux_8_STIG_Analysis.md)** - Detailed automation analysis

## Support

For questions or issues:
1. Review this README
2. Check [`CONFIG-GUIDE.md`](CONFIG-GUIDE.md) for configuration help
3. Review [`EXAMPLE-OUTPUT.md`](EXAMPLE-OUTPUT.md) for expected outputs
4. Validate JSON syntax: `python3 -m json.tool stig-config.json`
5. Test with sample check: `bash samples/V-248519.sh --help`

## Contributing

When adding new checks:
1. Follow the established pattern (see samples/)
2. Include both bash and python versions
3. Provide detailed audit evidence
4. Support --config parameter for environment-specific values
5. Return appropriate exit codes
6. Update documentation

## References

- **Oracle Linux 8 STIG v1r7**: [DISA STIG Library](https://public.cyber.mil/stigs/)
- **NIST SP 800-53 Rev 5**: [Security Controls](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)
- **NIST SP 800-52 Rev 2**: [TLS Guidelines](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-52r2.pdf)
- **FIPS 140-2**: [Cryptographic Module Validation](https://csrc.nist.gov/publications/detail/fips/140/2/final)
- **Oracle Linux 8 Documentation**: [docs.oracle.com](https://docs.oracle.com/en/operating-systems/oracle-linux/8/)

## License

See repository LICENSE file.

## Change Log

| Version | Date | STIG Version | Changes |
|---------|------|--------------|---------|
| 1.0 | 2025-11-22 | v1r7 | Initial framework release for OL8 v1r7 |

---

**Next Steps:**
1. ✅ Review this README
2. ✅ Copy and customize `stig-config.json`
3. ✅ Test with sample check: `bash samples/V-248519.sh --config stig-config.json`
4. ✅ Review [`CONFIG-GUIDE.md`](CONFIG-GUIDE.md) for detailed configuration
5. ✅ Review [`EXAMPLE-OUTPUT.md`](EXAMPLE-OUTPUT.md) for expected outputs
6. ✅ Integrate into your compliance workflow
7. ✅ Automate with Ansible/cron
8. ✅ Monitor and review findings regularly
