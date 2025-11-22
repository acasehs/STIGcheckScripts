# Test-Weblogic-3: STIG Checks with Environment-Specific Configuration Support

## Overview

Test-Weblogic-3 implements STIG checks for Oracle WebLogic Server 12c with support for **environment-specific configuration files**. This allows organizations to define approved values, authorized users, and other site-specific requirements that vary by deployment.

## Key Features

✅ **Native Tools Priority**: Bash → Python → Third-Party (minimizes dependencies)
✅ **Configuration File Support**: Define environment-specific values in JSON
✅ **Multiple Output Formats**: JSON, human-readable, exit codes
✅ **No Third-Party Requirements**: Uses bash/python stdlib (optional: xmllint, jq)

## Configuration File Pattern

### Why Configuration Files?

**44.4%** of WebLogic STIG checks are environment-specific, requiring values like:
- Approved ports and protocols
- Authorized user lists
- Organizational cipher suites
- Site-defined security settings
- Custom audit requirements

Without configuration files, these checks would require **manual validation** or **hardcoded values**.

### Configuration File Format

Create a JSON file (e.g., `stig-config.json`) with your environment-specific values:

```json
{
  "description": "STIG Check Configuration - Production Environment",
  "version": "1.0",
  "organization": "Your Organization",
  "environment": "Production",

  "weblogic": {
    "approved_protocols": ["t3s", "https", "iiops"],
    "approved_ports": [7002, 9002],
    "unauthorized_protocols": ["t3", "http", "iiop"],
    "unauthorized_ports": [7001, 9001],

    "approved_cipher_suites": [
      "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
      "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
    ],

    "authorized_users": ["weblogic", "admin", "sysadmin"],
    "privileged_users": ["weblogic"],

    "required_ssl_settings": {
      "min_tls_version": "1.2",
      "ssl_enabled": true,
      "client_certificate_enforced": false
    },

    "audit_settings": {
      "audit_level": "Custom",
      "all_events_enabled": true,
      "users_to_always_audit": ["weblogic", "admin"]
    }
  }
}
```

## Usage Examples

### Basic Check (Uses Defaults)

```bash
# Bash (Preferred)
bash V-235928.sh --domain-home /u01/oracle/user_projects/domains/base_domain

# Python (Fallback)
python3 V-235928.py --domain-home /u01/oracle/user_projects/domains/base_domain
```

### With Configuration File (Environment-Specific Values)

```bash
# Bash with config
bash V-235928.sh \
  --domain-home /u01/oracle/user_projects/domains/base_domain \
  --config stig-config.json

# Python with config
python3 V-235928.py \
  --domain-home /u01/oracle/user_projects/domains/base_domain \
  --config stig-config.json
```

### With JSON Output

```bash
# Bash with config and JSON output
bash V-235928.sh \
  --domain-home /u01/oracle/user_projects/domains/base_domain \
  --config stig-config.json \
  --output-json results/V-235928.json

# Python with config and JSON output
python3 V-235928.py \
  --domain-home /u01/oracle/user_projects/domains/base_domain \
  --config stig-config.json \
  --output-json results/V-235928.json
```

## Configuration Requirements by Check Type

### Environment-Specific Checks (44.4%)

These checks **require** a configuration file or manual validation:

- **Approved Protocols/Ports**: Must specify which protocols/ports are allowed
- **Authorized Users**: Must list privileged and authorized users
- **Cipher Suites**: Must define approved cryptographic algorithms
- **Audit Policies**: Must specify organizational audit requirements

**Without a config file**, these checks will:
- Use conservative defaults (e.g., only most secure options)
- Mark findings as "Requires Manual Validation"
- Include warnings in output

### System-Specific Checks (19.4%)

These checks adapt based on:
- Production vs. non-production environments
- Custom deployments
- Installation-specific paths

### Standard Checks (36.1%)

These checks have no configuration dependencies and work out-of-the-box.

## Default Values

If no configuration file is provided, checks use secure defaults:

| Setting | Default Value | Recommendation |
|---------|---------------|----------------|
| Approved Ports | 7002, 9002 | SSL ports only |
| Approved Protocols | t3s, https, iiops | Encrypted protocols only |
| SSL Enabled | true | Always require SSL |
| Min TLS Version | 1.2 | Modern TLS only |

**⚠️ Warning**: Defaults may not match your organization's security policy. **Use a configuration file** for production compliance.

## Creating Your Configuration File

### Step 1: Copy Example

```bash
cp stig-config.example.json stig-config.json
```

### Step 2: Customize for Your Environment

Edit `stig-config.json` with your organization's approved values:

```bash
# Review organizational security policies
# Consult with security team
# Document approved values
vi stig-config.json
```

### Step 3: Version Control

```bash
# Store config in version control
git add stig-config.json
git commit -m "Add production STIG configuration"

# Keep environment-specific configs separate
# stig-config-prod.json
# stig-config-dev.json
# stig-config-test.json
```

### Step 4: Validate Configuration

```bash
# Test config file with a check
bash V-235928.sh \
  --domain-home /u01/oracle/user_projects/domains/base_domain \
  --config stig-config.json \
  --output-json validation.json

# Review results
cat validation.json
```

## Exit Codes

All checks return standardized exit codes:

| Exit Code | Status | Meaning |
|-----------|--------|---------|
| 0 | PASS | Check passed, no findings |
| 1 | FAIL | Check failed, findings detected |
| 2 | N/A | Check not applicable or requires manual review |
| 3 | ERROR | Error occurred during execution |

## Dependencies

### Required (All Checks)
- Bash 4.0+ (for .sh scripts)
- Python 3.6+ (for .py scripts)

### Optional (Enhanced Features)
- `xmllint` (libxml2-utils) - Better XML parsing in bash
- `jq` - JSON parsing in bash for config files

```bash
# Install on Debian/Ubuntu
apt-get install libxml2-utils jq

# Install on RHEL/CentOS/Oracle Linux
yum install libxml2 jq
```

**Without optional tools**:
- Bash scripts fall back to grep-based parsing
- Python scripts always work (uses stdlib)

## Security Considerations

### Configuration File Security

```bash
# Protect configuration file
chmod 600 stig-config.json
chown root:root stig-config.json

# Encrypt sensitive configs
# ansible-vault encrypt stig-config.json
```

### Audit Trail

```bash
# Log all check executions
bash V-235928.sh --domain-home /path --config stig-config.json \
  2>&1 | tee -a /var/log/stig-checks.log
```

### Separation of Duties

- **Security team**: Define approved values in config
- **Operations team**: Run checks with approved config
- **Audit team**: Review results and findings

## Integration Examples

### Ansible Playbook

```yaml
- name: Run WebLogic STIG Checks
  hosts: weblogic_servers
  tasks:
    - name: Copy STIG config
      copy:
        src: stig-config-prod.json
        dest: /tmp/stig-config.json
        mode: '0600'

    - name: Run V-235928 check
      command: >
        bash /opt/stig-checks/V-235928.sh
        --domain-home {{ weblogic_domain_home }}
        --config /tmp/stig-config.json
        --output-json /var/log/stig/V-235928.json
      register: check_result

    - name: Collect results
      fetch:
        src: /var/log/stig/V-235928.json
        dest: ./results/{{ inventory_hostname }}/
```

### Continuous Compliance Scanning

```bash
#!/bin/bash
# Run all STIG checks with config file

CONFIG_FILE="/etc/stig/stig-config.json"
DOMAIN_HOME="/u01/oracle/user_projects/domains/base_domain"
RESULTS_DIR="/var/log/stig-checks/$(date +%Y%m%d)"

mkdir -p "$RESULTS_DIR"

for check_script in /opt/stig-checks/V-*.sh; do
    vuln_id=$(basename "$check_script" .sh)

    bash "$check_script" \
        --domain-home "$DOMAIN_HOME" \
        --config "$CONFIG_FILE" \
        --output-json "$RESULTS_DIR/${vuln_id}.json"

    echo "$vuln_id: exit code $?"
done
```

## Best Practices

1. ✅ **Use Configuration Files**: Don't rely on defaults in production
2. ✅ **Version Control**: Track config changes over time
3. ✅ **Environment-Specific**: Separate configs for prod/dev/test
4. ✅ **Review Regularly**: Update approved values as policies change
5. ✅ **Document Decisions**: Note why values were approved
6. ✅ **Test Changes**: Validate config updates before production
7. ✅ **Audit Results**: Review findings and remediate promptly

## Troubleshooting

### Config File Not Loading

```bash
# Check file exists and is readable
ls -l stig-config.json

# Validate JSON syntax
python3 -m json.tool stig-config.json

# Check for jq (bash scripts)
which jq
```

### Unexpected Findings

```bash
# Run with verbose output
bash V-235928.sh --domain-home /path --config stig-config.json

# Check what values were loaded
grep "INFO: Loaded configuration" output.log
```

### Exit Code 3 (Error)

Common causes:
- Domain home path incorrect
- Insufficient permissions
- Config file not found or invalid JSON
- Missing dependencies (check warnings)

## Support

For issues or questions:
1. Check this README
2. Review example config: `stig-config.example.json`
3. Run with `--help` flag for usage
4. Check logs for error messages

## Next Steps

1. Review `stig-config.example.json`
2. Create your organization's config file
3. Test with a single check
4. Integrate into your compliance workflow
5. Automate with Ansible/scripts
6. Monitor and review findings regularly
