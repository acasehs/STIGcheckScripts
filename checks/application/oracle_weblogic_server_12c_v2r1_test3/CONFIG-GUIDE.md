# STIG Configuration File Guide

## Overview

This guide explains how to customize the `stig-config.json` file for your organization's security requirements. The configuration file allows you to define environment-specific values that are required for STIG compliance checks.

## Configuration File Structure

The configuration file uses JSON format with inline comments (prefixed with `_comment`) to guide customization.

### Main Sections

```
stig-config.json
├── organization          # Your organization information
├── weblogic             # WebLogic-specific settings
│   ├── approved_protocols
│   ├── approved_ports
│   ├── approved_cipher_suites
│   ├── authorized_users
│   ├── required_ssl_settings
│   ├── audit_settings
│   ├── session_timeout
│   └── deployment_restrictions
└── _customization_instructions
```

## Step-by-Step Customization

### Step 1: Organization Information

```json
"organization": {
  "name": "Your Organization Name",           // UPDATE: Your org name
  "environment": "Production",                 // UPDATE: Production, Development, Test, or QA
}
```

**Instructions:**
- Replace "Your Organization Name" with your actual organization
- Set environment to match the target system

### Step 2: Approved Protocols

```json
"approved_protocols": {
  "_comment": "List only encrypted/secure protocols",
  "_examples": ["t3s", "https", "iiops", "ldaps"],
  "_reject": ["t3", "http", "iiop", "ldap"],
  "values": ["t3s", "https", "iiops"]        // UPDATE: Your approved protocols
}
```

**Instructions:**
- Only include encrypted protocols (SSL/TLS variants)
- Common secure protocols:
  - `t3s` - WebLogic T3 over SSL
  - `https` - HTTP over SSL/TLS
  - `iiops` - IIOP over SSL
  - `ldaps` - LDAP over SSL
- **DO NOT** include:
  - `t3` - Unencrypted WebLogic T3
  - `http` - Unencrypted HTTP
  - `iiop` - Unencrypted IIOP
  - `ldap` - Unencrypted LDAP

### Step 3: Approved Ports

```json
"approved_ports": {
  "_comment": "List only SSL/TLS ports",
  "_examples": [7002, 9002, 8002],
  "_reject": [7001, 9001, 8001],
  "values": [7002, 9002]                     // UPDATE: Your approved SSL ports
}
```

**Instructions:**
- WebLogic default ports:
  - `7001` - Admin server (non-SSL) ❌
  - `7002` - Admin server (SSL) ✅
  - `9001` - Managed server (non-SSL) ❌
  - `9002` - Managed server (SSL) ✅
- Only include SSL-enabled ports
- Consult your network team for custom port assignments

### Step 4: Cipher Suites

```json
"approved_cipher_suites": {
  "_comment": "NIST/NSA Suite B recommended",
  "_reference": "https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-52r2.pdf",
  "values": [
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",  // UPDATE: Your approved ciphers
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_RSA_WITH_AES_128_GCM_SHA256"
  ]
}
```

**Instructions:**
- Use only strong, modern cipher suites
- Recommended: ECDHE for forward secrecy, AES-GCM for encryption
- **Minimum**: TLS 1.2 compatible ciphers
- Reference NIST SP 800-52 Rev 2 for guidance
- Consult your security team for approved list

**Weak Ciphers to Avoid:**
- Anything with `SSL_` (SSL 2.0/3.0 - deprecated)
- Anything with `DES` or `3DES` (weak encryption)
- Anything with `RC4` (broken algorithm)
- Anything with `MD5` (weak hash)

### Step 5: User Lists

```json
"authorized_users": {
  "_comment": "All users authorized to access WebLogic",
  "values": ["weblogic", "admin", "sysadmin", "app_service"]  // UPDATE: Your users
},

"privileged_users": {
  "_comment": "Users with admin privileges (subset of authorized_users)",
  "values": ["weblogic", "admin"]                            // UPDATE: Your admins
},

"service_accounts": {
  "_comment": "Non-human service accounts",
  "values": ["app_service"]                                  // UPDATE: Your services
}
```

**Instructions:**
- `authorized_users`: All accounts that can access WebLogic
- `privileged_users`: Subset with administrative rights
- `service_accounts`: Automated/application accounts
- Include both human and service accounts
- Every privileged user MUST be in authorized_users
- Review with your IAM/identity team

### Step 6: SSL/TLS Settings

```json
"required_ssl_settings": {
  "min_tls_version": {
    "_allowed_values": ["1.2", "1.3"],
    "value": "1.2"                          // UPDATE: "1.2" or "1.3"
  },
  "ssl_enabled": {
    "value": true                           // REQUIRED: Must be true
  },
  "client_certificate_enforced": {
    "_recommendation": "true for high-security environments",
    "value": false                          // UPDATE: true for mutual TLS
  },
  "hostname_verification_enabled": {
    "value": true                           // RECOMMENDED: Keep true
  }
}
```

**Instructions:**
- **min_tls_version**: Use "1.2" minimum, "1.3" preferred
  - TLS 1.0/1.1 are deprecated and insecure
- **ssl_enabled**: Must be `true`
- **client_certificate_enforced**:
  - `false` - Server-side SSL only
  - `true` - Mutual TLS (requires client certs)
- **hostname_verification_enabled**: Keep `true` for security

### Step 7: Audit Settings

```json
"audit_settings": {
  "audit_level": {
    "_allowed_values": ["None", "Success", "Failure", "Custom"],
    "value": "Custom"                       // REQUIRED: Use "Custom"
  },
  "all_events_enabled": {
    "value": true                           // RECOMMENDED: true for compliance
  },
  "users_to_always_audit": {
    "values": ["weblogic", "admin"]        // UPDATE: Privileged users
  },
  "audit_data_retention_days": {
    "_comment": "NIST recommends 90+ days",
    "value": 90                             // UPDATE: Your retention policy
  }
}
```

**Instructions:**
- **audit_level**: Use "Custom" for selective auditing
- **all_events_enabled**: `true` recommended for compliance
- **users_to_always_audit**: Include all privileged users
- **audit_data_retention_days**:
  - Minimum: 90 days (NIST recommendation)
  - Adjust based on compliance requirements (PCI-DSS, HIPAA, etc.)

### Step 8: Session Timeout

```json
"session_timeout": {
  "admin_console_timeout": {
    "_comment": "NIST recommends 15 minutes or less",
    "value": 15                             // UPDATE: Max 15 minutes
  },
  "application_timeout": {
    "value": 30                             // UPDATE: Per your requirements
  }
}
```

**Instructions:**
- **admin_console_timeout**:
  - Maximum: 15 minutes (NIST/STIG requirement)
  - Lower for high-security environments
- **application_timeout**: Adjust based on application needs

### Step 9: Deployment Restrictions

```json
"deployment_restrictions": {
  "auto_deployment_enabled": {
    "_comment": "Should be disabled in production",
    "value": false                          // REQUIRED: false for production
  },
  "production_mode": {
    "_comment": "Should be enabled for production systems",
    "value": true                           // REQUIRED: true for production
  }
}
```

**Instructions:**
- **auto_deployment_enabled**:
  - `false` for production (security risk)
  - `true` acceptable for development only
- **production_mode**:
  - `true` for production systems
  - `false` only for development

## Validation

### Before Using the Configuration

1. **Validate JSON Syntax:**
   ```bash
   python3 -m json.tool stig-config.json
   ```

   Expected: Clean JSON output without errors

2. **Review with Security Team:**
   - Share config with security/compliance team
   - Verify approved values match organizational policies
   - Document approval and version

3. **Test with a Check:**
   ```bash
   python3 V-235928.py \
     --domain-home /path/to/domain \
     --config stig-config.json \
     --output-json test-results.json
   ```

   Review test-results.json for expected behavior

## Environment-Specific Configurations

### Multiple Environments

Create separate config files for each environment:

```bash
stig-config-prod.json      # Production settings
stig-config-dev.json       # Development settings
stig-config-test.json      # Test environment settings
stig-config-qa.json        # QA environment settings
```

### Example Differences:

| Setting | Production | Development | Test |
|---------|-----------|-------------|------|
| min_tls_version | "1.2" | "1.2" | "1.2" |
| client_certificate_enforced | true | false | false |
| auto_deployment_enabled | false | true | false |
| production_mode | true | false | false |
| audit_data_retention_days | 90 | 30 | 30 |

## Security Best Practices

### Protecting the Configuration File

```bash
# Set restrictive permissions
chmod 600 stig-config.json
chown root:root stig-config.json

# Or encrypt with ansible-vault
ansible-vault encrypt stig-config.json
```

### Version Control

```bash
# Commit to version control
git add stig-config-prod.json
git commit -m "Update approved cipher suites - Security Policy v2.5"
git tag -a "stig-config-v2.5" -m "Security policy v2.5 compliance"
```

### Regular Reviews

- **Quarterly**: Review user lists, remove terminated users
- **Semi-annually**: Review cipher suites, protocols, ports
- **Annually**: Full security policy review
- **As-needed**: After security incidents or policy changes

## Common Issues and Solutions

### Issue: JSON Syntax Error

**Symptom:**
```
json.decoder.JSONDecodeError: Expecting ',' delimiter
```

**Solution:**
- Validate JSON: `python3 -m json.tool stig-config.json`
- Check for missing commas, brackets, or quotes
- Remove trailing commas before closing brackets

### Issue: Check Uses Default Values

**Symptom:**
```
WARNING: jq not installed, using default approved values
```

**Solution:**
- Install jq: `apt-get install jq` or `yum install jq`
- Or use Python checks instead of bash

### Issue: Config File Not Found

**Symptom:**
```
ERROR: Configuration file not found: stig-config.json
```

**Solution:**
- Verify file path: `ls -l stig-config.json`
- Use absolute path: `--config /full/path/to/stig-config.json`

## Reference Materials

### NIST Publications
- **SP 800-52 Rev 2**: TLS Guidelines
  - https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-52r2.pdf
- **SP 800-53 Rev 5**: Security Controls
  - https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final

### DISA STIG Resources
- **WebLogic 12c STIG**: Latest version
  - https://public.cyber.mil/stigs/
- **Application Security and Development STIG**
  - https://public.cyber.mil/stigs/

### WebLogic Documentation
- **Security Configuration**
  - https://docs.oracle.com/middleware/12213/wls/SECMG/toc.htm
- **SSL Configuration**
  - https://docs.oracle.com/middleware/12213/wls/SECMG/ssl.htm

## Support

For questions or issues:
1. Review this guide
2. Check `README.md` in this directory
3. Validate JSON syntax
4. Test with: `--config stig-config.json --output-json test.json`
5. Review test.json for errors

## Change Log

| Version | Date | Changes | Author |
|---------|------|---------|--------|
| 1.0 | 2025-11-22 | Initial configuration template | System |

---

**Next Steps:**
1. ✅ Copy `stig-config.example.json` to `stig-config.json`
2. ✅ Follow steps 1-9 above to customize
3. ✅ Validate with `python3 -m json.tool stig-config.json`
4. ✅ Test with a check
5. ✅ Document and version control
6. ✅ Deploy to target systems
