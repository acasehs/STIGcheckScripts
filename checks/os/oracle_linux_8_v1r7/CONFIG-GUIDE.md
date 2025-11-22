# STIG Configuration File Guide - Oracle Linux 8

## Overview

This guide explains how to customize the `stig-config.json` file for Oracle Linux 8 STIG compliance checks. The configuration file allows you to define environment-specific values required for STIG compliance validation.

**STIG Version**: Oracle Linux 8 Security Technical Implementation Guide v1r7
**Benchmark Date**: 26 Jul 2023
**Total Checks**: 1003 checks
**Environment-Specific Checks**: 54 (5.4%)

## Configuration File Structure

```
stig-config.json
├── organization              # Your organization information
└── operating_system          # OS configuration settings
    ├── required_packages
    ├── prohibited_packages
    ├── authorized_users
    ├── privileged_users
    ├── service_accounts
    ├── firewall_settings
    ├── selinux_settings
    ├── audit_settings
    ├── ssh_settings
    ├── password_settings
    ├── login_settings
    ├── kernel_parameters
    ├── fips_mode
    ├── banner_text
    ├── file_integrity
    └── usb_restrictions
```

## Step-by-Step Customization

### Step 1: Organization Information

```json
"organization": {
  "name": "Your Organization Name",           // UPDATE: Your org name
  "environment": "Production"                  // UPDATE: Production, Development, Test, or QA
}
```

**Instructions:**
- Replace with your actual organization name
- Set environment to match the target system type

### Step 2: Required and Prohibited Packages

```json
"required_packages": {
  "_comment": "Packages that must be installed for security compliance",
  "values": [
    "audit",                     // Required for security auditing
    "firewalld",                 // Required for host firewall
    "rsyslog",                   // Required for system logging
    "chrony",                    // Required for time synchronization
    "tmux"                       // Required for session auditing
  ]
},

"prohibited_packages": {
  "_comment": "Packages that must NOT be installed (security risks)",
  "values": [
    "telnet-server",             // Unencrypted remote access
    "rsh-server",                // Insecure remote shell
    "ypserv",                    // NIS server (deprecated)
    "tftp-server",               // Unencrypted file transfer
    "vsftpd"                     // FTP server (use SFTP instead)
  ]
}
```

**Instructions:**
- Add packages required by your organization's baseline
- Remove packages from prohibited list only if documented exception exists
- Consult with security team before modifying

### Step 3: User Management

```json
"authorized_users": {
  "_comment": "All user accounts authorized on this system",
  "values": ["oracle", "admin", "appuser", "backup"]      // UPDATE: Your authorized users
},

"privileged_users": {
  "_comment": "Users with sudo/root privileges (subset of authorized_users)",
  "values": ["oracle", "admin"]                           // UPDATE: Your admin users
},

"service_accounts": {
  "_comment": "Non-human service accounts",
  "values": ["appuser", "backup"]                         // UPDATE: Your service accounts
}
```

**Instructions:**
- **authorized_users**: All accounts that should exist on the system
- **privileged_users**: Only accounts with administrative access
- **service_accounts**: Automated/application accounts
- Every privileged user MUST be in authorized_users
- Default system accounts (root, bin, daemon, etc.) are automatically handled
- Review and update quarterly

### Step 4: Firewall Configuration

```json
"firewall_settings": {
  "firewall_enabled": {
    "value": true                                         // REQUIRED: Must be true
  },
  "approved_services": {
    "values": ["ssh", "https"]                            // UPDATE: Your approved services
  },
  "approved_ports": {
    "values": [22, 443]                                   // UPDATE: Your approved ports
  }
}
```

**Instructions:**
- **firewall_enabled**: Must be `true` for STIG compliance
- **approved_services**: Only services required for operation
- **approved_ports**: Document business justification for each port
- Common services: ssh (22), https (443), ntp (123)

### Step 5: SELinux Configuration

```json
"selinux_settings": {
  "selinux_mode": {
    "_requirement": "Must be 'Enforcing' for STIG compliance",
    "value": "Enforcing"                                  // REQUIRED: Must be Enforcing
  },
  "selinux_policy": {
    "_recommendation": "Use 'targeted' for most deployments",
    "value": "targeted"                                   // RECOMMENDED: targeted
  }
}
```

**Instructions:**
- **selinux_mode**: MUST be "Enforcing" for STIG compliance
  - "Permissive" is NOT compliant (use only for troubleshooting)
  - "Disabled" is NOT compliant
- **selinux_policy**: Use "targeted" for most deployments
  - "mls" for Multi-Level Security environments
  - "minimum" for minimal policy (not recommended)

### Step 6: Audit Configuration

```json
"audit_settings": {
  "audit_enabled": {
    "value": true                                         // REQUIRED: Must be true
  },
  "audit_log_max_size": {
    "_recommendation": "Set based on audit volume",
    "value": 6                                            // MINIMUM: 6 MB per STIG
  },
  "audit_log_retention_days": {
    "_requirement": "NIST recommends 90+ days",
    "value": 90                                           // UPDATE: Your retention policy
  },
  "space_left_action": {
    "_requirement": "Must be 'email' or 'syslog' per STIG",
    "value": "email"                                      // REQUIRED: email or syslog
  },
  "admin_space_left_action": {
    "_requirement": "Must be 'single' or 'halt' per STIG",
    "value": "single"                                     // REQUIRED: single or halt
  }
}
```

**Instructions:**
- **audit_enabled**: Must be `true`
- **audit_log_max_size**: Minimum 6 MB, adjust based on log volume
- **audit_log_retention_days**: Minimum 90 days (NIST recommendation)
  - PCI-DSS requires 90 days minimum
  - HIPAA requires based on organizational policy
- **space_left_action**: Action when disk space low
  - "email" - Send email alert (requires configured mail)
  - "syslog" - Log to syslog
- **admin_space_left_action**: Action when critically low
  - "single" - Switch to single-user mode (recommended)
  - "halt" - Halt the system (use with caution)

### Step 7: SSH Configuration

```json
"ssh_settings": {
  "approved_ciphers": {
    "_reference": "NIST SP 800-52 Rev 2",
    "values": [
      "aes256-ctr",                                       // UPDATE: Your approved ciphers
      "aes192-ctr",
      "aes128-ctr"
    ]
  },
  "approved_macs": {
    "values": [
      "hmac-sha2-512",                                    // UPDATE: Your approved MACs
      "hmac-sha2-256"
    ]
  },
  "approved_kex_algorithms": {
    "values": [
      "ecdh-sha2-nistp256",                              // UPDATE: Your approved KEX
      "ecdh-sha2-nistp384",
      "ecdh-sha2-nistp521"
    ]
  },
  "max_auth_tries": {
    "_requirement": "STIG requires 3 or less",
    "value": 3                                            // MAX: 3 attempts
  },
  "client_alive_interval": {
    "_requirement": "STIG requires 600 (10 minutes) or less",
    "value": 600                                          // MAX: 600 seconds
  }
}
```

**Instructions:**
- **approved_ciphers**: Only FIPS 140-2 approved ciphers
  - Use CTR or GCM modes
  - Avoid CBC mode (vulnerable to attacks)
- **approved_macs**: Use SHA-2 family only
  - Avoid SHA-1 and MD5 (deprecated)
- **approved_kex_algorithms**: Use ECDH with NIST curves
  - Avoid older DH algorithms
- **max_auth_tries**: Maximum 3 attempts before disconnect
- **client_alive_interval**: Maximum 600 seconds (10 minutes) idle timeout

Reference: [NIST SP 800-52 Rev 2](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-52r2.pdf)

### Step 8: Password Policy

```json
"password_settings": {
  "min_length": {
    "_requirement": "STIG requires 15 characters minimum",
    "value": 15                                           // MIN: 15 characters
  },
  "min_class_requirements": {
    "_requirement": "STIG requires at least 4",
    "value": 4                                            // REQUIRED: 4 (upper, lower, digit, special)
  },
  "max_repeating_chars": {
    "_requirement": "STIG requires 3 or less",
    "value": 3                                            // MAX: 3 consecutive chars
  },
  "password_reuse_limit": {
    "_requirement": "STIG requires 5 or more",
    "value": 5                                            // MIN: 5 previous passwords
  },
  "password_max_age_days": {
    "_requirement": "STIG requires 60 days or less",
    "value": 60                                           // MAX: 60 days
  },
  "password_min_age_days": {
    "_requirement": "STIG requires 1 day minimum",
    "value": 1                                            // MIN: 1 day
  }
}
```

**Instructions:**
- All values shown are STIG requirements
- Organization may make policies MORE restrictive, but not less
- Example: min_length could be 16+, but not less than 15

### Step 9: Login and Session Settings

```json
"login_settings": {
  "session_timeout_seconds": {
    "_requirement": "STIG requires 900 seconds (15 minutes) or less",
    "value": 900                                          // MAX: 900 seconds
  },
  "max_login_attempts": {
    "_requirement": "STIG requires 3 or less",
    "value": 3                                            // MAX: 3 attempts
  },
  "lockout_duration_seconds": {
    "_requirement": "STIG requires 900 seconds or more; 0 = manual unlock",
    "value": 900                                          // MIN: 900 seconds (or 0)
  },
  "root_login_allowed": {
    "_requirement": "STIG requires false (use sudo instead)",
    "value": false                                        // REQUIRED: false
  }
}
```

**Instructions:**
- **session_timeout_seconds**: Maximum idle time before automatic logout
- **max_login_attempts**: Failed login attempts before account lockout
- **lockout_duration_seconds**: Time account is locked after max failures
  - Set to 0 to require manual unlock (more secure)
- **root_login_allowed**: Must be `false` - use sudo instead

### Step 10: Kernel Parameters

```json
"kernel_parameters": {
  "net.ipv4.conf.all.accept_source_route": {
    "_requirement": "Must be 0",
    "value": 0                                            // REQUIRED: 0 (disabled)
  },
  "net.ipv4.icmp_echo_ignore_broadcasts": {
    "_requirement": "Must be 1",
    "value": 1                                            // REQUIRED: 1 (enabled)
  },
  "kernel.randomize_va_space": {
    "_requirement": "Must be 2",
    "value": 2                                            // REQUIRED: 2 (full ASLR)
  }
}
```

**Instructions:**
- These are security-related kernel parameters
- Values shown are STIG requirements - DO NOT change unless documented exception
- Applied via `/etc/sysctl.conf` or `/etc/sysctl.d/`

### Step 11: FIPS Mode

```json
"fips_mode": {
  "fips_enabled": {
    "_requirement": "STIG requires true for DoD systems",
    "value": true                                         // DoD: true; Non-DoD: consult policy
  },
  "approved_crypto_policies": {
    "_allowed_values": ["FIPS", "FIPS:OSPP"],
    "value": "FIPS"                                       // RECOMMENDED: FIPS
  }
}
```

**Instructions:**
- **fips_enabled**: Required for DoD systems
  - Enabling requires system reboot
  - Some applications may not support FIPS mode
- **approved_crypto_policies**:
  - "FIPS" - Standard FIPS 140-2 compliance
  - "FIPS:OSPP" - FIPS + Common Criteria OSPP

**Enabling FIPS Mode:**
```bash
sudo fips-mode-setup --enable
sudo reboot
```

### Step 12: Login Banner

```json
"banner_text": {
  "_requirement": "Must display before granting access",
  "pre_login": "You are accessing a U.S. Government (USG) Information System...",
  "post_login": "You are accessing a U.S. Government (USG) Information System."
}
```

**Instructions:**
- **pre_login**: Displayed before authentication (/etc/issue, /etc/issue.net)
- **post_login**: Displayed after authentication (/etc/motd)
- DoD systems: Use Standard Mandatory DoD Notice (included in template)
- Non-DoD systems: Consult legal team for appropriate warning banner

### Step 13: File Integrity Monitoring

```json
"file_integrity": {
  "aide_enabled": {
    "_requirement": "STIG requires file integrity monitoring",
    "value": true                                         // REQUIRED: true
  },
  "aide_check_frequency": {
    "_requirement": "STIG requires at least weekly",
    "value": "weekly"                                     // RECOMMENDED: weekly
  }
}
```

**Instructions:**
- **aide_enabled**: Advanced Intrusion Detection Environment must be configured
- **aide_check_frequency**: How often to run integrity checks
  - "daily" - More secure, higher overhead
  - "weekly" - STIG minimum requirement

**Setting up AIDE:**
```bash
sudo yum install aide
sudo aide --init
sudo mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz
# Schedule weekly check via cron
```

## Validation

### Before Using the Configuration

1. **Validate JSON Syntax:**
   ```bash
   python3 -m json.tool stig-config.json
   ```
   Expected: Clean JSON output without errors

2. **Review with Security Team:**
   - Share config with security/compliance team
   - Verify values match organizational policies
   - Document approval and version

3. **Test with a Check:**
   ```bash
   bash samples/V-248519.sh --config stig-config.json --output-json test.json
   ```
   Review test.json for expected behavior

## Environment-Specific Configurations

### Multiple Environments

Create separate config files for each environment:

```bash
stig-config-prod.json      # Production settings (strictest)
stig-config-dev.json       # Development settings
stig-config-test.json      # Test environment settings
stig-config-qa.json        # QA environment settings
```

### Example Differences:

| Setting | Production | Development | Test |
|---------|-----------|-------------|------|
| selinux_mode | Enforcing | Enforcing | Permissive |
| fips_enabled | true | false | false |
| session_timeout_seconds | 600 | 900 | 900 |
| audit_log_retention_days | 90 | 30 | 30 |
| firewall_enabled | true | true | false |

**Important**: Development/Test environments should still meet minimum security requirements.

## Security Best Practices

### Protecting the Configuration File

```bash
# Set restrictive permissions
chmod 600 stig-config.json
chown root:root stig-config.json

# Or use SELinux
sudo semanage fcontext -a -t etc_t stig-config.json
sudo restorecon -v stig-config.json
```

### Version Control

```bash
# Store in version control
git add stig-config-prod.json
git commit -m "Update STIG config for Oracle Linux 8 v1r7 compliance"
git tag -a "ol8-stig-config-v1.0" -m "Oracle Linux 8 STIG v1r7 baseline"
```

### Regular Reviews

- **Weekly**: Review audit logs and failed checks
- **Monthly**: Review firewall rules and open ports
- **Quarterly**: Review user lists, remove terminated users
- **Semi-annually**: Review cipher suites, kernel parameters
- **Annually**: Full security policy and STIG configuration review
- **As-needed**: After security incidents or STIG updates

## Troubleshooting

### Issue: JSON Syntax Error

**Symptom:**
```
json.decoder.JSONDecodeError: Expecting ',' delimiter
```

**Solution:**
- Validate JSON: `python3 -m json.tool stig-config.json`
- Check for missing commas, brackets, or quotes
- Remove trailing commas before closing brackets
- Comment fields (_comment) must use proper JSON syntax

### Issue: Check Uses Default Values

**Symptom:**
```
WARNING: jq not installed, using default values
```

**Solution:**
- Install jq: `sudo yum install jq`
- Or use Python checks which don't require jq

### Issue: FIPS Mode Not Enabling

**Symptom:**
```
FIPS mode is disabled
```

**Solution:**
```bash
# Enable FIPS mode
sudo fips-mode-setup --enable
sudo reboot

# Verify after reboot
sudo fips-mode-setup --check
```

## Reference Materials

### Official Documentation

- **Oracle Linux 8 STIG v1r7**: [DISA STIG Viewer](https://public.cyber.mil/stigs/)
- **NIST SP 800-53 Rev 5**: Security Controls
- **NIST SP 800-52 Rev 2**: TLS Guidelines
- **FIPS 140-2**: Cryptographic Module Validation
- **Oracle Linux 8 Docs**: [docs.oracle.com](https://docs.oracle.com/en/operating-systems/oracle-linux/8/)

### Configuration Tools

- **OpenSCAP**: Automated compliance scanning
- **Ansible**: Configuration management
- **Puppet/Chef**: Infrastructure as code

## Support

For questions or issues:
1. Review this guide
2. Check `README.md` for usage examples
3. Review `EXAMPLE-OUTPUT.md` for expected check outputs
4. Validate JSON syntax: `python3 -m json.tool stig-config.json`
5. Test with sample check: `bash samples/V-248519.sh --config stig-config.json`

## Change Log

| Version | Date | Changes | Author |
|---------|------|---------|--------|
| 1.0 | 2025-11-22 | Initial configuration guide for OL8 v1r7 | System |

---

**Next Steps:**
1. ✅ Copy `stig-config.json` and customize for your environment
2. ✅ Review each section (steps 1-13) and update values
3. ✅ Validate: `python3 -m json.tool stig-config.json`
4. ✅ Test with sample check
5. ✅ Get security team approval
6. ✅ Version control the configuration
7. ✅ Deploy to target systems
8. ✅ Schedule regular reviews
