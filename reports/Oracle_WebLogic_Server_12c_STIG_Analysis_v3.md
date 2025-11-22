# Oracle WebLogic Server 12c STIG Check Analysis Report
**Generated:** 2025-11-22 03:20:05
**STIG:** Oracle WebLogic Server 12c Security Technical Implementation Guide :: Version 2, Release: 1 Benchmark Date: 23 Apr 2021
**Total Checks:** 72

---

## 📊 Executive Summary

### Automation Status Overview

| Automation Status | Count | Percentage | Status |
|------------------|-------|------------|--------|
| ✅ Automatable | 62 | 86.1% | Can be fully automated |
| ⚠️ Partially Automatable | 2 | 2.8% | Requires some manual validation |
| 📝 Manual Review Required | 8 | 11.1% | Cannot be automated |
| 🔍 Needs Analysis | 0 | 0.0% | Automation feasibility TBD |
| **TOTAL** | **72** | **100.0%** | |

### Automation Status by Severity

| Severity | Total | Automatable | Partial | Manual | Automation Rate |
|----------|-------|-------------|---------|--------|----------------|
| HIGH | 4 | 4 | 0 | 0 | 100.0% |
| MEDIUM | 49 | 40 | 2 | 7 | 85.7% |
| LOW | 19 | 18 | 0 | 1 | 94.7% |
| **TOTAL** | **72** | **62** | **2** | **8** | **88.9%** |

### Configuration Dependencies

| Dependency Type | Count | Percentage | Description |
|----------------|-------|------------|-------------|
| 🌐 Environment-Specific | 32 | 44.4% | Requires site-specific/organizational values |
| 🖥️ System-Specific | 14 | 19.4% | Depends on deployment/installation config |
| ✓ Standard | 26 | 36.1% | No special dependencies |

### Severity Distribution

| Severity | Count | Percentage |
|----------|-------|------------|
| 🔴 HIGH | 4 | 5.6% |
| 🟡 MEDIUM | 49 | 68.1% |
| 🟢 LOW | 19 | 26.4% |
| **TOTAL** | **72** | **100.0%** |

### Tool Preference (Priority: Bash > PowerShell > Python > Third-Party)

| Tool Type | Count | Notes |
|-----------|-------|-------|
| Bash (Native) | 64 | Primary method - no dependencies |
| Python (Native) | 0 | Fallback - uses stdlib only |
| Third-Party Optional | 20 | Can use WLST if needed |
| **Minimal Third-Party** | **52** | **72.2% can run without third-party tools** |

## Summary
- **Automatable Checks:** 62 (86.1%)
- **Partially Automatable:** 2 (2.8%)
- **Manual Review Required:** 8 (11.1%)
- **Needs Analysis:** 0 (0.0%)

### Environment/System Specific Checks
- **Environment-Specific:** 32 (44.4%)
  - *These checks require site-specific, organizational, or approved values*
- **System-Specific:** 14 (19.4%)
  - *These checks depend on deployment or installation-specific configurations*

### Severity Distribution
- **High:** 4
- **Medium:** 49
- **Low:** 19

---

## Detailed Check Analysis

### Automatable (62 checks)

#### V-235928 - WBLC-01-000009
**Severity:** MEDIUM

**Rule Title:** Oracle WebLogic must utilize cryptography to protect the confidentiality of remote access management sessions.

**Automation Status:** Automatable

**Automation Method:** Bash/Python (config.xml parsing)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python/powershell)

**Requires Elevation:** Yes (WebLogic Admin credentials)

**🔧 Configuration Dependencies:**
- ⚠️ **ENVIRONMENT-SPECIFIC**: This check requires site-specific or organizational values
- ⚠️ **SYSTEM-SPECIFIC**: This check depends on deployment/installation-specific configuration

**Notes:**
- Admin Console check - can be automated via native tools (bash/python parsing config.xml)

**Environment/System Annotations:**
- Environment-specific: Contains "ssp"
- System-specific: Contains "custom"

**Check Content:**
```
1. Access AC
2. From 'Domain Structure', select 'Environment' -> 'Servers' 
3. From the list of servers, select one which needs check for SSL configuration verification
4. From 'Configuration' tab -> 'General' tab, ensure 'Listen Port Enabled' checkbox is deselected
5. Ensure 'SSL Listen Port Enabled' checkbox is selected and a valid port number is in 'SSL Listen Port' field, e.g., 7002

6 Repeat steps 3-5 for all servers requiring SSL configuration checking

If 'Listen Port Enabled' is selected...
```
**Execution Command:**
```bash
# Option 1: Bash (Preferred - No third-party tools)
bash checks/application/Test-Weblogic-3/V-235928.sh \
  --domain-home /u01/oracle/user_projects/domains/base_domain

# Option 2: Python (Fallback - No third-party tools)
python3 checks/application/Test-Weblogic-3/V-235928.py \
  --domain-home /u01/oracle/user_projects/domains/base_domain

# With JSON output
bash checks/application/Test-Weblogic-3/V-235928.sh \
  --domain-home /u01/oracle/user_projects/domains/base_domain \
  --output-json results/V-235928.json

```

**NIST SP 800-53 Rev 4:** AC-17 (2)

--------------------------------------------------------------------------------

#### V-235929 - WBLC-01-000010
**Severity:** MEDIUM

**Rule Title:** Oracle WebLogic must use cryptography to protect the integrity of the remote access session.

**Automation Status:** Automatable

**Automation Method:** Bash/Python (config.xml parsing)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python/powershell)

**Requires Elevation:** Yes (WebLogic Admin credentials)

**🔧 Configuration Dependencies:**
- ⚠️ **ENVIRONMENT-SPECIFIC**: This check requires site-specific or organizational values
- ⚠️ **SYSTEM-SPECIFIC**: This check depends on deployment/installation-specific configuration

**Notes:**
- Admin Console check - can be automated via native tools (bash/python parsing config.xml)

**Environment/System Annotations:**
- Environment-specific: Contains "approved"
- Environment-specific: Contains "ssp"
- System-specific: Contains "custom"

**Check Content:**
```
1. Access AC
2. From 'Domain Structure', select 'Environment' -> 'Servers' 
3. From the list of servers, select one which needs check for SSL configuration verification
4. From 'Configuration' tab -> 'General' tab, ensure 'Listen Port Enabled' checkbox is deselected
5. Ensure 'SSL Listen Port Enabled' checkbox is selected and a valid port number is in 'SSL Listen Port' field, e.g., 7002

6. Repeat steps 3-5 for all servers requiring SSL configuration checking

If 'Listen Port Enabled' is selecte...
```
**Execution Command:**
```bash
# Option 1: Bash (Preferred - No third-party tools)
bash checks/application/Test-Weblogic-3/V-235929.sh \
  --domain-home /u01/oracle/user_projects/domains/base_domain

# Option 2: Python (Fallback - No third-party tools)
python3 checks/application/Test-Weblogic-3/V-235929.py \
  --domain-home /u01/oracle/user_projects/domains/base_domain

# With JSON output
bash checks/application/Test-Weblogic-3/V-235929.sh \
  --domain-home /u01/oracle/user_projects/domains/base_domain \
  --output-json results/V-235929.json

```

**NIST SP 800-53 Rev 4:** AC-17 (2)

--------------------------------------------------------------------------------

#### V-235930 - WBLC-01-000011
**Severity:** MEDIUM

**Rule Title:** Oracle WebLogic must employ automated mechanisms to facilitate the monitoring and control of remote access methods.

**Automation Status:** Automatable

**Automation Method:** Bash/Python (config.xml parsing)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python/powershell)

**Requires Elevation:** Yes (WebLogic Admin credentials)

**Notes:**
- Admin Console check - can be automated via native tools (bash/python parsing config.xml)

**Check Content:**
```
1. Access EM 
2. Select the domain from the navigation tree, and use the dropdown to select 'WebLogic Domain' -> 'JDBC Data Sources' 
3. From the list of data sources, select the one named 'opss-audit-DBDS', which connects to the IAU_APPEND schema of the audit database. Note the value in the 'JNDI name' field.
4. To verify, select 'Configuration' tab -> 'Connection Pool' tab 
5. Ensure the 'URL' and 'Properties' fields contain the correct connection values for the IAU_APPEND schema
6. To test, s...
```
**Execution Command:**
```bash
# Option 1: Bash (Preferred - No third-party tools)
bash checks/application/Test-Weblogic-3/V-235930.sh \
  --domain-home /u01/oracle/user_projects/domains/base_domain

# Option 2: Python (Fallback - No third-party tools)
python3 checks/application/Test-Weblogic-3/V-235930.py \
  --domain-home /u01/oracle/user_projects/domains/base_domain

# With JSON output
bash checks/application/Test-Weblogic-3/V-235930.sh \
  --domain-home /u01/oracle/user_projects/domains/base_domain \
  --output-json results/V-235930.json

```

**NIST SP 800-53 Rev 4:** AC-17 (1)

--------------------------------------------------------------------------------

#### V-235932 - WBLC-01-000014
**Severity:** MEDIUM

**Rule Title:** Oracle WebLogic must support the capability to disable network protocols deemed by the organization to be non-secure except for explicitly identified components in support of specific operational requirements.

**Automation Status:** Automatable

**Automation Method:** WLST (WebLogic Scripting Tool) or Bash/Python

**Preferred Tool:** Bash/Python (preferred), WLST (fallback)

**⚠️ Third-Party Tools Required:**
- WLST - Oracle WebLogic Scripting Tool (optional if bash/python can check)

**Requires Elevation:** Yes (WebLogic Admin credentials)

**🔧 Configuration Dependencies:**
- ⚠️ **ENVIRONMENT-SPECIFIC**: This check requires site-specific or organizational values

**Notes:**
- Admin Console/EM check - prefer native tools, use WLST if needed

**Environment/System Annotations:**
- Environment-specific: Contains "approved"
- Environment-specific: Contains "organizational"

**Check Content:**
```
1. Access EM 
2. Select the domain from the navigation tree, and use the dropdown to select 'WebLogic Domain' -> 'Monitoring' -> 'Port Usage' 
3. In the results table, ensure values in the 'Port in Use' column match approved ports
4. In the results table, ensure values in the 'Protocol' column match approved protocols

If ports or protocols are in use that the organization deems nonsecure, this is a finding.
```
**Execution Command:**
```bash
# Option 1: Bash (Preferred - No third-party tools)
bash checks/application/Test-Weblogic-3/V-235932.sh \
  --domain-home /u01/oracle/user_projects/domains/base_domain

# Option 2: Python (Fallback - No third-party tools)
python3 checks/application/Test-Weblogic-3/V-235932.py \
  --domain-home /u01/oracle/user_projects/domains/base_domain

# With JSON output
bash checks/application/Test-Weblogic-3/V-235932.sh \
  --domain-home /u01/oracle/user_projects/domains/base_domain \
  --output-json results/V-235932.json

# Option 3: WLST (Third-party - use if native tools insufficient)
# Requires: Oracle WebLogic Scripting Tool (WLST)
wlst.sh checks/application/Test-Weblogic-1/V-235932.py \
  --admin-url t3://localhost:7001 \
  --username weblogic \
  --password <password>
```

**NIST SP 800-53 Rev 4:** CM-7 b

--------------------------------------------------------------------------------

#### V-235933 - WBLC-01-000018
**Severity:** MEDIUM

**Rule Title:** Oracle WebLogic must automatically audit account creation.

**Automation Status:** Automatable

**Automation Method:** Bash/Python (config.xml parsing)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python/powershell)

**Requires Elevation:** Yes (WebLogic Admin credentials)

**Notes:**
- Admin Console check - can be automated via native tools (bash/python parsing config.xml)

**Check Content:**
```
1. Access AC
2. From 'Domain Structure', select 'Security Realms'
3. Select realm to configure (default is 'myrealm')
4. Select 'Providers' tab -> 'Auditing' tab
5. Ensure the list of 'Auditing Providers' contains at least one Auditing Provider
6. From 'Domain Structure', select the top-level domain link
7. Click 'Advanced' near the bottom of the page
8. Ensure 'Configuration Audit Type' is set to 'Change Log and Audit'

If the 'Configuration Audit Type' is not set to 'Change Log and Audit', thi...
```
**Execution Command:**
```bash
# Option 1: Bash (Preferred - No third-party tools)
bash checks/application/Test-Weblogic-3/V-235933.sh \
  --domain-home /u01/oracle/user_projects/domains/base_domain

# Option 2: Python (Fallback - No third-party tools)
python3 checks/application/Test-Weblogic-3/V-235933.py \
  --domain-home /u01/oracle/user_projects/domains/base_domain

# With JSON output
bash checks/application/Test-Weblogic-3/V-235933.sh \
  --domain-home /u01/oracle/user_projects/domains/base_domain \
  --output-json results/V-235933.json

```

**NIST SP 800-53 Rev 4:** AC-2 (4)

--------------------------------------------------------------------------------

#### V-235934 - WBLC-01-000019
**Severity:** MEDIUM

**Rule Title:** Oracle WebLogic must automatically audit account modification.

**Automation Status:** Automatable

**Automation Method:** Bash/Python (config.xml parsing)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python/powershell)

**Requires Elevation:** Yes (WebLogic Admin credentials)

**Notes:**
- Admin Console check - can be automated via native tools (bash/python parsing config.xml)

**Check Content:**
```
1. Access AC
2. From 'Domain Structure', select 'Security Realms'
3. Select realm to configure (default is 'myrealm')
4. Select 'Providers' tab -> 'Auditing' tab
5. Ensure the list of 'Auditing Providers' contains at least one Auditing Provider
6. From 'Domain Structure', select the top-level domain link
7. Click 'Advanced' near the bottom of the page
8. Ensure 'Configuration Audit Type' is set to 'Change Log and Audit'

If the 'Configuration Audit Type' is not set to 'Change Log and Audit', thi...
```
**Execution Command:**
```bash
# Option 1: Bash (Preferred - No third-party tools)
bash checks/application/Test-Weblogic-3/V-235934.sh \
  --domain-home /u01/oracle/user_projects/domains/base_domain

# Option 2: Python (Fallback - No third-party tools)
python3 checks/application/Test-Weblogic-3/V-235934.py \
  --domain-home /u01/oracle/user_projects/domains/base_domain

# With JSON output
bash checks/application/Test-Weblogic-3/V-235934.sh \
  --domain-home /u01/oracle/user_projects/domains/base_domain \
  --output-json results/V-235934.json

```

**NIST SP 800-53 Rev 4:** AC-2 (4)

--------------------------------------------------------------------------------

#### V-235937 - WBLC-01-000033
**Severity:** MEDIUM

**Rule Title:** Oracle WebLogic must enforce the organization-defined time period during which the limit of consecutive invalid access attempts by a user is counted.

**Automation Status:** Automatable

**Automation Method:** Bash/Python (config.xml parsing)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python/powershell)

**Requires Elevation:** Yes (WebLogic Admin credentials)

**🔧 Configuration Dependencies:**
- ⚠️ **ENVIRONMENT-SPECIFIC**: This check requires site-specific or organizational values

**Notes:**
- Admin Console check - can be automated via native tools (bash/python parsing config.xml)

**Environment/System Annotations:**
- Environment-specific: Contains "authorized"

**Check Content:**
```
1. Access AC
2. From 'Domain Structure', select 'Security Realms'
3. Select realm to configure (default is 'myrealm')
4. Select 'Configuration' tab -> 'User Lockout' tab
5. Ensure the following field values are set:
'Lockout Threshold' = 3
'Lockout Duration' = 15
'Lockout Reset Duration' = 15

If 'Lockout Threshold' is not set to 3 or 'Lockout Duration' is not set to 15 or 'Lockout Reset Duration' is not set to 15, this is a finding.
```
**Execution Command:**
```bash
# Option 1: Bash (Preferred - No third-party tools)
bash checks/application/Test-Weblogic-3/V-235937.sh \
  --domain-home /u01/oracle/user_projects/domains/base_domain

# Option 2: Python (Fallback - No third-party tools)
python3 checks/application/Test-Weblogic-3/V-235937.py \
  --domain-home /u01/oracle/user_projects/domains/base_domain

# With JSON output
bash checks/application/Test-Weblogic-3/V-235937.sh \
  --domain-home /u01/oracle/user_projects/domains/base_domain \
  --output-json results/V-235937.json

```

**NIST SP 800-53 Rev 4:** CM-6 b

--------------------------------------------------------------------------------

#### V-235940 - WBLC-02-000065
**Severity:** LOW

**Rule Title:** Oracle WebLogic must compile audit records from multiple components within the system into a system-wide (logical or physical) audit trail that is time-correlated to within an organization-defined level of tolerance.

**Automation Status:** Automatable

**Automation Method:** Bash/Python (config.xml parsing)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python/powershell)

**Requires Elevation:** Yes (WebLogic Admin credentials)

**Notes:**
- Admin Console check - can be automated via native tools (bash/python parsing config.xml)

**Check Content:**
```
1. Access EM 
2. Select the domain from the navigation tree, and use the dropdown to select 'WebLogic Domain' -> 'JDBC Data Sources' 
3. From the list of data sources, select the one named 'opss-audit-DBDS', which connects to the IAU_APPEND schema of the audit database. Note the value in the 'JNDI name' field.
4. To verify, select 'Configuration' tab -> 'Connection Pool' tab 
5. Ensure the 'URL' and 'Properties' fields contain the correct connection values for the IAU_APPEND schema
6. To test, s...
```
**Execution Command:**
```bash
# Option 1: Bash (Preferred - No third-party tools)
bash checks/application/Test-Weblogic-3/V-235940.sh \
  --domain-home /u01/oracle/user_projects/domains/base_domain

# Option 2: Python (Fallback - No third-party tools)
python3 checks/application/Test-Weblogic-3/V-235940.py \
  --domain-home /u01/oracle/user_projects/domains/base_domain

# With JSON output
bash checks/application/Test-Weblogic-3/V-235940.sh \
  --domain-home /u01/oracle/user_projects/domains/base_domain \
  --output-json results/V-235940.json

```

**NIST SP 800-53 Rev 4:** AU-12 (1)

--------------------------------------------------------------------------------

#### V-235941 - WBLC-02-000069
**Severity:** LOW

**Rule Title:** Oracle WebLogic must generate audit records for the DoD-selected list of auditable events.

**Automation Status:** Automatable

**Automation Method:** WLST (WebLogic Scripting Tool) or Bash/Python

**Preferred Tool:** Bash/Python (preferred), WLST (fallback)

**⚠️ Third-Party Tools Required:**
- WLST - Oracle WebLogic Scripting Tool (optional if bash/python can check)

**Requires Elevation:** Yes (WebLogic Admin credentials)

**Notes:**
- Admin Console/EM check - prefer native tools, use WLST if needed

**Check Content:**
```
1. Access EM 
2. Select the domain from the navigation tree, and use the dropdown to select 'WebLogic Domain' -> 'Logs' -> 'View Log Messages'
3. Within the 'Search' panel, expand 'Selected Targets'
4. Click 'Target Log Files' icon for 'AdminServer' target
5. From the list of log files, select 'access.log' and click 'View Log File' button
6. All HTTPD, JVM, AS process event and other logging of the AdminServer will be displayed
7. Repeat for each managed server

If there are no events being logg...
```
**Execution Command:**
```bash
# Option 1: Bash (Preferred - No third-party tools)
bash checks/application/Test-Weblogic-3/V-235941.sh \
  --domain-home /u01/oracle/user_projects/domains/base_domain

# Option 2: Python (Fallback - No third-party tools)
python3 checks/application/Test-Weblogic-3/V-235941.py \
  --domain-home /u01/oracle/user_projects/domains/base_domain

# With JSON output
bash checks/application/Test-Weblogic-3/V-235941.sh \
  --domain-home /u01/oracle/user_projects/domains/base_domain \
  --output-json results/V-235941.json

# Option 3: WLST (Third-party - use if native tools insufficient)
# Requires: Oracle WebLogic Scripting Tool (WLST)
wlst.sh checks/application/Test-Weblogic-1/V-235941.py \
  --admin-url t3://localhost:7001 \
  --username weblogic \
  --password <password>
```

**NIST SP 800-53 Rev 4:** AU-12 c

--------------------------------------------------------------------------------

#### V-235942 - WBLC-02-000073
**Severity:** LOW

**Rule Title:** Oracle WebLogic must produce process events and severity levels to establish what type of HTTPD-related events and severity levels occurred.

**Automation Status:** Automatable

**Automation Method:** WLST (WebLogic Scripting Tool) or Bash/Python

**Preferred Tool:** Bash/Python (preferred), WLST (fallback)

**⚠️ Third-Party Tools Required:**
- WLST - Oracle WebLogic Scripting Tool (optional if bash/python can check)

**Requires Elevation:** Yes (WebLogic Admin credentials)

**Notes:**
- Admin Console/EM check - prefer native tools, use WLST if needed

**Check Content:**
```
1. Access EM 
2. Select the domain from the navigation tree, and use the dropdown to select 'WebLogic Domain' -> 'Logs' -> 'View Log Messages'
3. Within the 'Search' panel, expand 'Selected Targets'
4. Click 'Target Log Files' icon for 'AdminServer' target
5. From the list of log files, select 'access.log' and click 'View Log File' button
6. All HTTPD logging of the AdminServer will be displayed
7. Repeat for each managed server

If any managed server or the AdminServer does not have HTTPD event...
```
**Execution Command:**
```bash
# Option 1: Bash (Preferred - No third-party tools)
bash checks/application/Test-Weblogic-3/V-235942.sh \
  --domain-home /u01/oracle/user_projects/domains/base_domain

# Option 2: Python (Fallback - No third-party tools)
python3 checks/application/Test-Weblogic-3/V-235942.py \
  --domain-home /u01/oracle/user_projects/domains/base_domain

# With JSON output
bash checks/application/Test-Weblogic-3/V-235942.sh \
  --domain-home /u01/oracle/user_projects/domains/base_domain \
  --output-json results/V-235942.json

# Option 3: WLST (Third-party - use if native tools insufficient)
# Requires: Oracle WebLogic Scripting Tool (WLST)
wlst.sh checks/application/Test-Weblogic-1/V-235942.py \
  --admin-url t3://localhost:7001 \
  --username weblogic \
  --password <password>
```

**NIST SP 800-53 Rev 4:** AU-3

--------------------------------------------------------------------------------

#### V-235943 - WBLC-02-000074
**Severity:** LOW

**Rule Title:** Oracle WebLogic must produce audit records containing sufficient information to establish what type of JVM-related events and severity levels occurred.

**Automation Status:** Automatable

**Automation Method:** WLST (WebLogic Scripting Tool) or Bash/Python

**Preferred Tool:** Bash/Python (preferred), WLST (fallback)

**⚠️ Third-Party Tools Required:**
- WLST - Oracle WebLogic Scripting Tool (optional if bash/python can check)

**Requires Elevation:** Yes (WebLogic Admin credentials)

**Notes:**
- Admin Console/EM check - prefer native tools, use WLST if needed

**Check Content:**
```
1. Access EM 
2. Select the domain from the navigation tree, and use the dropdown to select 'WebLogic Domain' -> 'Logs' -> 'View Log Messages'
3. Within the 'Search' panel, expand 'Selected Targets'
4. Click 'Target Log Files' icon for 'AdminServer' target
5. From the list of log files, select '<server-name>-diagnostic.log' and click 'View Log File' button
6. All JVM logging of the AdminServer will be displayed
7. Repeat for each managed server

If there are no JVM-related events for the managed...
```
**Execution Command:**
```bash
# Option 1: Bash (Preferred - No third-party tools)
bash checks/application/Test-Weblogic-3/V-235943.sh \
  --domain-home /u01/oracle/user_projects/domains/base_domain

# Option 2: Python (Fallback - No third-party tools)
python3 checks/application/Test-Weblogic-3/V-235943.py \
  --domain-home /u01/oracle/user_projects/domains/base_domain

# With JSON output
bash checks/application/Test-Weblogic-3/V-235943.sh \
  --domain-home /u01/oracle/user_projects/domains/base_domain \
  --output-json results/V-235943.json

# Option 3: WLST (Third-party - use if native tools insufficient)
# Requires: Oracle WebLogic Scripting Tool (WLST)
wlst.sh checks/application/Test-Weblogic-1/V-235943.py \
  --admin-url t3://localhost:7001 \
  --username weblogic \
  --password <password>
```

**NIST SP 800-53 Rev 4:** AU-3

--------------------------------------------------------------------------------

#### V-235944 - WBLC-02-000075
**Severity:** LOW

**Rule Title:** Oracle WebLogic must produce process events and security levels to establish what type of Oracle WebLogic process events and severity levels occurred.

**Automation Status:** Automatable

**Automation Method:** WLST (WebLogic Scripting Tool) or Bash/Python

**Preferred Tool:** Bash/Python (preferred), WLST (fallback)

**⚠️ Third-Party Tools Required:**
- WLST - Oracle WebLogic Scripting Tool (optional if bash/python can check)

**Requires Elevation:** Yes (WebLogic Admin credentials)

**Notes:**
- Admin Console/EM check - prefer native tools, use WLST if needed

**Check Content:**
```
1. Access EM 
2. Select the domain from the navigation tree, and use the dropdown to select 'WebLogic Domain' -> 'Logs' -> 'View Log Messages'
3. Within the 'Search' panel, expand 'Selected Targets'
4. Click 'Target Log Files' icon for 'AdminServer' target
5. From the list of log files, select '<server-name>.log' and click 'View Log File' button
6. All AS process logging of the AdminServer will be displayed
7. Repeat for each managed server

If the managed servers or AdminServer does not have pr...
```
**Execution Command:**
```bash
# Option 1: Bash (Preferred - No third-party tools)
bash checks/application/Test-Weblogic-3/V-235944.sh \
  --domain-home /u01/oracle/user_projects/domains/base_domain

# Option 2: Python (Fallback - No third-party tools)
python3 checks/application/Test-Weblogic-3/V-235944.py \
  --domain-home /u01/oracle/user_projects/domains/base_domain

# With JSON output
bash checks/application/Test-Weblogic-3/V-235944.sh \
  --domain-home /u01/oracle/user_projects/domains/base_domain \
  --output-json results/V-235944.json

# Option 3: WLST (Third-party - use if native tools insufficient)
# Requires: Oracle WebLogic Scripting Tool (WLST)
wlst.sh checks/application/Test-Weblogic-1/V-235944.py \
  --admin-url t3://localhost:7001 \
  --username weblogic \
  --password <password>
```

**NIST SP 800-53 Rev 4:** AU-3

--------------------------------------------------------------------------------

#### V-235945 - WBLC-02-000076
**Severity:** LOW

**Rule Title:** Oracle WebLogic must produce audit records containing sufficient information to establish when (date and time) the events occurred.

**Automation Status:** Automatable

**Automation Method:** WLST (WebLogic Scripting Tool) or Bash/Python

**Preferred Tool:** Bash/Python (preferred), WLST (fallback)

**⚠️ Third-Party Tools Required:**
- WLST - Oracle WebLogic Scripting Tool (optional if bash/python can check)

**Requires Elevation:** Yes (WebLogic Admin credentials)

**Notes:**
- Admin Console/EM check - prefer native tools, use WLST if needed

**Check Content:**
```
1. Access EM 
2. Select the domain from the navigation tree, and use the dropdown to select 'WebLogic Domain' -> 'Logs' -> 'View Log Messages'
3. Within the 'Search' panel, expand 'Selected Targets'
4. Click 'Target Log Files' icon for any of the managed server or 'Application Deployment' type targets (not AdminServer)
5. From the list of log files, select '<server-name>.log', 'access.log' or '<server-name>-diagnostic.log' and click 'View Log File' button
6. Time stamp of audit event will be dis...
```
**Execution Command:**
```bash
# Option 1: Bash (Preferred - No third-party tools)
bash checks/application/Test-Weblogic-3/V-235945.sh \
  --domain-home /u01/oracle/user_projects/domains/base_domain

# Option 2: Python (Fallback - No third-party tools)
python3 checks/application/Test-Weblogic-3/V-235945.py \
  --domain-home /u01/oracle/user_projects/domains/base_domain

# With JSON output
bash checks/application/Test-Weblogic-3/V-235945.sh \
  --domain-home /u01/oracle/user_projects/domains/base_domain \
  --output-json results/V-235945.json

# Option 3: WLST (Third-party - use if native tools insufficient)
# Requires: Oracle WebLogic Scripting Tool (WLST)
wlst.sh checks/application/Test-Weblogic-1/V-235945.py \
  --admin-url t3://localhost:7001 \
  --username weblogic \
  --password <password>
```

**NIST SP 800-53 Rev 4:** AU-3

--------------------------------------------------------------------------------

#### V-235946 - WBLC-02-000077
**Severity:** LOW

**Rule Title:** Oracle WebLogic must produce audit records containing sufficient information to establish where the events occurred.

**Automation Status:** Automatable

**Automation Method:** WLST (WebLogic Scripting Tool) or Bash/Python

**Preferred Tool:** Bash/Python (preferred), WLST (fallback)

**⚠️ Third-Party Tools Required:**
- WLST - Oracle WebLogic Scripting Tool (optional if bash/python can check)

**Requires Elevation:** Yes (WebLogic Admin credentials)

**Notes:**
- Admin Console/EM check - prefer native tools, use WLST if needed

**Check Content:**
```
1. Access EM 
2. Select the domain from the navigation tree, and use the dropdown to select 'WebLogic Domain' -> 'Logs' -> 'View Log Messages'
3. Within the 'Search' panel, expand 'Selected Targets'
4. Click 'Target Log Files' icon for any of the managed server or 'Application Deployment' type targets (not AdminServer)
5. From the list of log files, select '<server-name>.log', 'access.log' or '<server-name>-diagnostic.log' and click 'View Log File' button
6. Select any record which appears in th...
```
**Execution Command:**
```bash
# Option 1: Bash (Preferred - No third-party tools)
bash checks/application/Test-Weblogic-3/V-235946.sh \
  --domain-home /u01/oracle/user_projects/domains/base_domain

# Option 2: Python (Fallback - No third-party tools)
python3 checks/application/Test-Weblogic-3/V-235946.py \
  --domain-home /u01/oracle/user_projects/domains/base_domain

# With JSON output
bash checks/application/Test-Weblogic-3/V-235946.sh \
  --domain-home /u01/oracle/user_projects/domains/base_domain \
  --output-json results/V-235946.json

# Option 3: WLST (Third-party - use if native tools insufficient)
# Requires: Oracle WebLogic Scripting Tool (WLST)
wlst.sh checks/application/Test-Weblogic-1/V-235946.py \
  --admin-url t3://localhost:7001 \
  --username weblogic \
  --password <password>
```

**NIST SP 800-53 Rev 4:** AU-3

--------------------------------------------------------------------------------

#### V-235947 - WBLC-02-000078
**Severity:** LOW

**Rule Title:** Oracle WebLogic must produce audit records containing sufficient information to establish the sources of the events.

**Automation Status:** Automatable

**Automation Method:** WLST (WebLogic Scripting Tool) or Bash/Python

**Preferred Tool:** Bash/Python (preferred), WLST (fallback)

**⚠️ Third-Party Tools Required:**
- WLST - Oracle WebLogic Scripting Tool (optional if bash/python can check)

**Requires Elevation:** Yes (WebLogic Admin credentials)

**Notes:**
- Admin Console/EM check - prefer native tools, use WLST if needed

**Check Content:**
```
1. Access EM 
2. Select the domain from the navigation tree, and use the dropdown to select 'WebLogic Domain' -> 'Logs' -> 'View Log Messages'
3. Within the 'Search' panel, expand 'Selected Targets'
4. Click 'Target Log Files' icon for any of the managed server or 'Application Deployment' type targets (not AdminServer)
5. From the list of log files, select '<server-name>.log', 'access.log' or '<server-name>-diagnostic.log' and click 'View Log File' button
6. Select any record which appears in th...
```
**Execution Command:**
```bash
# Option 1: Bash (Preferred - No third-party tools)
bash checks/application/Test-Weblogic-3/V-235947.sh \
  --domain-home /u01/oracle/user_projects/domains/base_domain

# Option 2: Python (Fallback - No third-party tools)
python3 checks/application/Test-Weblogic-3/V-235947.py \
  --domain-home /u01/oracle/user_projects/domains/base_domain

# With JSON output
bash checks/application/Test-Weblogic-3/V-235947.sh \
  --domain-home /u01/oracle/user_projects/domains/base_domain \
  --output-json results/V-235947.json

# Option 3: WLST (Third-party - use if native tools insufficient)
# Requires: Oracle WebLogic Scripting Tool (WLST)
wlst.sh checks/application/Test-Weblogic-1/V-235947.py \
  --admin-url t3://localhost:7001 \
  --username weblogic \
  --password <password>
```

**NIST SP 800-53 Rev 4:** AU-3

--------------------------------------------------------------------------------

#### V-235948 - WBLC-02-000079
**Severity:** LOW

**Rule Title:** Oracle WebLogic must produce audit records that contain sufficient information to establish the outcome (success or failure) of application server and application events.

**Automation Status:** Automatable

**Automation Method:** WLST (WebLogic Scripting Tool) or Bash/Python

**Preferred Tool:** Bash/Python (preferred), WLST (fallback)

**⚠️ Third-Party Tools Required:**
- WLST - Oracle WebLogic Scripting Tool (optional if bash/python can check)

**Requires Elevation:** Yes (WebLogic Admin credentials)

**🔧 Configuration Dependencies:**
- ⚠️ **ENVIRONMENT-SPECIFIC**: This check requires site-specific or organizational values

**Notes:**
- Admin Console/EM check - prefer native tools, use WLST if needed

**Environment/System Annotations:**
- Environment-specific: Contains "authorized"

**Check Content:**
```
1. Access EM 
2. Select the domain from the navigation tree, and use the dropdown to select 'WebLogic Domain' -> 'Logs' -> 'View Log Messages'
3. Within the 'Search' panel, expand 'Selected Targets'
4. Click 'Target Log Files' icon for any of the managed server or 'Application Deployment' type targets (not AdminServer)
5. From the list of log files, select '<server-name>.log', 'access.log' or '<server-name>-diagnostic.log' and click 'View Log File' button
6. Outcome of audit event will be displa...
```
**Execution Command:**
```bash
# Option 1: Bash (Preferred - No third-party tools)
bash checks/application/Test-Weblogic-3/V-235948.sh \
  --domain-home /u01/oracle/user_projects/domains/base_domain

# Option 2: Python (Fallback - No third-party tools)
python3 checks/application/Test-Weblogic-3/V-235948.py \
  --domain-home /u01/oracle/user_projects/domains/base_domain

# With JSON output
bash checks/application/Test-Weblogic-3/V-235948.sh \
  --domain-home /u01/oracle/user_projects/domains/base_domain \
  --output-json results/V-235948.json

# Option 3: WLST (Third-party - use if native tools insufficient)
# Requires: Oracle WebLogic Scripting Tool (WLST)
wlst.sh checks/application/Test-Weblogic-1/V-235948.py \
  --admin-url t3://localhost:7001 \
  --username weblogic \
  --password <password>
```

**NIST SP 800-53 Rev 4:** AU-3

--------------------------------------------------------------------------------

#### V-235949 - WBLC-02-000080
**Severity:** MEDIUM

**Rule Title:** Oracle WebLogic must produce audit records containing sufficient information to establish the identity of any user/subject or process associated with the event.

**Automation Status:** Automatable

**Automation Method:** WLST (WebLogic Scripting Tool) or Bash/Python

**Preferred Tool:** Bash/Python (preferred), WLST (fallback)

**⚠️ Third-Party Tools Required:**
- WLST - Oracle WebLogic Scripting Tool (optional if bash/python can check)

**Requires Elevation:** Yes (WebLogic Admin credentials)

**Notes:**
- Admin Console/EM check - prefer native tools, use WLST if needed

**Check Content:**
```
1. Access EM 
2. Select the domain from the navigation tree, and use the dropdown to select 'WebLogic Domain' -> 'Logs' -> 'View Log Messages'
3. Within the 'Search' panel, expand 'Selected Targets'
4. Click 'Target Log Files' icon for any of the managed server or 'Application Deployment' type targets (not AdminServer)
5. From the list of log files, select '<server-name>.log', 'access.log' or '<server-name>-diagnostic.log' and click 'View Log File' button
6. User or process associated with audit...
```
**Execution Command:**
```bash
# Option 1: Bash (Preferred - No third-party tools)
bash checks/application/Test-Weblogic-3/V-235949.sh \
  --domain-home /u01/oracle/user_projects/domains/base_domain

# Option 2: Python (Fallback - No third-party tools)
python3 checks/application/Test-Weblogic-3/V-235949.py \
  --domain-home /u01/oracle/user_projects/domains/base_domain

# With JSON output
bash checks/application/Test-Weblogic-3/V-235949.sh \
  --domain-home /u01/oracle/user_projects/domains/base_domain \
  --output-json results/V-235949.json

# Option 3: WLST (Third-party - use if native tools insufficient)
# Requires: Oracle WebLogic Scripting Tool (WLST)
wlst.sh checks/application/Test-Weblogic-1/V-235949.py \
  --admin-url t3://localhost:7001 \
  --username weblogic \
  --password <password>
```

**NIST SP 800-53 Rev 4:** AU-3

--------------------------------------------------------------------------------

#### V-235950 - WBLC-02-000081
**Severity:** MEDIUM

**Rule Title:** Oracle WebLogic must provide the ability to write specified audit record content to an audit log server.

**Automation Status:** Automatable

**Automation Method:** Bash/Python (config.xml parsing)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python/powershell)

**Requires Elevation:** Yes (WebLogic Admin credentials)

**Notes:**
- Admin Console check - can be automated via native tools (bash/python parsing config.xml)

**Check Content:**
```
1. Access EM 
2. Select the domain from the navigation tree, and use the dropdown to select 'WebLogic Domain' -> 'JDBC Data Sources' 
3. From the list of data sources, select the one named 'opss-audit-DBDS', which connects to the IAU_APPEND schema of the audit database. Note the value in the 'JNDI name' field
4. To verify, select 'Configuration' tab -> 'Connection Pool' tab 
5. Ensure the 'URL' and 'Properties' fields contain the correct connection values for the IAU_APPEND schema
6. To test, se...
```
**Execution Command:**
```bash
# Option 1: Bash (Preferred - No third-party tools)
bash checks/application/Test-Weblogic-3/V-235950.sh \
  --domain-home /u01/oracle/user_projects/domains/base_domain

# Option 2: Python (Fallback - No third-party tools)
python3 checks/application/Test-Weblogic-3/V-235950.py \
  --domain-home /u01/oracle/user_projects/domains/base_domain

# With JSON output
bash checks/application/Test-Weblogic-3/V-235950.sh \
  --domain-home /u01/oracle/user_projects/domains/base_domain \
  --output-json results/V-235950.json

```

**NIST SP 800-53 Rev 4:** AU-4 (1)

--------------------------------------------------------------------------------

#### V-235951 - WBLC-02-000083
**Severity:** LOW

**Rule Title:** Oracle WebLogic must provide a real-time alert when organization-defined audit failure events occur.

**Automation Status:** Automatable

**Automation Method:** Bash/Python (config.xml parsing)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python/powershell)

**Requires Elevation:** Yes (WebLogic Admin credentials)

**🔧 Configuration Dependencies:**
- ⚠️ **ENVIRONMENT-SPECIFIC**: This check requires site-specific or organizational values
- ⚠️ **SYSTEM-SPECIFIC**: This check depends on deployment/installation-specific configuration

**Notes:**
- Admin Console check - can be automated via native tools (bash/python parsing config.xml)

**Environment/System Annotations:**
- Environment-specific: Contains "as needed"
- System-specific: Contains "custom"

**Check Content:**
```
1. Access AC
2. From 'Domain Structure', select 'Diagnostics' -> 'Diagnostic Modules' 
3. Select 'Module-HealthState' from 'Diagnostic System Modules' list
4. Select 'Configuration' tab -> 'Watches and Notifications' tab. Select the 'Watches' tab from the bottom of page
5. Ensure 'ServerHealthWatch' row has 'Enabled' column value set to 'true'
6. Select 'Configuration' tab -> 'Watches and Notifications' tab. Select the 'Notifications' tab from the bottom of page
7. Ensure 'ServerHealthNotificati...
```
**Execution Command:**
```bash
# Option 1: Bash (Preferred - No third-party tools)
bash checks/application/Test-Weblogic-3/V-235951.sh \
  --domain-home /u01/oracle/user_projects/domains/base_domain

# Option 2: Python (Fallback - No third-party tools)
python3 checks/application/Test-Weblogic-3/V-235951.py \
  --domain-home /u01/oracle/user_projects/domains/base_domain

# With JSON output
bash checks/application/Test-Weblogic-3/V-235951.sh \
  --domain-home /u01/oracle/user_projects/domains/base_domain \
  --output-json results/V-235951.json

```

**NIST SP 800-53 Rev 4:** AU-5 a

--------------------------------------------------------------------------------

#### V-235952 - WBLC-02-000084
**Severity:** LOW

**Rule Title:** Oracle WebLogic must alert designated individual organizational officials in the event of an audit processing failure.

**Automation Status:** Automatable

**Automation Method:** Bash/Python (config.xml parsing)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python/powershell)

**Requires Elevation:** Yes (WebLogic Admin credentials)

**🔧 Configuration Dependencies:**
- ⚠️ **ENVIRONMENT-SPECIFIC**: This check requires site-specific or organizational values
- ⚠️ **SYSTEM-SPECIFIC**: This check depends on deployment/installation-specific configuration

**Notes:**
- Admin Console check - can be automated via native tools (bash/python parsing config.xml)

**Environment/System Annotations:**
- Environment-specific: Contains "designated"
- Environment-specific: Contains "as needed"
- System-specific: Contains "custom"

**Check Content:**
```
1. Access AC
2. From 'Domain Structure', select 'Diagnostics' -> 'Diagnostic Modules'
3. Select 'Module-HealthState' from 'Diagnostic System Modules' list
4. Select 'Configuration' tab -> 'Watches and Notifications' tab. Select the 'Watches' tab from the bottom of page
5. Ensure 'ServerHealthWatch' row has 'Enabled' column value set to 'true'
6. Select 'Configuration' tab -> 'Watches and Notifications' tab. Select the 'Notifications' tab from the bottom of page
7. Ensure 'ServerHealthNotificatio...
```
**Execution Command:**
```bash
# Option 1: Bash (Preferred - No third-party tools)
bash checks/application/Test-Weblogic-3/V-235952.sh \
  --domain-home /u01/oracle/user_projects/domains/base_domain

# Option 2: Python (Fallback - No third-party tools)
python3 checks/application/Test-Weblogic-3/V-235952.py \
  --domain-home /u01/oracle/user_projects/domains/base_domain

# With JSON output
bash checks/application/Test-Weblogic-3/V-235952.sh \
  --domain-home /u01/oracle/user_projects/domains/base_domain \
  --output-json results/V-235952.json

```

**NIST SP 800-53 Rev 4:** AU-5 a

--------------------------------------------------------------------------------

#### V-235953 - WBLC-02-000086
**Severity:** LOW

**Rule Title:** Oracle WebLogic must notify administrative personnel as a group in the event of audit processing failure.

**Automation Status:** Automatable

**Automation Method:** Bash/Python (config.xml parsing)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python/powershell)

**Requires Elevation:** Yes (WebLogic Admin credentials)

**🔧 Configuration Dependencies:**
- ⚠️ **ENVIRONMENT-SPECIFIC**: This check requires site-specific or organizational values
- ⚠️ **SYSTEM-SPECIFIC**: This check depends on deployment/installation-specific configuration

**Notes:**
- Admin Console check - can be automated via native tools (bash/python parsing config.xml)

**Environment/System Annotations:**
- Environment-specific: Contains "as needed"
- System-specific: Contains "custom"

**Check Content:**
```
1. Access AC
2. From 'Domain Structure', select 'Diagnostics' -> 'Diagnostic Modules' 
3. Select 'Module-HealthState' from 'Diagnostic System Modules' list
4. Select 'Configuration' tab -> 'Watches and Notifications' tab. Select the 'Watches' tab from the bottom of page
5. Ensure 'ServerHealthWatch' row has 'Enabled' column value set to 'true'
6. Select 'Configuration' tab -> 'Watches and Notifications' tab. Select the 'Notifications' tab from the bottom of page
7. Ensure 'ServerHealthNotificati...
```
**Execution Command:**
```bash
# Option 1: Bash (Preferred - No third-party tools)
bash checks/application/Test-Weblogic-3/V-235953.sh \
  --domain-home /u01/oracle/user_projects/domains/base_domain

# Option 2: Python (Fallback - No third-party tools)
python3 checks/application/Test-Weblogic-3/V-235953.py \
  --domain-home /u01/oracle/user_projects/domains/base_domain

# With JSON output
bash checks/application/Test-Weblogic-3/V-235953.sh \
  --domain-home /u01/oracle/user_projects/domains/base_domain \
  --output-json results/V-235953.json

```

**NIST SP 800-53 Rev 4:** AU-5 b

--------------------------------------------------------------------------------

#### V-235954 - WBLC-02-000093
**Severity:** LOW

**Rule Title:** Oracle WebLogic must use internal system clocks to generate time stamps for audit records.

**Automation Status:** Automatable

**Automation Method:** Bash/Python (config.xml parsing)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python/powershell)

**Requires Elevation:** Yes (WebLogic Admin credentials)

**🔧 Configuration Dependencies:**
- ⚠️ **ENVIRONMENT-SPECIFIC**: This check requires site-specific or organizational values

**Notes:**
- Admin Console check - can be automated via native tools (bash/python parsing config.xml)

**Environment/System Annotations:**
- Environment-specific: Contains "approved"

**Check Content:**
```
1. Access EM 
2. Select the domain from the navigation tree, and use the dropdown to select 'WebLogic Domain' -> 'Security' -> 'Security Provider Configuration' 
3. Beneath 'Audit Service' section, click 'Configure' button 
4. Ensure the 'Timezone Settings' radio button is set to 'UTC' so audit logs will be time stamped in Coordinated Universal Time regardless of the time zone of the underlying physical or virtual machine 
5. The time stamp will be recorded according to the operating system's se...
```
**Execution Command:**
```bash
# Option 1: Bash (Preferred - No third-party tools)
bash checks/application/Test-Weblogic-3/V-235954.sh \
  --domain-home /u01/oracle/user_projects/domains/base_domain

# Option 2: Python (Fallback - No third-party tools)
python3 checks/application/Test-Weblogic-3/V-235954.py \
  --domain-home /u01/oracle/user_projects/domains/base_domain

# With JSON output
bash checks/application/Test-Weblogic-3/V-235954.sh \
  --domain-home /u01/oracle/user_projects/domains/base_domain \
  --output-json results/V-235954.json

```

**NIST SP 800-53 Rev 4:** AU-8 a

--------------------------------------------------------------------------------

#### V-235955 - WBLC-02-000094
**Severity:** LOW

**Rule Title:** Oracle WebLogic must synchronize with internal information system clocks which, in turn, are synchronized on an organization-defined frequency with an organization-defined authoritative time source.

**Automation Status:** Automatable

**Automation Method:** Bash/Python (config.xml parsing)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python/powershell)

**Requires Elevation:** Yes (WebLogic Admin credentials)

**Notes:**
- Admin Console check - can be automated via native tools (bash/python parsing config.xml)

**Check Content:**
```
1. Access EM 
2. Select the domain from the navigation tree, and use the dropdown to select 'WebLogic Domain' -> 'Security' -> 'Security Provider Configuration' 
3. Beneath 'Audit Service' section, click 'Configure' button 
4. Ensure the 'Timezone Settings' radio button is set to 'UTC' so audit logs will be time stamped in Coordinated Universal Time regardless of the time zone of the underlying physical or virtual machine 
5. The time stamp will be recorded according to the operating system's se...
```
**Execution Command:**
```bash
# Option 1: Bash (Preferred - No third-party tools)
bash checks/application/Test-Weblogic-3/V-235955.sh \
  --domain-home /u01/oracle/user_projects/domains/base_domain

# Option 2: Python (Fallback - No third-party tools)
python3 checks/application/Test-Weblogic-3/V-235955.py \
  --domain-home /u01/oracle/user_projects/domains/base_domain

# With JSON output
bash checks/application/Test-Weblogic-3/V-235955.sh \
  --domain-home /u01/oracle/user_projects/domains/base_domain \
  --output-json results/V-235955.json

```

**NIST SP 800-53 Rev 4:** AU-8 (1) (b)

--------------------------------------------------------------------------------

#### V-235956 - WBLC-02-000095
**Severity:** LOW

**Rule Title:** Oracle WebLogic must protect audit information from any type of unauthorized read access.

**Automation Status:** Automatable

**Automation Method:** Bash/Python (config.xml parsing)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python/powershell)

**Requires Elevation:** Yes (WebLogic Admin credentials)

**🔧 Configuration Dependencies:**
- ⚠️ **ENVIRONMENT-SPECIFIC**: This check requires site-specific or organizational values

**Notes:**
- Admin Console check - can be automated via native tools (bash/python parsing config.xml)

**Environment/System Annotations:**
- Environment-specific: Contains "authorized"

**Check Content:**
```
1. Access AC
2. From 'Domain Structure', select 'Security Realms'
3. Select realm to configure (default is 'myrealm')
4. Select 'Users and Groups' tab -> 'Users' tab
5. From 'Users' table, select a user that must not have audit read access
6. From users settings page, select 'Groups' tab
7. Ensure the 'Chosen' table does not contain any of the following roles - 'Admin', 'Deployer', 'Monitor', 'Operator'
8. Repeat steps 5-7 for all users that must not have audit read access

If any users that sho...
```
**Execution Command:**
```bash
# Option 1: Bash (Preferred - No third-party tools)
bash checks/application/Test-Weblogic-3/V-235956.sh \
  --domain-home /u01/oracle/user_projects/domains/base_domain

# Option 2: Python (Fallback - No third-party tools)
python3 checks/application/Test-Weblogic-3/V-235956.py \
  --domain-home /u01/oracle/user_projects/domains/base_domain

# With JSON output
bash checks/application/Test-Weblogic-3/V-235956.sh \
  --domain-home /u01/oracle/user_projects/domains/base_domain \
  --output-json results/V-235956.json

```

**NIST SP 800-53 Rev 4:** AU-9

--------------------------------------------------------------------------------

#### V-235957 - WBLC-02-000098
**Severity:** MEDIUM

**Rule Title:** Oracle WebLogic must protect audit tools from unauthorized access.

**Automation Status:** Automatable

**Automation Method:** Bash/Python (config.xml parsing)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python/powershell)

**Requires Elevation:** Yes (WebLogic Admin credentials)

**🔧 Configuration Dependencies:**
- ⚠️ **ENVIRONMENT-SPECIFIC**: This check requires site-specific or organizational values

**Notes:**
- Admin Console check - can be automated via native tools (bash/python parsing config.xml)

**Environment/System Annotations:**
- Environment-specific: Contains "authorized"

**Check Content:**
```
1. Access AC
2. From 'Domain Structure', select 'Security Realms'
3. Select realm to configure (default is 'myrealm')
4. Select 'Users and Groups' tab -> 'Users' tab
5. From 'Users' table, select a user that must not have audit tool configuration access
6. From users settings page, select 'Groups' tab
7. Ensure the 'Chosen' table does not contain the role - 'Admin'
8. Repeat steps 5-7 for all users that must not have audit tool configuration access

If any users that should not have access to th...
```
**Execution Command:**
```bash
# Option 1: Bash (Preferred - No third-party tools)
bash checks/application/Test-Weblogic-3/V-235957.sh \
  --domain-home /u01/oracle/user_projects/domains/base_domain

# Option 2: Python (Fallback - No third-party tools)
python3 checks/application/Test-Weblogic-3/V-235957.py \
  --domain-home /u01/oracle/user_projects/domains/base_domain

# With JSON output
bash checks/application/Test-Weblogic-3/V-235957.sh \
  --domain-home /u01/oracle/user_projects/domains/base_domain \
  --output-json results/V-235957.json

```

**NIST SP 800-53 Rev 4:** AU-9

--------------------------------------------------------------------------------

#### V-235958 - WBLC-02-000099
**Severity:** MEDIUM

**Rule Title:** Oracle WebLogic must protect audit tools from unauthorized modification.

**Automation Status:** Automatable

**Automation Method:** Bash/Python (config.xml parsing)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python/powershell)

**Requires Elevation:** Yes (WebLogic Admin credentials)

**🔧 Configuration Dependencies:**
- ⚠️ **ENVIRONMENT-SPECIFIC**: This check requires site-specific or organizational values

**Notes:**
- Admin Console check - can be automated via native tools (bash/python parsing config.xml)

**Environment/System Annotations:**
- Environment-specific: Contains "authorized"

**Check Content:**
```
1. Access AC
2. From 'Domain Structure', select 'Security Realms'
3. Select realm to configure (default is 'myrealm')
4. Select 'Users and Groups' tab -> 'Users' tab
5. From 'Users' table, select a user that must not have audit tool configuration access
6. From users settings page, select 'Groups' tab
7. Ensure the 'Chosen' table does not contain the role - 'Admin'
8. Repeat steps 5-7 for all users that must not have audit tool configuration access

If any users that should not have access to th...
```
**Execution Command:**
```bash
# Option 1: Bash (Preferred - No third-party tools)
bash checks/application/Test-Weblogic-3/V-235958.sh \
  --domain-home /u01/oracle/user_projects/domains/base_domain

# Option 2: Python (Fallback - No third-party tools)
python3 checks/application/Test-Weblogic-3/V-235958.py \
  --domain-home /u01/oracle/user_projects/domains/base_domain

# With JSON output
bash checks/application/Test-Weblogic-3/V-235958.sh \
  --domain-home /u01/oracle/user_projects/domains/base_domain \
  --output-json results/V-235958.json

```

**NIST SP 800-53 Rev 4:** AU-9

--------------------------------------------------------------------------------

#### V-235959 - WBLC-02-000100
**Severity:** MEDIUM

**Rule Title:** Oracle WebLogic must protect audit tools from unauthorized deletion.

**Automation Status:** Automatable

**Automation Method:** Bash/Python (config.xml parsing)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python/powershell)

**Requires Elevation:** Yes (WebLogic Admin credentials)

**🔧 Configuration Dependencies:**
- ⚠️ **ENVIRONMENT-SPECIFIC**: This check requires site-specific or organizational values

**Notes:**
- Admin Console check - can be automated via native tools (bash/python parsing config.xml)

**Environment/System Annotations:**
- Environment-specific: Contains "authorized"

**Check Content:**
```
1. Access AC
2. From 'Domain Structure', select 'Security Realms'
3. Select realm to configure (default is 'myrealm')
4. Select 'Users and Groups' tab -> 'Users' tab
5. From 'Users' table, select a user that must not have audit tool configuration access
6. From users settings page, select 'Groups' tab
7. Ensure the 'Chosen' table does not contain the role - 'Admin'
8. Repeat steps 5-7 for all users that must not have audit tool configuration access

If any users that should not have access to th...
```
**Execution Command:**
```bash
# Option 1: Bash (Preferred - No third-party tools)
bash checks/application/Test-Weblogic-3/V-235959.sh \
  --domain-home /u01/oracle/user_projects/domains/base_domain

# Option 2: Python (Fallback - No third-party tools)
python3 checks/application/Test-Weblogic-3/V-235959.py \
  --domain-home /u01/oracle/user_projects/domains/base_domain

# With JSON output
bash checks/application/Test-Weblogic-3/V-235959.sh \
  --domain-home /u01/oracle/user_projects/domains/base_domain \
  --output-json results/V-235959.json

```

**NIST SP 800-53 Rev 4:** AU-9

--------------------------------------------------------------------------------

#### V-235960 - WBLC-03-000125
**Severity:** MEDIUM

**Rule Title:** Oracle WebLogic must limit privileges to change the software resident within software libraries (including privileged programs).

**Automation Status:** Automatable

**Automation Method:** Bash/Python (config.xml parsing)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python/powershell)

**Requires Elevation:** Yes (WebLogic Admin credentials)

**Notes:**
- Admin Console check - can be automated via native tools (bash/python parsing config.xml)

**Check Content:**
```
1. Access AC
2. From 'Domain Structure', select 'Security Realms'
3. Select realm to configure (default is 'myrealm')
4. Select 'Users and Groups' tab -> 'Users' tab
5. From 'Users' table, select a user that must not have shared library modification access
6. From users settings page, select 'Groups' tab
7. Ensure the 'Chosen' table does not contain the roles - 'Admin', 'Deployer'
8. Repeat steps 5-7 for all users that must not have shared library modification access

If any users that are not p...
```
**Execution Command:**
```bash
# Option 1: Bash (Preferred - No third-party tools)
bash checks/application/Test-Weblogic-3/V-235960.sh \
  --domain-home /u01/oracle/user_projects/domains/base_domain

# Option 2: Python (Fallback - No third-party tools)
python3 checks/application/Test-Weblogic-3/V-235960.py \
  --domain-home /u01/oracle/user_projects/domains/base_domain

# With JSON output
bash checks/application/Test-Weblogic-3/V-235960.sh \
  --domain-home /u01/oracle/user_projects/domains/base_domain \
  --output-json results/V-235960.json

```

**NIST SP 800-53 Rev 4:** CM-5 (6)

--------------------------------------------------------------------------------

#### V-235961 - WBLC-03-000127
**Severity:** MEDIUM

**Rule Title:** Oracle WebLogic must adhere to the principles of least functionality by providing only essential capabilities.

**Automation Status:** Automatable

**Automation Method:** Bash/Python (config.xml parsing)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python/powershell)

**Requires Elevation:** Yes (WebLogic Admin credentials)

**Notes:**
- Admin Console check - can be automated via native tools (bash/python parsing config.xml)

**Check Content:**
```
1. Access AC
2. From 'Domain Structure', select 'Deployments'
3. Select a deployment of type 'Web Application' from list of deployments
4. Select 'Configuration' tab -> 'General' tab
5. Ensure 'JSP Page Check' field value is set to '-1', which indicates JSP reloading is disabled within this deployment. Repeat steps 3-5 for all 'Web Application' type deployments
6. For every WebLogic resource within the domain, the 'Configuration' tab and associated subtabs provide the ability to disable or deact...
```
**Execution Command:**
```bash
# Option 1: Bash (Preferred - No third-party tools)
bash checks/application/Test-Weblogic-3/V-235961.sh \
  --domain-home /u01/oracle/user_projects/domains/base_domain

# Option 2: Python (Fallback - No third-party tools)
python3 checks/application/Test-Weblogic-3/V-235961.py \
  --domain-home /u01/oracle/user_projects/domains/base_domain

# With JSON output
bash checks/application/Test-Weblogic-3/V-235961.sh \
  --domain-home /u01/oracle/user_projects/domains/base_domain \
  --output-json results/V-235961.json

```

**NIST SP 800-53 Rev 4:** CM-7 a

--------------------------------------------------------------------------------

#### V-235962 - WBLC-03-000128
**Severity:** MEDIUM

**Rule Title:** Oracle WebLogic must prohibit or restrict the use of unauthorized functions, ports, protocols, and/or services.

**Automation Status:** Automatable

**Automation Method:** WLST (WebLogic Scripting Tool) or Bash/Python

**Preferred Tool:** Bash/Python (preferred), WLST (fallback)

**⚠️ Third-Party Tools Required:**
- WLST - Oracle WebLogic Scripting Tool (optional if bash/python can check)

**Requires Elevation:** Yes (WebLogic Admin credentials)

**🔧 Configuration Dependencies:**
- ⚠️ **ENVIRONMENT-SPECIFIC**: This check requires site-specific or organizational values

**Notes:**
- Admin Console/EM check - prefer native tools, use WLST if needed

**Environment/System Annotations:**
- Environment-specific: Contains "approved"
- Environment-specific: Contains "authorized"

**Check Content:**
```
1. Access EM 
2. Select the domain from the navigation tree, and use the dropdown to select 'WebLogic Domain' -> 'Monitoring' -> 'Port Usage' 
3. In the results table, ensure values in the 'Port in Use' column match approved ports
4. In the results table, ensure values in the 'Protocol' column match approved protocols

If any ports listed in the 'Port in Use' column is an unauthorized port or any protocols listed in the 'Protocol' column is an unauthorized protocol, this is a finding.
```
**Execution Command:**
```bash
# Option 1: Bash (Preferred - No third-party tools)
bash checks/application/Test-Weblogic-3/V-235962.sh \
  --domain-home /u01/oracle/user_projects/domains/base_domain

# Option 2: Python (Fallback - No third-party tools)
python3 checks/application/Test-Weblogic-3/V-235962.py \
  --domain-home /u01/oracle/user_projects/domains/base_domain

# With JSON output
bash checks/application/Test-Weblogic-3/V-235962.sh \
  --domain-home /u01/oracle/user_projects/domains/base_domain \
  --output-json results/V-235962.json

# Option 3: WLST (Third-party - use if native tools insufficient)
# Requires: Oracle WebLogic Scripting Tool (WLST)
wlst.sh checks/application/Test-Weblogic-1/V-235962.py \
  --admin-url t3://localhost:7001 \
  --username weblogic \
  --password <password>
```

**NIST SP 800-53 Rev 4:** CM-7 b

--------------------------------------------------------------------------------

#### V-235963 - WBLC-03-000129
**Severity:** LOW

**Rule Title:** Oracle WebLogic must utilize automated mechanisms to prevent program execution on the information system.

**Automation Status:** Automatable

**Automation Method:** Bash/Python (config.xml parsing)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python/powershell)

**Requires Elevation:** Yes (WebLogic Admin credentials)

**Notes:**
- Admin Console check - can be automated via native tools (bash/python parsing config.xml)

**Check Content:**
```
1. Access AC 
2. From 'Domain Structure', select the top-level domain 
3. Select 'Configuration' tab -> 'General' tab 
4. Ensure 'Production Mode' checkbox is selected

If the 'Production Mode' checkbox is not selected, this is a finding.
```
**Execution Command:**
```bash
# Option 1: Bash (Preferred - No third-party tools)
bash checks/application/Test-Weblogic-3/V-235963.sh \
  --domain-home /u01/oracle/user_projects/domains/base_domain

# Option 2: Python (Fallback - No third-party tools)
python3 checks/application/Test-Weblogic-3/V-235963.py \
  --domain-home /u01/oracle/user_projects/domains/base_domain

# With JSON output
bash checks/application/Test-Weblogic-3/V-235963.sh \
  --domain-home /u01/oracle/user_projects/domains/base_domain \
  --output-json results/V-235963.json

```

**NIST SP 800-53 Rev 4:** CM-6 b

--------------------------------------------------------------------------------

#### V-235964 - WBLC-05-000150
**Severity:** HIGH

**Rule Title:** Oracle WebLogic must uniquely identify and authenticate users (or processes acting on behalf of users).

**Automation Status:** Automatable

**Automation Method:** Bash/Python (config.xml parsing)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python/powershell)

**Requires Elevation:** Yes (WebLogic Admin credentials)

**🔧 Configuration Dependencies:**
- ⚠️ **ENVIRONMENT-SPECIFIC**: This check requires site-specific or organizational values

**Notes:**
- Admin Console check - can be automated via native tools (bash/python parsing config.xml)

**Environment/System Annotations:**
- Environment-specific: Contains "authorized"

**Check Content:**
```
1. Access AC
2. From 'Domain Structure', select 'Security Realms'
3. Select realm to configure (default is 'myrealm')
4. Select 'Providers' tab -> 'Authentication' tab
5. Ensure the list of 'Authentication Providers' contains at least one non-Default Authentication Provider
6. If the Authentication Provider is perimeter-based, ensure the list contains at least one non-Default IdentityAsserter

If the list of 'Authentication Providers' does not contain at least one non-Default Authentication Prov...
```
**Execution Command:**
```bash
# Option 1: Bash (Preferred - No third-party tools)
bash checks/application/Test-Weblogic-3/V-235964.sh \
  --domain-home /u01/oracle/user_projects/domains/base_domain

# Option 2: Python (Fallback - No third-party tools)
python3 checks/application/Test-Weblogic-3/V-235964.py \
  --domain-home /u01/oracle/user_projects/domains/base_domain

# With JSON output
bash checks/application/Test-Weblogic-3/V-235964.sh \
  --domain-home /u01/oracle/user_projects/domains/base_domain \
  --output-json results/V-235964.json

```

**NIST SP 800-53 Rev 4:** IA-2

--------------------------------------------------------------------------------

#### V-235965 - WBLC-05-000153
**Severity:** HIGH

**Rule Title:** Oracle WebLogic must authenticate users individually prior to using a group authenticator.

**Automation Status:** Automatable

**Automation Method:** Bash/Python (config.xml parsing)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python/powershell)

**Requires Elevation:** Yes (WebLogic Admin credentials)

**🔧 Configuration Dependencies:**
- ⚠️ **ENVIRONMENT-SPECIFIC**: This check requires site-specific or organizational values

**Notes:**
- Admin Console check - can be automated via native tools (bash/python parsing config.xml)

**Environment/System Annotations:**
- Environment-specific: Contains "authorized"

**Check Content:**
```
1. Access AC
2. From 'Domain Structure', select 'Security Realms'
3. Select realm to configure (default is 'myrealm')
4. Select 'Providers' tab -> 'Authentication' tab
5. Ensure the list of 'Authentication Providers' contains at least one non-Default Authentication Provider
6. If the Authentication Provider is perimeter-based, ensure the list contains at least one non-Default IdentityAsserter

If the list of 'Authentication Providers' does not contain at least one non-Default Authentication Prov...
```
**Execution Command:**
```bash
# Option 1: Bash (Preferred - No third-party tools)
bash checks/application/Test-Weblogic-3/V-235965.sh \
  --domain-home /u01/oracle/user_projects/domains/base_domain

# Option 2: Python (Fallback - No third-party tools)
python3 checks/application/Test-Weblogic-3/V-235965.py \
  --domain-home /u01/oracle/user_projects/domains/base_domain

# With JSON output
bash checks/application/Test-Weblogic-3/V-235965.sh \
  --domain-home /u01/oracle/user_projects/domains/base_domain \
  --output-json results/V-235965.json

```

**NIST SP 800-53 Rev 4:** IA-2 (5)

--------------------------------------------------------------------------------

#### V-235966 - WBLC-05-000160
**Severity:** MEDIUM

**Rule Title:** Oracle WebLogic must enforce minimum password length.

**Automation Status:** Automatable

**Automation Method:** Bash/Python (config.xml parsing)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python/powershell)

**Requires Elevation:** Yes (WebLogic Admin credentials)

**Notes:**
- Admin Console check - can be automated via native tools (bash/python parsing config.xml)

**Check Content:**
```
1. Access AC
2. From 'Domain Structure', select 'Security Realms'
3. Select realm to configure (default is 'myrealm')
4. Select 'Providers' tab -> 'Password Validation' subtab
5. Select 'SystemPasswordValidator'
6. Select 'Configuration' tab -> 'Provider Specific' subtab
7. Ensure 'Minimum Password Length' field value is set to '15'

If the 'Minimum Password Length' field is not set to '15', this is a finding.
```
**Execution Command:**
```bash
# Option 1: Bash (Preferred - No third-party tools)
bash checks/application/Test-Weblogic-3/V-235966.sh \
  --domain-home /u01/oracle/user_projects/domains/base_domain

# Option 2: Python (Fallback - No third-party tools)
python3 checks/application/Test-Weblogic-3/V-235966.py \
  --domain-home /u01/oracle/user_projects/domains/base_domain

# With JSON output
bash checks/application/Test-Weblogic-3/V-235966.sh \
  --domain-home /u01/oracle/user_projects/domains/base_domain \
  --output-json results/V-235966.json

```

**NIST SP 800-53 Rev 4:** IA-5 (1) (a)

--------------------------------------------------------------------------------

#### V-235967 - WBLC-05-000162
**Severity:** MEDIUM

**Rule Title:** Oracle WebLogic must enforce password complexity by the number of upper-case characters used.

**Automation Status:** Automatable

**Automation Method:** Bash/Python (config.xml parsing)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python/powershell)

**Requires Elevation:** Yes (WebLogic Admin credentials)

**Notes:**
- Admin Console check - can be automated via native tools (bash/python parsing config.xml)

**Check Content:**
```
1. Access AC
2. From 'Domain Structure', select 'Security Realms'
3. Select realm to configure (default is 'myrealm')
4. Select 'Providers' tab -> 'Password Validation' subtab
5. Select 'SystemPasswordValidator'
6. Select 'Configuration' tab -> 'Provider Specific' subtab
7. Ensure 'Minimum Number of Upper Case Characters' field value is set to '1' or higher

If the 'Minimum Number of Upper Case Characters' field value is not set to '1' or higher, this is a finding.
```
**Execution Command:**
```bash
# Option 1: Bash (Preferred - No third-party tools)
bash checks/application/Test-Weblogic-3/V-235967.sh \
  --domain-home /u01/oracle/user_projects/domains/base_domain

# Option 2: Python (Fallback - No third-party tools)
python3 checks/application/Test-Weblogic-3/V-235967.py \
  --domain-home /u01/oracle/user_projects/domains/base_domain

# With JSON output
bash checks/application/Test-Weblogic-3/V-235967.sh \
  --domain-home /u01/oracle/user_projects/domains/base_domain \
  --output-json results/V-235967.json

```

**NIST SP 800-53 Rev 4:** IA-5 (1) (a)

--------------------------------------------------------------------------------

#### V-235968 - WBLC-05-000163
**Severity:** MEDIUM

**Rule Title:** Oracle WebLogic must enforce password complexity by the number of lower-case characters used.

**Automation Status:** Automatable

**Automation Method:** Bash/Python (config.xml parsing)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python/powershell)

**Requires Elevation:** Yes (WebLogic Admin credentials)

**Notes:**
- Admin Console check - can be automated via native tools (bash/python parsing config.xml)

**Check Content:**
```
1. Access AC
2. From 'Domain Structure', select 'Security Realms'
3. Select realm to configure (default is 'myrealm')
4. Select 'Providers' tab -> 'Password Validation' subtab
5. Select 'SystemPasswordValidator'
6. Select 'Configuration' tab -> 'Provider Specific' subtab
7. Ensure 'Minimum Number of Lower Case Characters' field value is set to '1' or higher

If the 'Minimum Number of Lower Case Characters' field value is not set to '1' or higher, this is a finding.
```
**Execution Command:**
```bash
# Option 1: Bash (Preferred - No third-party tools)
bash checks/application/Test-Weblogic-3/V-235968.sh \
  --domain-home /u01/oracle/user_projects/domains/base_domain

# Option 2: Python (Fallback - No third-party tools)
python3 checks/application/Test-Weblogic-3/V-235968.py \
  --domain-home /u01/oracle/user_projects/domains/base_domain

# With JSON output
bash checks/application/Test-Weblogic-3/V-235968.sh \
  --domain-home /u01/oracle/user_projects/domains/base_domain \
  --output-json results/V-235968.json

```

**NIST SP 800-53 Rev 4:** IA-5 (1) (a)

--------------------------------------------------------------------------------

#### V-235969 - WBLC-05-000164
**Severity:** MEDIUM

**Rule Title:** Oracle WebLogic must enforce password complexity by the number of numeric characters used.

**Automation Status:** Automatable

**Automation Method:** Bash/Python (config.xml parsing)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python/powershell)

**Requires Elevation:** Yes (WebLogic Admin credentials)

**Notes:**
- Admin Console check - can be automated via native tools (bash/python parsing config.xml)

**Check Content:**
```
1. Access AC
2. From 'Domain Structure', select 'Security Realms'
3. Select realm to configure (default is 'myrealm')
4. Select 'Providers' tab -> 'Password Validation' subtab
5. Select 'SystemPasswordValidator'
6. Select 'Configuration' tab -> 'Provider Specific' subtab
7. Ensure 'Minimum Number of Numeric Characters' field value is set to '1' or higher

If the 'Minimum Number of Numeric Characters' field value is not set to '1' or higher, this is a finding.
```
**Execution Command:**
```bash
# Option 1: Bash (Preferred - No third-party tools)
bash checks/application/Test-Weblogic-3/V-235969.sh \
  --domain-home /u01/oracle/user_projects/domains/base_domain

# Option 2: Python (Fallback - No third-party tools)
python3 checks/application/Test-Weblogic-3/V-235969.py \
  --domain-home /u01/oracle/user_projects/domains/base_domain

# With JSON output
bash checks/application/Test-Weblogic-3/V-235969.sh \
  --domain-home /u01/oracle/user_projects/domains/base_domain \
  --output-json results/V-235969.json

```

**NIST SP 800-53 Rev 4:** IA-5 (1) (a)

--------------------------------------------------------------------------------

#### V-235970 - WBLC-05-000165
**Severity:** MEDIUM

**Rule Title:** Oracle WebLogic must enforce password complexity by the number of special characters used.

**Automation Status:** Automatable

**Automation Method:** Bash/Python (config.xml parsing)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python/powershell)

**Requires Elevation:** Yes (WebLogic Admin credentials)

**Notes:**
- Admin Console check - can be automated via native tools (bash/python parsing config.xml)

**Check Content:**
```
1. Access AC
2. From 'Domain Structure', select 'Security Realms'
3. Select realm to configure (default is 'myrealm')
4. Select 'Providers' tab -> 'Password Validation' subtab
5. Select 'SystemPasswordValidator'
6. Select 'Configuration' tab -> 'Provider Specific' subtab
7. Ensure 'Minimum Number of Non-Alphanumeric Characters' field value is set to '1' or higher

If the 'Minimum Number of Non-Alphanumeric Characters' field value is not set to '1' or higher, this is a finding.
```
**Execution Command:**
```bash
# Option 1: Bash (Preferred - No third-party tools)
bash checks/application/Test-Weblogic-3/V-235970.sh \
  --domain-home /u01/oracle/user_projects/domains/base_domain

# Option 2: Python (Fallback - No third-party tools)
python3 checks/application/Test-Weblogic-3/V-235970.py \
  --domain-home /u01/oracle/user_projects/domains/base_domain

# With JSON output
bash checks/application/Test-Weblogic-3/V-235970.sh \
  --domain-home /u01/oracle/user_projects/domains/base_domain \
  --output-json results/V-235970.json

```

**NIST SP 800-53 Rev 4:** IA-5 (1) (a)

--------------------------------------------------------------------------------

#### V-235971 - WBLC-05-000168
**Severity:** HIGH

**Rule Title:** Oracle WebLogic must encrypt passwords during transmission.

**Automation Status:** Automatable

**Automation Method:** Bash/Python (config.xml parsing)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python/powershell)

**Requires Elevation:** Yes (WebLogic Admin credentials)

**Notes:**
- Admin Console check - can be automated via native tools (bash/python parsing config.xml)

**Check Content:**
```
1. Access AC
2. From 'Domain Structure', select 'Security Realms'
3. Select realm to configure (default is 'myrealm')
4. Select 'Providers' tab -> 'Authentication' tab
5. Ensure the list of 'Authentication Providers' contains at least one non-Default Authentication Provider
6. If the Authentication Provider is perimeter-based, ensure the list contains at least one non-Default IdentityAsserter

If the list of 'Authentication Providers' does not contain at least one non-Default Authentication Prov...
```
**Execution Command:**
```bash
# Option 1: Bash (Preferred - No third-party tools)
bash checks/application/Test-Weblogic-3/V-235971.sh \
  --domain-home /u01/oracle/user_projects/domains/base_domain

# Option 2: Python (Fallback - No third-party tools)
python3 checks/application/Test-Weblogic-3/V-235971.py \
  --domain-home /u01/oracle/user_projects/domains/base_domain

# With JSON output
bash checks/application/Test-Weblogic-3/V-235971.sh \
  --domain-home /u01/oracle/user_projects/domains/base_domain \
  --output-json results/V-235971.json

```

**NIST SP 800-53 Rev 4:** IA-5 (1) (c)

--------------------------------------------------------------------------------

#### V-235972 - WBLC-05-000169
**Severity:** HIGH

**Rule Title:** Oracle WebLogic must utilize encryption when using LDAP for authentication.

**Automation Status:** Automatable

**Automation Method:** WLST (WebLogic Scripting Tool) or Bash/Python

**Preferred Tool:** Bash/Python (preferred), WLST (fallback)

**⚠️ Third-Party Tools Required:**
- WLST - Oracle WebLogic Scripting Tool (optional if bash/python can check)

**Requires Elevation:** Yes (WebLogic Admin credentials)

**Notes:**
- Admin Console/EM check - prefer native tools, use WLST if needed

**Check Content:**
```
1. Access EM 
2. Select the domain from the navigation tree, and use the dropdown to select 'WebLogic Domain' -> 'Monitoring' -> 'Port Usage' 
3. In the results table, ensure the 'Protocol' column does not contain the value 'LDAP' (only 'LDAPS')

If LDAP is being used and the 'Protocol' column contains the value 'LDAP', this is a finding.
```
**Execution Command:**
```bash
# Option 1: Bash (Preferred - No third-party tools)
bash checks/application/Test-Weblogic-3/V-235972.sh \
  --domain-home /u01/oracle/user_projects/domains/base_domain

# Option 2: Python (Fallback - No third-party tools)
python3 checks/application/Test-Weblogic-3/V-235972.py \
  --domain-home /u01/oracle/user_projects/domains/base_domain

# With JSON output
bash checks/application/Test-Weblogic-3/V-235972.sh \
  --domain-home /u01/oracle/user_projects/domains/base_domain \
  --output-json results/V-235972.json

# Option 3: WLST (Third-party - use if native tools insufficient)
# Requires: Oracle WebLogic Scripting Tool (WLST)
wlst.sh checks/application/Test-Weblogic-1/V-235972.py \
  --admin-url t3://localhost:7001 \
  --username weblogic \
  --password <password>
```

**NIST SP 800-53 Rev 4:** IA-5 (1) (c)

--------------------------------------------------------------------------------

#### V-235973 - WBLC-05-000172
**Severity:** MEDIUM

**Rule Title:** Oracle WebLogic, when utilizing PKI-based authentication, must validate certificates by constructing a certification path with status information to an accepted trust anchor.

**Automation Status:** Automatable

**Automation Method:** Bash/Python (config.xml parsing)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python/powershell)

**Requires Elevation:** Yes (WebLogic Admin credentials)

**🔧 Configuration Dependencies:**
- ⚠️ **ENVIRONMENT-SPECIFIC**: This check requires site-specific or organizational values
- ⚠️ **SYSTEM-SPECIFIC**: This check depends on deployment/installation-specific configuration

**Notes:**
- Admin Console check - can be automated via native tools (bash/python parsing config.xml)

**Environment/System Annotations:**
- Environment-specific: Contains "ssp"
- System-specific: Contains "custom"

**Check Content:**
```
1. Access AC
2. From 'Domain Structure', select 'Environment' -> 'Servers' 
3. From the list of servers, select one which needs check for SSL configuration verification
4. From 'Configuration' tab -> 'General' tab, ensure 'Listen Port Enabled' checkbox is deselected
5. Ensure 'SSL Listen Port Enabled' checkbox is selected and a valid port number is in 'SSL Listen Port' field, e.g., 7002

6. Repeat steps 3-5 for all servers requiring SSL configuration checking

If any servers utilizing PKI-based ...
```
**Execution Command:**
```bash
# Option 1: Bash (Preferred - No third-party tools)
bash checks/application/Test-Weblogic-3/V-235973.sh \
  --domain-home /u01/oracle/user_projects/domains/base_domain

# Option 2: Python (Fallback - No third-party tools)
python3 checks/application/Test-Weblogic-3/V-235973.py \
  --domain-home /u01/oracle/user_projects/domains/base_domain

# With JSON output
bash checks/application/Test-Weblogic-3/V-235973.sh \
  --domain-home /u01/oracle/user_projects/domains/base_domain \
  --output-json results/V-235973.json

```

**NIST SP 800-53 Rev 4:** IA-5 (2) (a)

--------------------------------------------------------------------------------

#### V-235974 - WBLC-05-000174
**Severity:** MEDIUM

**Rule Title:** Oracle WebLogic must map the PKI-based authentication identity to the user account.

**Automation Status:** Automatable

**Automation Method:** Bash/Python (config.xml parsing)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python/powershell)

**Requires Elevation:** Yes (WebLogic Admin credentials)

**Notes:**
- Admin Console check - can be automated via native tools (bash/python parsing config.xml)

**Check Content:**
```
1. Access AC
2. From 'Domain Structure', select 'Security Realms'
3. Select realm to configure (default is 'myrealm')
4. Select 'Providers' tab -> 'Authentication' tab
5. Ensure the list of 'Authentication Providers' contains at least one non-Default Authentication Provider
6. If the Authentication Provider is perimeter-based, ensure the list contains at least one non-Default IdentityAsserter

If PKI-based authentication is being used and the list of 'Authentication Providers' does not contain a...
```
**Execution Command:**
```bash
# Option 1: Bash (Preferred - No third-party tools)
bash checks/application/Test-Weblogic-3/V-235974.sh \
  --domain-home /u01/oracle/user_projects/domains/base_domain

# Option 2: Python (Fallback - No third-party tools)
python3 checks/application/Test-Weblogic-3/V-235974.py \
  --domain-home /u01/oracle/user_projects/domains/base_domain

# With JSON output
bash checks/application/Test-Weblogic-3/V-235974.sh \
  --domain-home /u01/oracle/user_projects/domains/base_domain \
  --output-json results/V-235974.json

```

**NIST SP 800-53 Rev 4:** IA-5 (2) (c)

--------------------------------------------------------------------------------

#### V-235975 - WBLC-05-000176
**Severity:** MEDIUM

**Rule Title:** Oracle WebLogic must use cryptographic modules that meet the requirements of applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance when encrypting stored data.

**Automation Status:** Automatable

**Automation Method:** WLST (WebLogic Scripting Tool) or Bash/Python

**Preferred Tool:** Bash/Python (preferred), WLST (fallback)

**⚠️ Third-Party Tools Required:**
- WLST - Oracle WebLogic Scripting Tool (optional if bash/python can check)

**Requires Elevation:** Yes (WebLogic Admin credentials)

**🔧 Configuration Dependencies:**
- ⚠️ **ENVIRONMENT-SPECIFIC**: This check requires site-specific or organizational values

**Notes:**
- Admin Console/EM check - prefer native tools, use WLST if needed

**Environment/System Annotations:**
- Environment-specific: Contains "approved"
- Environment-specific: Contains "ssp"

**Check Content:**
```
1. Access EM 
2. Select the domain from the navigation tree, and use the dropdown to select 'WebLogic Domain' -> 'Logs' -> 'View Log Messages'
3. Within the 'Search' panel, expand 'Selected Targets'
4. Click 'Target Log Files' icon for 'AdminServer' target
5. From the list of log files, select 'AdminServer.log' and click 'View Log File' button
6. Within the search criteria, enter the value 'FIPS' for the 'Message contains' field, and select the appropriate 'Start Date' and 'End Date' range. Clic...
```
**Execution Command:**
```bash
# Option 1: Bash (Preferred - No third-party tools)
bash checks/application/Test-Weblogic-3/V-235975.sh \
  --domain-home /u01/oracle/user_projects/domains/base_domain

# Option 2: Python (Fallback - No third-party tools)
python3 checks/application/Test-Weblogic-3/V-235975.py \
  --domain-home /u01/oracle/user_projects/domains/base_domain

# With JSON output
bash checks/application/Test-Weblogic-3/V-235975.sh \
  --domain-home /u01/oracle/user_projects/domains/base_domain \
  --output-json results/V-235975.json

# Option 3: WLST (Third-party - use if native tools insufficient)
# Requires: Oracle WebLogic Scripting Tool (WLST)
wlst.sh checks/application/Test-Weblogic-1/V-235975.py \
  --admin-url t3://localhost:7001 \
  --username weblogic \
  --password <password>
```

**NIST SP 800-53 Rev 4:** IA-7

--------------------------------------------------------------------------------

#### V-235976 - WBLC-05-000177
**Severity:** MEDIUM

**Rule Title:** Oracle WebLogic must utilize FIPS 140-2 approved encryption modules when authenticating users and processes.

**Automation Status:** Automatable

**Automation Method:** WLST (WebLogic Scripting Tool) or Bash/Python

**Preferred Tool:** Bash/Python (preferred), WLST (fallback)

**⚠️ Third-Party Tools Required:**
- WLST - Oracle WebLogic Scripting Tool (optional if bash/python can check)

**Requires Elevation:** Yes (WebLogic Admin credentials)

**🔧 Configuration Dependencies:**
- ⚠️ **ENVIRONMENT-SPECIFIC**: This check requires site-specific or organizational values

**Notes:**
- Admin Console/EM check - prefer native tools, use WLST if needed

**Environment/System Annotations:**
- Environment-specific: Contains "approved"
- Environment-specific: Contains "ssp"

**Check Content:**
```
1. Access EM 
2. Select the domain from the navigation tree, and use the dropdown to select 'WebLogic Domain' -> 'Logs' -> 'View Log Messages'
3. Within the 'Search' panel, expand 'Selected Targets'
4. Click 'Target Log Files' icon for 'AdminServer' target
5. From the list of log files, select 'AdminServer.log' and click 'View Log File' button
6. Within the search criteria, enter the value 'FIPS' for the 'Message contains' field, and select the appropriate 'Start Date' and 'End Date' range. Clic...
```
**Execution Command:**
```bash
# Option 1: Bash (Preferred - No third-party tools)
bash checks/application/Test-Weblogic-3/V-235976.sh \
  --domain-home /u01/oracle/user_projects/domains/base_domain

# Option 2: Python (Fallback - No third-party tools)
python3 checks/application/Test-Weblogic-3/V-235976.py \
  --domain-home /u01/oracle/user_projects/domains/base_domain

# With JSON output
bash checks/application/Test-Weblogic-3/V-235976.sh \
  --domain-home /u01/oracle/user_projects/domains/base_domain \
  --output-json results/V-235976.json

# Option 3: WLST (Third-party - use if native tools insufficient)
# Requires: Oracle WebLogic Scripting Tool (WLST)
wlst.sh checks/application/Test-Weblogic-1/V-235976.py \
  --admin-url t3://localhost:7001 \
  --username weblogic \
  --password <password>
```

**NIST SP 800-53 Rev 4:** IA-7

--------------------------------------------------------------------------------

#### V-235977 - WBLC-06-000190
**Severity:** MEDIUM

**Rule Title:** Oracle WebLogic must employ cryptographic encryption to protect the integrity and confidentiality of nonlocal maintenance and diagnostic communications.

**Automation Status:** Automatable

**Automation Method:** Bash/Python (config.xml parsing)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python/powershell)

**Requires Elevation:** Yes (WebLogic Admin credentials)

**🔧 Configuration Dependencies:**
- ⚠️ **ENVIRONMENT-SPECIFIC**: This check requires site-specific or organizational values
- ⚠️ **SYSTEM-SPECIFIC**: This check depends on deployment/installation-specific configuration

**Notes:**
- Admin Console check - can be automated via native tools (bash/python parsing config.xml)

**Environment/System Annotations:**
- Environment-specific: Contains "ssp"
- System-specific: Contains "custom"

**Check Content:**
```
1. Access AC
2. From 'Domain Structure', select 'Environment' -> 'Servers' 
3. From the list of servers, select one which needs check for SSL configuration verification
4. From 'Configuration' tab -> 'General' tab, ensure 'Listen Port Enabled' checkbox is deselected
5. Ensure 'SSL Listen Port Enabled' checkbox is selected and a valid port number is in 'SSL Listen Port' field, e.g., 7002

6. Repeat steps 3-5 for all servers requiring SSL configuration checking

If any of the servers requiring SSL...
```
**Execution Command:**
```bash
# Option 1: Bash (Preferred - No third-party tools)
bash checks/application/Test-Weblogic-3/V-235977.sh \
  --domain-home /u01/oracle/user_projects/domains/base_domain

# Option 2: Python (Fallback - No third-party tools)
python3 checks/application/Test-Weblogic-3/V-235977.py \
  --domain-home /u01/oracle/user_projects/domains/base_domain

# With JSON output
bash checks/application/Test-Weblogic-3/V-235977.sh \
  --domain-home /u01/oracle/user_projects/domains/base_domain \
  --output-json results/V-235977.json

```

**NIST SP 800-53 Rev 4:** SC-8 (1)

--------------------------------------------------------------------------------

#### V-235978 - WBLC-06-000191
**Severity:** MEDIUM

**Rule Title:** Oracle WebLogic must employ strong identification and authentication techniques when establishing nonlocal maintenance and diagnostic sessions.

**Automation Status:** Automatable

**Automation Method:** Bash/Python (config.xml parsing)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python/powershell)

**Requires Elevation:** Yes (WebLogic Admin credentials)

**🔧 Configuration Dependencies:**
- ⚠️ **ENVIRONMENT-SPECIFIC**: This check requires site-specific or organizational values
- ⚠️ **SYSTEM-SPECIFIC**: This check depends on deployment/installation-specific configuration

**Notes:**
- Admin Console check - can be automated via native tools (bash/python parsing config.xml)

**Environment/System Annotations:**
- Environment-specific: Contains "approved"
- Environment-specific: Contains "ssp"
- System-specific: Contains "custom"

**Check Content:**
```
1. Access AC
2. From 'Domain Structure', select 'Environment' -> 'Servers' 
3. From the list of servers, select one which needs check for SSL configuration verification
4. From 'Configuration' tab -> 'General' tab, ensure 'Listen Port Enabled' checkbox is deselected
5. Ensure 'SSL Listen Port Enabled' checkbox is selected and a valid port number is in 'SSL Listen Port' field, e.g., 7002

6. Repeat steps 3-5 for all servers requiring SSL configuration checking

If any of the servers requiring SSL...
```
**Execution Command:**
```bash
# Option 1: Bash (Preferred - No third-party tools)
bash checks/application/Test-Weblogic-3/V-235978.sh \
  --domain-home /u01/oracle/user_projects/domains/base_domain

# Option 2: Python (Fallback - No third-party tools)
python3 checks/application/Test-Weblogic-3/V-235978.py \
  --domain-home /u01/oracle/user_projects/domains/base_domain

# With JSON output
bash checks/application/Test-Weblogic-3/V-235978.sh \
  --domain-home /u01/oracle/user_projects/domains/base_domain \
  --output-json results/V-235978.json

```

**NIST SP 800-53 Rev 4:** MA-4 c

--------------------------------------------------------------------------------

#### V-235979 - WBLC-08-000210
**Severity:** LOW

**Rule Title:** Oracle WebLogic must terminate the network connection associated with a communications session at the end of the session or after a DoD-defined time period of inactivity.

**Automation Status:** Automatable

**Automation Method:** Bash/Python (config.xml parsing)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python/powershell)

**Requires Elevation:** Yes (WebLogic Admin credentials)

**Notes:**
- Admin Console check - can be automated via native tools (bash/python parsing config.xml)

**Check Content:**
```
1. Access AC 
2. From 'Domain Structure', select 'Deployments'
3. Sort 'Deployments' table by 'Type' by click the column header
4. Select an 'Enterprise Application' or 'Web Application' to check the session timeout setting
5. Select 'Configuration' tab -> 'Application' tab for deployments of 'Enterprise Application' type
Select 'Configuration' tab -> 'General' tab for deployments of 'Web Application' type
6. Ensure 'Session Timeout' field value is set to '900' (seconds)

If the 'Session Timeout...
```
**Execution Command:**
```bash
# Option 1: Bash (Preferred - No third-party tools)
bash checks/application/Test-Weblogic-3/V-235979.sh \
  --domain-home /u01/oracle/user_projects/domains/base_domain

# Option 2: Python (Fallback - No third-party tools)
python3 checks/application/Test-Weblogic-3/V-235979.py \
  --domain-home /u01/oracle/user_projects/domains/base_domain

# With JSON output
bash checks/application/Test-Weblogic-3/V-235979.sh \
  --domain-home /u01/oracle/user_projects/domains/base_domain \
  --output-json results/V-235979.json

```

**NIST SP 800-53 Rev 4:** SC-10

--------------------------------------------------------------------------------

#### V-235980 - WBLC-08-000211
**Severity:** MEDIUM

**Rule Title:** Oracle WebLogic must establish a trusted communications path between the user and organization-defined security functions within the information system.

**Automation Status:** Automatable

**Automation Method:** Bash/Python (config.xml parsing)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python/powershell)

**Requires Elevation:** Yes (WebLogic Admin credentials)

**🔧 Configuration Dependencies:**
- ⚠️ **ENVIRONMENT-SPECIFIC**: This check requires site-specific or organizational values
- ⚠️ **SYSTEM-SPECIFIC**: This check depends on deployment/installation-specific configuration

**Notes:**
- Admin Console check - can be automated via native tools (bash/python parsing config.xml)

**Environment/System Annotations:**
- Environment-specific: Contains "ssp"
- System-specific: Contains "custom"

**Check Content:**
```
1. Access AC
2. From 'Domain Structure', select 'Environment' -> 'Servers' 
3. From the list of servers, select one which needs check for SSL configuration verification
4. From 'Configuration' tab -> 'General' tab, ensure 'Listen Port Enabled' checkbox is deselected
5. Ensure 'SSL Listen Port Enabled' checkbox is selected and a valid port number is in 'SSL Listen Port' field, e.g., 7002

6. Repeat steps 3-5 for all servers requiring SSL configuration checking

If any of the servers requiring SSL...
```
**Execution Command:**
```bash
# Option 1: Bash (Preferred - No third-party tools)
bash checks/application/Test-Weblogic-3/V-235980.sh \
  --domain-home /u01/oracle/user_projects/domains/base_domain

# Option 2: Python (Fallback - No third-party tools)
python3 checks/application/Test-Weblogic-3/V-235980.py \
  --domain-home /u01/oracle/user_projects/domains/base_domain

# With JSON output
bash checks/application/Test-Weblogic-3/V-235980.sh \
  --domain-home /u01/oracle/user_projects/domains/base_domain \
  --output-json results/V-235980.json

```

**NIST SP 800-53 Rev 4:** SC-11

--------------------------------------------------------------------------------

#### V-235981 - WBLC-08-000214
**Severity:** MEDIUM

**Rule Title:** Oracle WebLogic must utilize NSA-approved cryptography when protecting classified compartmentalized data.

**Automation Status:** Automatable

**Automation Method:** WLST (WebLogic Scripting Tool) or Bash/Python

**Preferred Tool:** Bash/Python (preferred), WLST (fallback)

**⚠️ Third-Party Tools Required:**
- WLST - Oracle WebLogic Scripting Tool (optional if bash/python can check)

**Requires Elevation:** Yes (WebLogic Admin credentials)

**🔧 Configuration Dependencies:**
- ⚠️ **ENVIRONMENT-SPECIFIC**: This check requires site-specific or organizational values

**Notes:**
- Admin Console/EM check - prefer native tools, use WLST if needed

**Environment/System Annotations:**
- Environment-specific: Contains "approved"
- Environment-specific: Contains "ssp"

**Check Content:**
```
1. Access EM 
2. Select the domain from the navigation tree, and use the dropdown to select 'WebLogic Domain' -> 'Logs' -> 'View Log Messages'
3. Within the 'Search' panel, expand 'Selected Targets'
4. Click 'Target Log Files' icon for 'AdminServer' target
5. From the list of log files, select 'AdminServer.log' and click 'View Log File' button
6. Within the search criteria, enter the value 'FIPS' for the 'Message contains' field, and select the appropriate 'Start Date' and 'End Date' range. Clic...
```
**Execution Command:**
```bash
# Option 1: Bash (Preferred - No third-party tools)
bash checks/application/Test-Weblogic-3/V-235981.sh \
  --domain-home /u01/oracle/user_projects/domains/base_domain

# Option 2: Python (Fallback - No third-party tools)
python3 checks/application/Test-Weblogic-3/V-235981.py \
  --domain-home /u01/oracle/user_projects/domains/base_domain

# With JSON output
bash checks/application/Test-Weblogic-3/V-235981.sh \
  --domain-home /u01/oracle/user_projects/domains/base_domain \
  --output-json results/V-235981.json

# Option 3: WLST (Third-party - use if native tools insufficient)
# Requires: Oracle WebLogic Scripting Tool (WLST)
wlst.sh checks/application/Test-Weblogic-1/V-235981.py \
  --admin-url t3://localhost:7001 \
  --username weblogic \
  --password <password>
```

**NIST SP 800-53 Rev 4:** CM-6 b

--------------------------------------------------------------------------------

#### V-235982 - WBLC-08-000218
**Severity:** MEDIUM

**Rule Title:** Oracle WebLogic must protect the integrity and availability of publicly available information and applications.

**Automation Status:** Automatable

**Automation Method:** WLST (WebLogic Scripting Tool) or Bash/Python

**Preferred Tool:** Bash/Python (preferred), WLST (fallback)

**⚠️ Third-Party Tools Required:**
- WLST - Oracle WebLogic Scripting Tool (optional if bash/python can check)

**Requires Elevation:** Yes (WebLogic Admin credentials)

**Notes:**
- Admin Console/EM check - prefer native tools, use WLST if needed

**Check Content:**
```
1. Access AC 
2. From 'Domain Structure', select 'Deployments' 
3. Select a deployed component which contains publicly available information and/or applications
4. Select 'Targets' tab
5. Ensure one or more of the selected targets for this deployment is a cluster of managed servers

If the information requires clustering of managed server and the managed servers are not clustered, this is a finding.
```
**Execution Command:**
```bash
# Option 1: Bash (Preferred - No third-party tools)
bash checks/application/Test-Weblogic-3/V-235982.sh \
  --domain-home /u01/oracle/user_projects/domains/base_domain

# Option 2: Python (Fallback - No third-party tools)
python3 checks/application/Test-Weblogic-3/V-235982.py \
  --domain-home /u01/oracle/user_projects/domains/base_domain

# With JSON output
bash checks/application/Test-Weblogic-3/V-235982.sh \
  --domain-home /u01/oracle/user_projects/domains/base_domain \
  --output-json results/V-235982.json

# Option 3: WLST (Third-party - use if native tools insufficient)
# Requires: Oracle WebLogic Scripting Tool (WLST)
wlst.sh checks/application/Test-Weblogic-1/V-235982.py \
  --admin-url t3://localhost:7001 \
  --username weblogic \
  --password <password>
```

**NIST SP 800-53 Rev 4:** SC-5

--------------------------------------------------------------------------------

#### V-235983 - WBLC-08-000222
**Severity:** MEDIUM

**Rule Title:** Oracle WebLogic must separate hosted application functionality from Oracle WebLogic management functionality.

**Automation Status:** Automatable

**Automation Method:** WLST (WebLogic Scripting Tool) or Bash/Python

**Preferred Tool:** Bash/Python (preferred), WLST (fallback)

**⚠️ Third-Party Tools Required:**
- WLST - Oracle WebLogic Scripting Tool (optional if bash/python can check)

**Requires Elevation:** Yes (WebLogic Admin credentials)

**Notes:**
- Admin Console/EM check - prefer native tools, use WLST if needed

**Check Content:**
```
1. Access AC 
2. From 'Domain Structure', select 'Environment' -> 'Servers' 
3. A single server in the list will be named 'Admin Server' and this is the server which hosts AS management functionality, such as the AdminConsole application
4. All remaining servers in the list are 'Managed Servers' and these are the individual or clustered servers which will host the actual applications
5. Ensure no applications are deployed on the Admin server, rather, only on the Managed servers

If any applicati...
```
**Execution Command:**
```bash
# Option 1: Bash (Preferred - No third-party tools)
bash checks/application/Test-Weblogic-3/V-235983.sh \
  --domain-home /u01/oracle/user_projects/domains/base_domain

# Option 2: Python (Fallback - No third-party tools)
python3 checks/application/Test-Weblogic-3/V-235983.py \
  --domain-home /u01/oracle/user_projects/domains/base_domain

# With JSON output
bash checks/application/Test-Weblogic-3/V-235983.sh \
  --domain-home /u01/oracle/user_projects/domains/base_domain \
  --output-json results/V-235983.json

# Option 3: WLST (Third-party - use if native tools insufficient)
# Requires: Oracle WebLogic Scripting Tool (WLST)
wlst.sh checks/application/Test-Weblogic-1/V-235983.py \
  --admin-url t3://localhost:7001 \
  --username weblogic \
  --password <password>
```

**NIST SP 800-53 Rev 4:** SC-2

--------------------------------------------------------------------------------

#### V-235984 - WBLC-08-000223
**Severity:** MEDIUM

**Rule Title:** Oracle WebLogic must ensure authentication of both client and server during the entire session.

**Automation Status:** Automatable

**Automation Method:** Bash/Python (config.xml parsing)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python/powershell)

**Requires Elevation:** Yes (WebLogic Admin credentials)

**Notes:**
- Admin Console check - can be automated via native tools (bash/python parsing config.xml)

**Check Content:**
```
1. Access AC
2. From 'Domain Structure', select 'Environment' -> 'Servers' 
3. From the list of servers, select one which needs check for Mutual Authentication configuration verification
4. From 'Configuration' tab -> 'General' tab, ensure 'Listen Port Enabled' checkbox is deselected
5. Ensure 'SSL Listen Port Enabled' checkbox is selected and a valid port number is in 'SSL Listen Port' field, e.g., 7002
6. From 'Configuration' tab -> 'SSL' tab, click 'Advanced' link
7. Ensure 'Two Way Client Ce...
```
**Execution Command:**
```bash
# Option 1: Bash (Preferred - No third-party tools)
bash checks/application/Test-Weblogic-3/V-235984.sh \
  --domain-home /u01/oracle/user_projects/domains/base_domain

# Option 2: Python (Fallback - No third-party tools)
python3 checks/application/Test-Weblogic-3/V-235984.py \
  --domain-home /u01/oracle/user_projects/domains/base_domain

# With JSON output
bash checks/application/Test-Weblogic-3/V-235984.sh \
  --domain-home /u01/oracle/user_projects/domains/base_domain \
  --output-json results/V-235984.json

```

**NIST SP 800-53 Rev 4:** SC-23

--------------------------------------------------------------------------------

#### V-235986 - WBLC-08-000229
**Severity:** MEDIUM

**Rule Title:** Oracle WebLogic must be configured to perform complete application deployments.

**Automation Status:** Automatable

**Automation Method:** Bash/Python (config.xml parsing)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python/powershell)

**Requires Elevation:** Yes (WebLogic Admin credentials)

**Notes:**
- Admin Console check - can be automated via native tools (bash/python parsing config.xml)

**Check Content:**
```
1. Access AC 
2. From 'Domain Structure', select the top-level domain 
3. Select 'Configuration' tab -> 'General' tab 
4. Ensure 'Production Mode' checkbox is selected

If the 'Production Mode' checkbox is not selected, this is a finding.
```
**Execution Command:**
```bash
# Option 1: Bash (Preferred - No third-party tools)
bash checks/application/Test-Weblogic-3/V-235986.sh \
  --domain-home /u01/oracle/user_projects/domains/base_domain

# Option 2: Python (Fallback - No third-party tools)
python3 checks/application/Test-Weblogic-3/V-235986.py \
  --domain-home /u01/oracle/user_projects/domains/base_domain

# With JSON output
bash checks/application/Test-Weblogic-3/V-235986.sh \
  --domain-home /u01/oracle/user_projects/domains/base_domain \
  --output-json results/V-235986.json

```

**NIST SP 800-53 Rev 4:** SC-24

--------------------------------------------------------------------------------

#### V-235987 - WBLC-08-000231
**Severity:** MEDIUM

**Rule Title:** Oracle WebLogic must protect the confidentiality of applications and leverage transmission protection mechanisms, such as TLS and SSL VPN, when deploying applications.

**Automation Status:** Automatable

**Automation Method:** Bash/Python (config.xml parsing)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python/powershell)

**Requires Elevation:** Yes (WebLogic Admin credentials)

**🔧 Configuration Dependencies:**
- ⚠️ **ENVIRONMENT-SPECIFIC**: This check requires site-specific or organizational values
- ⚠️ **SYSTEM-SPECIFIC**: This check depends on deployment/installation-specific configuration

**Notes:**
- Admin Console check - can be automated via native tools (bash/python parsing config.xml)

**Environment/System Annotations:**
- Environment-specific: Contains "ssp"
- System-specific: Contains "custom"

**Check Content:**
```
1. Access AC
2. From 'Domain Structure', select 'Environment' -> 'Servers' 
3. From the list of servers, select the AdminServer
4. From 'Configuration' tab -> 'General' tab, ensure 'Listen Port Enabled' checkbox is deselected
5. Ensure 'SSL Listen Port Enabled' checkbox is selected and a valid port number is in 'SSL Listen Port' field, e.g., 7002


If the field 'SSL Listen Port Enabled' is not selected or 'Listen Port Enabled' is selected, this is a finding.

```
**Execution Command:**
```bash
# Option 1: Bash (Preferred - No third-party tools)
bash checks/application/Test-Weblogic-3/V-235987.sh \
  --domain-home /u01/oracle/user_projects/domains/base_domain

# Option 2: Python (Fallback - No third-party tools)
python3 checks/application/Test-Weblogic-3/V-235987.py \
  --domain-home /u01/oracle/user_projects/domains/base_domain

# With JSON output
bash checks/application/Test-Weblogic-3/V-235987.sh \
  --domain-home /u01/oracle/user_projects/domains/base_domain \
  --output-json results/V-235987.json

```

**NIST SP 800-53 Rev 4:** SC-8 (1)

--------------------------------------------------------------------------------

#### V-235988 - WBLC-08-000235
**Severity:** LOW

**Rule Title:** Oracle WebLogic must protect the integrity of applications during the processes of data aggregation, packaging, and transformation in preparation for deployment.

**Automation Status:** Automatable

**Automation Method:** Bash/Python (config.xml parsing)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python/powershell)

**Requires Elevation:** Yes (WebLogic Admin credentials)

**🔧 Configuration Dependencies:**
- ⚠️ **ENVIRONMENT-SPECIFIC**: This check requires site-specific or organizational values

**Notes:**
- Admin Console check - can be automated via native tools (bash/python parsing config.xml)

**Environment/System Annotations:**
- Environment-specific: Contains "authorized"

**Check Content:**
```
1. Access AC 
2. From 'Domain Structure', select the top-level domain 
3. Select 'Configuration' tab -> 'General' tab 
4. Ensure 'Production Mode' checkbox is selected

If the 'Production Mode' checkbox is not selected, this is a finding.
```
**Execution Command:**
```bash
# Option 1: Bash (Preferred - No third-party tools)
bash checks/application/Test-Weblogic-3/V-235988.sh \
  --domain-home /u01/oracle/user_projects/domains/base_domain

# Option 2: Python (Fallback - No third-party tools)
python3 checks/application/Test-Weblogic-3/V-235988.py \
  --domain-home /u01/oracle/user_projects/domains/base_domain

# With JSON output
bash checks/application/Test-Weblogic-3/V-235988.sh \
  --domain-home /u01/oracle/user_projects/domains/base_domain \
  --output-json results/V-235988.json

```

**NIST SP 800-53 Rev 4:** SC-8 (2)

--------------------------------------------------------------------------------

#### V-235989 - WBLC-08-000236
**Severity:** MEDIUM

**Rule Title:** Oracle WebLogic must protect against or limit the effects of HTTP types of Denial of Service (DoS) attacks.

**Automation Status:** Automatable

**Automation Method:** Bash/Python (config.xml parsing)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python/powershell)

**Requires Elevation:** Yes (WebLogic Admin credentials)

**Notes:**
- Admin Console check - can be automated via native tools (bash/python parsing config.xml)

**Check Content:**
```
1. Access AC 
2. From 'Domain Structure', select 'Deployments'
3. Sort 'Deployments' table by 'Type' by click the column header
4. Select an 'Enterprise Application' or 'Web Application' to check the session timeout setting
5. Select 'Configuration' tab -> 'Application' tab for deployments of 'Enterprise Application' type
Select 'Configuration' tab -> 'General' tab for deployments of 'Web Application' type
6. Ensure 'Maximum in-memory Session' field value is set to an integer value at or lower t...
```
**Execution Command:**
```bash
# Option 1: Bash (Preferred - No third-party tools)
bash checks/application/Test-Weblogic-3/V-235989.sh \
  --domain-home /u01/oracle/user_projects/domains/base_domain

# Option 2: Python (Fallback - No third-party tools)
python3 checks/application/Test-Weblogic-3/V-235989.py \
  --domain-home /u01/oracle/user_projects/domains/base_domain

# With JSON output
bash checks/application/Test-Weblogic-3/V-235989.sh \
  --domain-home /u01/oracle/user_projects/domains/base_domain \
  --output-json results/V-235989.json

```

**NIST SP 800-53 Rev 4:** SC-5

--------------------------------------------------------------------------------

#### V-235990 - WBLC-08-000237
**Severity:** MEDIUM

**Rule Title:** Oracle WebLogic must limit the use of resources by priority and not impede the host from servicing processes designated as a higher-priority.

**Automation Status:** Automatable

**Automation Method:** WLST (WebLogic Scripting Tool) or Bash/Python

**Preferred Tool:** Bash/Python (preferred), WLST (fallback)

**⚠️ Third-Party Tools Required:**
- WLST - Oracle WebLogic Scripting Tool (optional if bash/python can check)

**Requires Elevation:** Yes (WebLogic Admin credentials)

**Notes:**
- Admin Console/EM check - prefer native tools, use WLST if needed

**Check Content:**
```
1. Access AC
2. From 'Domain Structure', select 'Environment' -> 'Work Managers' 
3. Existing Work Managers will appear in the list

If Work Managers are not created to allow prioritization of resources, this is a finding.
```
**Execution Command:**
```bash
# Option 1: Bash (Preferred - No third-party tools)
bash checks/application/Test-Weblogic-3/V-235990.sh \
  --domain-home /u01/oracle/user_projects/domains/base_domain

# Option 2: Python (Fallback - No third-party tools)
python3 checks/application/Test-Weblogic-3/V-235990.py \
  --domain-home /u01/oracle/user_projects/domains/base_domain

# With JSON output
bash checks/application/Test-Weblogic-3/V-235990.sh \
  --domain-home /u01/oracle/user_projects/domains/base_domain \
  --output-json results/V-235990.json

# Option 3: WLST (Third-party - use if native tools insufficient)
# Requires: Oracle WebLogic Scripting Tool (WLST)
wlst.sh checks/application/Test-Weblogic-1/V-235990.py \
  --admin-url t3://localhost:7001 \
  --username weblogic \
  --password <password>
```

**NIST SP 800-53 Rev 4:** SC-5

--------------------------------------------------------------------------------

#### V-235991 - WBLC-08-000238
**Severity:** MEDIUM

**Rule Title:** Oracle WebLogic must fail securely in the event of an operational failure.

**Automation Status:** Automatable

**Automation Method:** WLST (WebLogic Scripting Tool) or Bash/Python

**Preferred Tool:** Bash/Python (preferred), WLST (fallback)

**⚠️ Third-Party Tools Required:**
- WLST - Oracle WebLogic Scripting Tool (optional if bash/python can check)

**Requires Elevation:** Yes (WebLogic Admin credentials)

**Notes:**
- Admin Console/EM check - prefer native tools, use WLST if needed

**Check Content:**
```
1. Access EM 
2. Select the domain from the navigation tree, and use the dropdown to select 'WebLogic Domain' -> 'Monitoring' -> 'Port Usage' 
3. In the results table, ensure values in the 'Protocol' column each end with 's' (secure)

If the protocols are not secure, this is a finding.
```
**Execution Command:**
```bash
# Option 1: Bash (Preferred - No third-party tools)
bash checks/application/Test-Weblogic-3/V-235991.sh \
  --domain-home /u01/oracle/user_projects/domains/base_domain

# Option 2: Python (Fallback - No third-party tools)
python3 checks/application/Test-Weblogic-3/V-235991.py \
  --domain-home /u01/oracle/user_projects/domains/base_domain

# With JSON output
bash checks/application/Test-Weblogic-3/V-235991.sh \
  --domain-home /u01/oracle/user_projects/domains/base_domain \
  --output-json results/V-235991.json

# Option 3: WLST (Third-party - use if native tools insufficient)
# Requires: Oracle WebLogic Scripting Tool (WLST)
wlst.sh checks/application/Test-Weblogic-1/V-235991.py \
  --admin-url t3://localhost:7001 \
  --username weblogic \
  --password <password>
```

**NIST SP 800-53 Rev 4:** SC-7 (18)

--------------------------------------------------------------------------------

#### V-235992 - WBLC-08-000239
**Severity:** MEDIUM

**Rule Title:** Oracle WebLogic must employ approved cryptographic mechanisms when transmitting sensitive data.

**Automation Status:** Automatable

**Automation Method:** Bash/Python (config.xml parsing)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python/powershell)

**Requires Elevation:** Yes (WebLogic Admin credentials)

**🔧 Configuration Dependencies:**
- ⚠️ **ENVIRONMENT-SPECIFIC**: This check requires site-specific or organizational values
- ⚠️ **SYSTEM-SPECIFIC**: This check depends on deployment/installation-specific configuration

**Notes:**
- Admin Console check - can be automated via native tools (bash/python parsing config.xml)

**Environment/System Annotations:**
- Environment-specific: Contains "approved"
- Environment-specific: Contains "ssp"
- System-specific: Contains "custom"

**Check Content:**
```
1. Access AC
2. From 'Domain Structure', select 'Environment' -> 'Servers' 
3. From the list of servers, select one which needs check for SSL configuration verification
4. From 'Configuration' tab -> 'General' tab, ensure 'Listen Port Enabled' checkbox is deselected
5. Ensure 'SSL Listen Port Enabled' checkbox is selected and a valid port number is in 'SSL Listen Port' field, e.g., 7002

6. Repeat steps 3-5 for all servers requiring SSL configuration checking

If any of the servers requiring cry...
```
**Execution Command:**
```bash
# Option 1: Bash (Preferred - No third-party tools)
bash checks/application/Test-Weblogic-3/V-235992.sh \
  --domain-home /u01/oracle/user_projects/domains/base_domain

# Option 2: Python (Fallback - No third-party tools)
python3 checks/application/Test-Weblogic-3/V-235992.py \
  --domain-home /u01/oracle/user_projects/domains/base_domain

# With JSON output
bash checks/application/Test-Weblogic-3/V-235992.sh \
  --domain-home /u01/oracle/user_projects/domains/base_domain \
  --output-json results/V-235992.json

```

**NIST SP 800-53 Rev 4:** SC-8 (1)

--------------------------------------------------------------------------------

#### V-235994 - WBLC-09-000253
**Severity:** MEDIUM

**Rule Title:** Oracle WebLogic must only generate error messages that provide information necessary for corrective actions without revealing sensitive or potentially harmful information in error logs and administrative messages.

**Automation Status:** Automatable

**Automation Method:** WLST (WebLogic Scripting Tool) or Bash/Python

**Preferred Tool:** Bash/Python (preferred), WLST (fallback)

**⚠️ Third-Party Tools Required:**
- WLST - Oracle WebLogic Scripting Tool (optional if bash/python can check)

**Requires Elevation:** Yes (WebLogic Admin credentials)

**Notes:**
- Admin Console/EM check - prefer native tools, use WLST if needed

**Check Content:**
```
1. Access EM 
2. Select the domain from the navigation tree, and use the dropdown to select 'WebLogic Domain' -> 'Logs' -> 'View Log Messages'
3. Within the search criteria, click 'Add Fields' button
4. Notice the list of available fields do not contain sensitive data

If sensitive or potentially harmful information, such as passwords, private keys or other sensitive data, is part of the error logs or administrative messages, this is a finding.
```
**Execution Command:**
```bash
# Option 1: Bash (Preferred - No third-party tools)
bash checks/application/Test-Weblogic-3/V-235994.sh \
  --domain-home /u01/oracle/user_projects/domains/base_domain

# Option 2: Python (Fallback - No third-party tools)
python3 checks/application/Test-Weblogic-3/V-235994.py \
  --domain-home /u01/oracle/user_projects/domains/base_domain

# With JSON output
bash checks/application/Test-Weblogic-3/V-235994.sh \
  --domain-home /u01/oracle/user_projects/domains/base_domain \
  --output-json results/V-235994.json

# Option 3: WLST (Third-party - use if native tools insufficient)
# Requires: Oracle WebLogic Scripting Tool (WLST)
wlst.sh checks/application/Test-Weblogic-1/V-235994.py \
  --admin-url t3://localhost:7001 \
  --username weblogic \
  --password <password>
```

**NIST SP 800-53 Rev 4:** SI-11 a

--------------------------------------------------------------------------------

#### V-235996 - WBLC-09-000257
**Severity:** MEDIUM

**Rule Title:** Oracle WebLogic must provide system notifications to a list of response personnel who are identified by name and/or role.

**Automation Status:** Automatable

**Automation Method:** Bash/Python (config.xml parsing)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python/powershell)

**Requires Elevation:** Yes (WebLogic Admin credentials)

**🔧 Configuration Dependencies:**
- ⚠️ **ENVIRONMENT-SPECIFIC**: This check requires site-specific or organizational values
- ⚠️ **SYSTEM-SPECIFIC**: This check depends on deployment/installation-specific configuration

**Notes:**
- Admin Console check - can be automated via native tools (bash/python parsing config.xml)

**Environment/System Annotations:**
- Environment-specific: Contains "as needed"
- System-specific: Contains "custom"

**Check Content:**
```
1. Access AC
2. From 'Domain Structure', select 'Diagnostics' -> 'Diagnostic Modules' 
3. Select 'Module-HealthState' from 'Diagnostic System Modules' list
4. Select 'Configuration' tab -> 'Watches and Notifications' tab. Select the 'Watches' tab from the bottom of page
5. Ensure 'ServerHealthWatch' row has 'Enabled' column value set to 'true'
6. Select 'Configuration' tab -> 'Watches and Notifications' tab. Select the 'Notifications' tab from the bottom of page
7. Ensure 'ServerHealthNotificati...
```
**Execution Command:**
```bash
# Option 1: Bash (Preferred - No third-party tools)
bash checks/application/Test-Weblogic-3/V-235996.sh \
  --domain-home /u01/oracle/user_projects/domains/base_domain

# Option 2: Python (Fallback - No third-party tools)
python3 checks/application/Test-Weblogic-3/V-235996.py \
  --domain-home /u01/oracle/user_projects/domains/base_domain

# With JSON output
bash checks/application/Test-Weblogic-3/V-235996.sh \
  --domain-home /u01/oracle/user_projects/domains/base_domain \
  --output-json results/V-235996.json

```

**NIST SP 800-53 Rev 4:** AU-5 a

--------------------------------------------------------------------------------

#### V-235998 - WBLC-10-000271
**Severity:** MEDIUM

**Rule Title:** Oracle WebLogic must be managed through a centralized enterprise tool.

**Automation Status:** Automatable

**Automation Method:** Bash/Python (config.xml parsing)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python/powershell)

**Requires Elevation:** Yes (WebLogic Admin credentials)

**Notes:**
- Admin Console check - can be automated via native tools (bash/python parsing config.xml)

**Check Content:**
```
Review the Oracle WebLogic configuration to determine if a tool, such as Oracle Enterprise Manager, is in place to centrally manage enterprise functionality needed for Oracle WebLogic. If a tool is not in place to centrally manage enterprise functionality, this is a finding.
```
**Execution Command:**
```bash
# Option 1: Bash (Preferred - No third-party tools)
bash checks/application/Test-Weblogic-3/V-235998.sh \
  --domain-home /u01/oracle/user_projects/domains/base_domain

# Option 2: Python (Fallback - No third-party tools)
python3 checks/application/Test-Weblogic-3/V-235998.py \
  --domain-home /u01/oracle/user_projects/domains/base_domain

# With JSON output
bash checks/application/Test-Weblogic-3/V-235998.sh \
  --domain-home /u01/oracle/user_projects/domains/base_domain \
  --output-json results/V-235998.json

```

**NIST SP 800-53 Rev 4:** CM-6 b

--------------------------------------------------------------------------------

### Partially Automatable (2 checks)

#### V-235997 - WBLC-10-000270
**Severity:** MEDIUM

**Rule Title:** Oracle WebLogic must be integrated with a tool to monitor audit subsystem failure notification information that is sent out (e.g., the recipients of the message and the nature of the failure).

**Automation Status:** Partially Automatable

**Automation Method:** Bash/Python or WLST

**Preferred Tool:** Bash/Python (preferred), WLST (if needed)

**Third-Party Tools (Optional):**
- WLST - WebLogic Scripting Tool (optional)

**Requires Elevation:** Yes (WebLogic Admin credentials)

**🔧 Configuration Dependencies:**
- ⚠️ **ENVIRONMENT-SPECIFIC**: This check requires site-specific or organizational values

**Notes:**
- May require bash/python scripting or WLST with manual validation

**Environment/System Annotations:**
- Environment-specific: Contains "designated"

**Check Content:**
```
Review the configuration of Oracle WebLogic to determine if a tool, such as Oracle Diagnostic Framework, is in place to monitor audit subsystem failure notification information that is sent out. 

If a tool is not in place to monitor audit subsystem failure notification information that is sent, this is a finding.
```
**Execution Command:**
```bash
# Option 1: Bash (Preferred - No third-party tools)
bash checks/application/Test-Weblogic-3/V-235997.sh \
  --domain-home /u01/oracle/user_projects/domains/base_domain

# Option 2: Python (Fallback - No third-party tools)
python3 checks/application/Test-Weblogic-3/V-235997.py \
  --domain-home /u01/oracle/user_projects/domains/base_domain

# With JSON output
bash checks/application/Test-Weblogic-3/V-235997.sh \
  --domain-home /u01/oracle/user_projects/domains/base_domain \
  --output-json results/V-235997.json

# Option 3: WLST (Third-party - use if native tools insufficient)
# Requires: Oracle WebLogic Scripting Tool (WLST)
wlst.sh checks/application/Test-Weblogic-1/V-235997.py \
  --admin-url t3://localhost:7001 \
  --username weblogic \
  --password <password>
```

**NIST SP 800-53 Rev 4:** CM-6 b

--------------------------------------------------------------------------------

#### V-235999 - WBLC-10-000272
**Severity:** MEDIUM

**Rule Title:** Oracle WebLogic must be integrated with a tool to implement multi-factor user authentication.

**Automation Status:** Partially Automatable

**Automation Method:** Bash/Python or WLST

**Preferred Tool:** Bash/Python (preferred), WLST (if needed)

**Third-Party Tools (Optional):**
- WLST - WebLogic Scripting Tool (optional)

**Requires Elevation:** Yes (WebLogic Admin credentials)

**Notes:**
- May require bash/python scripting or WLST with manual validation

**Check Content:**
```
Review the WebLogic configuration to determine if a tool, such as Oracle Access Manager, is in place to implement multi-factor authentication for the users. If a tool is not in place to implement multi-factor authentication, this is a finding.
```
**Execution Command:**
```bash
# Option 1: Bash (Preferred - No third-party tools)
bash checks/application/Test-Weblogic-3/V-235999.sh \
  --domain-home /u01/oracle/user_projects/domains/base_domain

# Option 2: Python (Fallback - No third-party tools)
python3 checks/application/Test-Weblogic-3/V-235999.py \
  --domain-home /u01/oracle/user_projects/domains/base_domain

# With JSON output
bash checks/application/Test-Weblogic-3/V-235999.sh \
  --domain-home /u01/oracle/user_projects/domains/base_domain \
  --output-json results/V-235999.json

# Option 3: WLST (Third-party - use if native tools insufficient)
# Requires: Oracle WebLogic Scripting Tool (WLST)
wlst.sh checks/application/Test-Weblogic-1/V-235999.py \
  --admin-url t3://localhost:7001 \
  --username weblogic \
  --password <password>
```

**NIST SP 800-53 Rev 4:** CM-6 b

--------------------------------------------------------------------------------

### Manual (8 checks)

#### V-235931 - WBLC-01-000013
**Severity:** MEDIUM

**Rule Title:** Oracle WebLogic must ensure remote sessions for accessing security functions and security-relevant information are audited.

**Automation Status:** Manual

**Automation Method:** Manual review required

**Preferred Tool:** N/A (manual)

**Third-Party Tools:** None (uses native bash/python/powershell)

**Requires Elevation:** Yes (WebLogic Admin credentials)

**🔧 Configuration Dependencies:**
- ⚠️ **SYSTEM-SPECIFIC**: This check depends on deployment/installation-specific configuration

**Notes:**
- Contains keyword: "policy"

**Environment/System Annotations:**
- System-specific: Contains "custom"

**Check Content:**
```
1. Access EM 
2. Select the domain from the navigation tree, and use the dropdown to select 'WebLogic Domain' -> 'Security' -> 'Audit Policy' 
3. Select 'Oracle Platform Security Services' from the 'Audit Component Name' dropdown
4. Beneath 'Audit Policy Settings' section, ensure that the value 'Custom' is set in the 'Audit Level' dropdown
5. Beneath 'Audit Policy Settings' section, ensure that every checkbox is selected under the 'Select For Audit' column of the policy category table

If all au...
```

**NIST SP 800-53 Rev 4:** AC-17 (1)

--------------------------------------------------------------------------------

#### V-235935 - WBLC-01-000030
**Severity:** MEDIUM

**Rule Title:** Oracle WebLogic must provide access logging that ensures users who are granted a privileged role (or roles) have their privileged activity logged.

**Automation Status:** Manual

**Automation Method:** Manual review required

**Preferred Tool:** N/A (manual)

**Third-Party Tools:** None (uses native bash/python/powershell)

**Requires Elevation:** Yes (WebLogic Admin credentials)

**Notes:**
- Contains keyword: "policy"

**Check Content:**
```
1. Access EM 
2. Select the domain from the navigation tree, and use the dropdown to select 'WebLogic Domain' -> 'Security' -> 'Audit Policy' 
3. Select 'Oracle Platform Security Services' from the 'Audit Component Name' dropdown
4. Beneath 'Audit Policy Settings' section, ensure that the comma-delimited list of privileged users (e.g., WebLogic, etc.) is set in the 'Users to Always Audit' field

If all privileged users are not listed in the 'Users to Always Audit' field, this is a finding.
```

**NIST SP 800-53 Rev 4:** AU-12 c

--------------------------------------------------------------------------------

#### V-235936 - WBLC-01-000032
**Severity:** MEDIUM

**Rule Title:** Oracle WebLogic must limit the number of failed login attempts to an organization-defined number of consecutive invalid attempts that occur within an organization-defined time period.

**Automation Status:** Manual

**Automation Method:** Manual review required

**Preferred Tool:** N/A (manual)

**Third-Party Tools:** None (uses native bash/python/powershell)

**Requires Elevation:** Yes (WebLogic Admin credentials)

**🔧 Configuration Dependencies:**
- ⚠️ **ENVIRONMENT-SPECIFIC**: This check requires site-specific or organizational values

**Notes:**
- Contains keyword: "obtain"

**Environment/System Annotations:**
- Environment-specific: Contains "authorized"

**Check Content:**
```
1. Access AC
2. From 'Domain Structure', select 'Security Realms'
3. Select realm to configure (default is 'myrealm')
4. Select 'Configuration' tab -> 'User Lockout' tab
5. Ensure the following field values are set:
'Lockout Threshold' = 3
'Lockout Duration' = 15
'Lockout Reset Duration' = 15

If 'Lockout Threshold' is not set to 3 or 'Lockout Duration' is not set to 15 or 'Lockout Reset Duration' is not set to 15, this is a finding.
```

**NIST SP 800-53 Rev 4:** AC-7 a

--------------------------------------------------------------------------------

#### V-235938 - WBLC-01-000034
**Severity:** MEDIUM

**Rule Title:** Oracle WebLogic must automatically lock accounts when the maximum number of unsuccessful login attempts is exceeded for an organization-defined time period or until the account is unlocked by an administrator.

**Automation Status:** Manual

**Automation Method:** Manual review required

**Preferred Tool:** N/A (manual)

**Third-Party Tools:** None (uses native bash/python/powershell)

**Requires Elevation:** Yes (WebLogic Admin credentials)

**🔧 Configuration Dependencies:**
- ⚠️ **ENVIRONMENT-SPECIFIC**: This check requires site-specific or organizational values

**Notes:**
- Contains keyword: "obtain"

**Environment/System Annotations:**
- Environment-specific: Contains "authorized"

**Check Content:**
```
1. Access AC
2. From 'Domain Structure', select 'Security Realms'
3. Select realm to configure (default is 'myrealm')
4. Select 'Configuration' tab -> 'User Lockout' tab
5. Ensure the following field values are set:
'Lockout Threshold' = 3
'Lockout Duration' = 15
'Lockout Reset Duration' = 15

If 'Lockout Threshold' is not set to 3 or 'Lockout Duration' is not set to 15 or 'Lockout Reset Duration' is not set to 15, this is a finding.

```

**NIST SP 800-53 Rev 4:** CM-6 b

--------------------------------------------------------------------------------

#### V-235939 - WBLC-02-000062
**Severity:** MEDIUM

**Rule Title:** Oracle WebLogic must protect against an individual falsely denying having performed a particular action.

**Automation Status:** Manual

**Automation Method:** Manual review required

**Preferred Tool:** N/A (manual)

**Third-Party Tools:** None (uses native bash/python/powershell)

**Requires Elevation:** Yes (WebLogic Admin credentials)

**🔧 Configuration Dependencies:**
- ⚠️ **SYSTEM-SPECIFIC**: This check depends on deployment/installation-specific configuration

**Notes:**
- Contains keyword: "policy"

**Environment/System Annotations:**
- System-specific: Contains "custom"

**Check Content:**
```
1. Access EM 
2. Select the domain from the navigation tree, and use the dropdown to select 'WebLogic Domain' -> 'Security' -> 'Audit Policy' 
3. Select 'Oracle Platform Security Services' from the 'Audit Component Name' dropdown
4. Beneath 'Audit Policy Settings' section, ensure that the value 'Custom' is set in the 'Audit Level' dropdown
5. Beneath 'Audit Policy Settings' section, ensure that every checkbox is selected under the 'Select For Audit' column of the policy category table
6. Select ...
```

**NIST SP 800-53 Rev 4:** AU-10

--------------------------------------------------------------------------------

#### V-235985 - WBLC-08-000224
**Severity:** MEDIUM

**Rule Title:** Oracle WebLogic must terminate user sessions upon user logout or any other organization- or policy-defined session termination events such as idle time limit exceeded.

**Automation Status:** Manual

**Automation Method:** Manual review required

**Preferred Tool:** N/A (manual)

**Third-Party Tools:** None (uses native bash/python/powershell)

**Requires Elevation:** Yes (WebLogic Admin credentials)

**Notes:**
- Contains keyword: "policy"

**Check Content:**
```
1. Access AC 
2. From 'Domain Structure', select 'Deployments'
3. Sort 'Deployments' table by 'Type' by click the column header
4. Select an 'Enterprise Application' or 'Web Application' to check the session timeout setting
5. Select 'Configuration' tab -> 'Application' tab for deployments of 'Enterprise Application' type
Select 'Configuration' tab -> 'General' tab for deployments of 'Web Application' type
6. Ensure 'Session Timeout' field value is set to organization- or policy-defined session ...
```

**NIST SP 800-53 Rev 4:** SC-23 (1)

--------------------------------------------------------------------------------

#### V-235993 - WBLC-09-000252
**Severity:** LOW

**Rule Title:** Oracle WebLogic must identify potentially security-relevant error conditions.

**Automation Status:** Manual

**Automation Method:** Manual review required

**Preferred Tool:** N/A (manual)

**Third-Party Tools:** None (uses native bash/python/powershell)

**Requires Elevation:** Yes (WebLogic Admin credentials)

**🔧 Configuration Dependencies:**
- ⚠️ **ENVIRONMENT-SPECIFIC**: This check requires site-specific or organizational values

**Notes:**
- Contains keyword: "policy"

**Environment/System Annotations:**
- Environment-specific: Contains "organizational"

**Check Content:**
```
1. Access EM 
2. Expand the domain from the navigation tree, and select the AdminServer
3. Use the dropdown to select 'WebLogic Server' -> 'Logs' -> 'Log Configuration'
4. Select the 'Log Levels' tab, and within the table, expand 'Root Logger' node
5. Log levels for system-related events can be set here
6. Select the domain from the navigation tree, and use the dropdown to select 'WebLogic Domain' -> 'Security' -> 'Audit Policy' 
7. Select 'Oracle Platform Security Services' from the 'Audit Comp...
```

**NIST SP 800-53 Rev 4:** SI-11 a

--------------------------------------------------------------------------------

#### V-235995 - WBLC-09-000254
**Severity:** MEDIUM

**Rule Title:** Oracle WebLogic must restrict error messages so only authorized personnel may view them.

**Automation Status:** Manual

**Automation Method:** Manual review required

**Preferred Tool:** N/A (manual)

**Third-Party Tools:** None (uses native bash/python/powershell)

**Requires Elevation:** Yes (WebLogic Admin credentials)

**🔧 Configuration Dependencies:**
- ⚠️ **ENVIRONMENT-SPECIFIC**: This check requires site-specific or organizational values

**Notes:**
- Contains keyword: "policy"

**Environment/System Annotations:**
- Environment-specific: Contains "organizational"
- Environment-specific: Contains "authorized"
- Environment-specific: Contains "as needed"

**Check Content:**
```
1. Access AC
2. From 'Domain Structure', select 'Security Realms'
3. Select realm to configure (default is 'myrealm')
4. Select 'Users and Groups' tab -> 'Users' tab
5. From 'Users' table, select a user that must not have access to view error messages
6. From users settings page, select 'Groups' tab
7. Ensure the 'Chosen' table does not contain any of the following roles - 'Admin', 'Deployer', 'Monitor', 'Operator'
8. Repeat steps 5-7 for all users that must not have access to view error message...
```

**NIST SP 800-53 Rev 4:** SI-11 b

--------------------------------------------------------------------------------

## Appendix

### Prerequisites
- Oracle WebLogic Server 12c installation
- WLST (WebLogic Scripting Tool) available in PATH or WLST_PATH environment variable set
- WebLogic admin credentials
- Python 3.6 or higher
- Network access to WebLogic Admin Server

### Environment Variables
```bash
export WLST_PATH=/path/to/oracle/middleware/oracle_common/common/bin/wlst.sh
export WL_HOME=/path/to/oracle/middleware/wlserver
```

### Exit Codes
- `0` - **PASS**: Check passed, no findings
- `1` - **FAIL**: Check failed, findings detected
- `2` - **N/A**: Check not applicable or requires manual review
- `3` - **ERROR**: Error occurred during check execution

### Output Formats
All automated checks support multiple output formats:

1. **Human Readable** (default to stdout)
2. **JSON** (via `--output-json` parameter)
3. **Exit Codes** (for scripting/automation)

### JSON Output Schema
```json
{
  "vuln_id": "V-235928",
  "severity": "medium",
  "stig_id": "WBLC-01-000009",
  "rule_title": "Rule description",
  "status": "NotAFinding|Open|Manual Review Required|Error",
  "finding_details": [],
  "timestamp": "ISO 8601 timestamp",
  "requires_elevation": true,
  "exit_code": 0
}
```
