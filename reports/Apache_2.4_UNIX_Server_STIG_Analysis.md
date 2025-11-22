# Apache Server 2.4 UNIX Server STIG Check Analysis Report
**Generated:** 2025-11-22 15:11:52
**STIG:** Apache Server 2.4 UNIX Server :: Release: 2 Benchmark Date: 30 Jan 2025
**Total Checks:** 47

---

## 📊 Executive Summary

### Automation Status Overview

| Automation Status | Count | Percentage | Status |
|------------------|-------|------------|--------|
| ✅ Automatable | 29 | 61.7% | Can be fully automated |
| ⚠️ Partially Automatable | 3 | 6.4% | Requires some manual validation |
| 📝 Manual Review Required | 10 | 21.3% | Cannot be automated |
| 🔍 Needs Analysis | 5 | 10.6% | Automation feasibility TBD |
| **TOTAL** | **47** | **100.0%** | |

### Automation Status by Severity

| Severity | Total | Automatable | Partial | Manual | Automation Rate |
|----------|-------|-------------|---------|--------|----------------|
| HIGH | 5 | 4 | 0 | 1 | 80.0% |
| MEDIUM | 41 | 25 | 3 | 8 | 68.3% |
| LOW | 1 | 0 | 0 | 1 | 0.0% |
| **TOTAL** | **47** | **29** | **3** | **10** | **68.1%** |

### Configuration Dependencies

| Dependency Type | Count | Percentage | Description |
|----------------|-------|------------|-------------|
| 🌐 Environment-Specific | 8 | 17.0% | Requires site-specific/organizational values |
| 🖥️ System-Specific | 4 | 8.5% | Depends on deployment/installation config |
| ✓ Standard | 35 | 74.5% | No special dependencies |

### Severity Distribution

| Severity | Count | Percentage |
|----------|-------|------------|
| 🔴 HIGH | 5 | 10.6% |
| 🟡 MEDIUM | 41 | 87.2% |
| 🟢 LOW | 1 | 2.1% |
| **TOTAL** | **47** | **100.0%** |

### Tool Preference (Priority: Bash > PowerShell > Python > Third-Party)

| Tool Type | Count | Notes |
|-----------|-------|-------|
| Bash (Native) | 32 | Primary method - no dependencies |
| Python (Native) | 0 | Fallback - uses stdlib only |
| Third-Party Optional | 0 | All checks use native commands |
| **Minimal Third-Party** | **32** | **68.1% can run without third-party tools** |

## Summary
- **Automatable Checks:** 29 (61.7%)
- **Partially Automatable:** 3 (6.4%)
- **Manual Review Required:** 10 (21.3%)
- **Needs Analysis:** 5 (10.6%)

### Environment/System Specific Checks
- **Environment-Specific:** 8 (17.0%)
  - *These checks require site-specific, organizational, or approved values*
- **System-Specific:** 4 (8.5%)
  - *These checks depend on deployment or installation-specific configurations*

### Severity Distribution
- **High:** 5
- **Medium:** 41
- **Low:** 1

---

## Detailed Check Analysis

### Automatable (29 checks)

#### V-214228 - AS24-U1-000010
**Severity:** MEDIUM

**Rule Title:** The Apache web server must limit the number of allowed simultaneous session requests.

**Automation Status:** Automatable

**Automation Method:** Bash (grep/awk/sed for config parsing)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**Notes:**
- Configuration file parsing (httpd.conf/ssl.conf)

**Check Content:**
```
Determine the location of the "HTTPD_ROOT" directory and the "httpd.conf" file:

# apachectl -V | egrep -i 'httpd_root|server_config_file'
-D HTTPD_ROOT="/etc/httpd"
-D SERVER_CONFIG_FILE="conf/httpd.conf"

Note: The apachectl front end is the preferred method for locating the Apache httpd file. For some Linux distributions, "apache2ctl -V" or  "httpd -V" can also be used.

Search for the directives "KeepAlive" and "MaxKeepAliveRequests" in the "httpd.conf" file:

# cat /<path_to_file>/httpd.con...
```
**NIST SP 800-53 Rev 4:** AC-10
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-214229 - AS24-U1-000020
**Severity:** MEDIUM

**Rule Title:** The Apache web server must perform server-side session management.

**Automation Status:** Automatable

**Automation Method:** Bash (grep/awk/sed for config parsing)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**Notes:**
- Configuration file parsing (httpd.conf/ssl.conf)

**Check Content:**
```
Issue the following command:
httpd -M |grep -E 'session_module|usertrack'

Expected output:
usertrack_module (shared)
session_module (shared)

If results do not return both "usertrack_module (shared)" and "session_module (shared)", this is a finding.

Alternatively, determine the location of the "HTTPD_ROOT" directory and the "httpd.conf" file:

# apachectl -V | egrep -i 'httpd_root|server_config_file'
-D HTTPD_ROOT="/etc/httpd"
-D SERVER_CONFIG_FILE="conf/httpd.conf"

Note: The apachectl front ...
```
**NIST SP 800-53 Rev 4:** AC-10
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-214231 - AS24-U1-000065
**Severity:** MEDIUM

**Rule Title:** The Apache web server must have system logging enabled.

**Automation Status:** Automatable

**Automation Method:** Bash (grep/awk/sed for config parsing)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**🔧 Configuration Dependencies:**
- ⚠️ **SYSTEM-SPECIFIC**: This check depends on deployment/installation-specific configuration

**Notes:**
- Configuration file parsing (httpd.conf/ssl.conf)

**Check Content:**
```
Determine the location of the "HTTPD_ROOT" directory and the "httpd.conf" file:

# apachectl -V | egrep -i 'httpd_root|server_config_file'
-D HTTPD_ROOT="/etc/httpd"
-D SERVER_CONFIG_FILE="conf/httpd.conf"

Note: The apachectl front end is the preferred method for locating the Apache httpd file. For some Linux distributions, "apache2ctl -V" or  "httpd -V" can also be used.

Search for the directive "CustomLog" in the "httpd.conf" file:

# cat /<path_to_file>/httpd.conf | grep -i "CustomLog"

If ...
```
**NIST SP 800-53 Rev 4:** CM-6 b
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-214232 - AS24-U1-000070
**Severity:** MEDIUM

**Rule Title:** The Apache web server must generate, at a minimum, log records for system startup and shutdown, system access, and system authentication events.

**Automation Status:** Automatable

**Automation Method:** Bash (grep/awk/sed for config parsing)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**🔧 Configuration Dependencies:**
- ⚠️ **SYSTEM-SPECIFIC**: This check depends on deployment/installation-specific configuration

**Notes:**
- Configuration file parsing (httpd.conf/ssl.conf)

**Check Content:**
```
Verify the Log Configuration Module is loaded:
# httpd -M | grep -i log_config_module
Output:  log_config_module (shared)

If the "log_config_module" is not enabled, this is a finding.

Determine the location of the "HTTPD_ROOT" directory and the "httpd.conf" file:

# apachectl -V | egrep -i 'httpd_root|server_config_file'
-D HTTPD_ROOT="/etc/httpd"
-D SERVER_CONFIG_FILE="conf/httpd.conf"

Note: The apachectl front end is the preferred method for locating the Apache httpd file. For some Linux di...
```
**NIST SP 800-53 Rev 4:** AU-3
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-214238 - AS24-U1-000230
**Severity:** MEDIUM

**Rule Title:** Expansion modules must be fully reviewed, tested, and signed before they can exist on a production Apache web server.

**Automation Status:** Automatable

**Automation Method:** Bash (apachectl/httpd commands)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**Notes:**
- Apache command-line tool verification

**Check Content:**
```
Enter the following command:

"httpd -M"

This will provide a list of the loaded modules. Validate that all displayed modules are required for operations.

If any module is not required for operation, this is a finding.

Note: The following modules are needed for basic web function and do not need to be reviewed:

core_module
http_module
so_module
mpm_prefork_module

For a complete list of signed Apache Modules, review https://httpd.apache.org/docs/2.4/mod/.
```
**NIST SP 800-53 Rev 4:** CM-5 (3)

--------------------------------------------------------------------------------

#### V-214239 - AS24-U1-000240
**Severity:** MEDIUM

**Rule Title:** The Apache web server must not perform user management for hosted applications.

**Automation Status:** Automatable

**Automation Method:** Bash (native commands)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**Notes:**
- Command-line verification possible

**Check Content:**
```
Review the web server documentation and configuration to determine if the web server is being used as a user management application.
 
Search for "AuthUserFile" in the configuration files in the installed Apache Path.
 
Example:

grep -rin AuthUserFile *
 
If there are uncommented lines pointing to files on disk using the above configuration option, this is a finding.
```
**NIST SP 800-53 Rev 4:** CM-7 a
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-214240 - AS24-U1-000250
**Severity:** MEDIUM

**Rule Title:** The Apache web server must only contain services and functions necessary for operation.

**Automation Status:** Automatable

**Automation Method:** Bash (file/directory checks)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**Check Content:**
```
If the site requires the use of a particular piece of software, verify that the Information System Security Officer (ISSO) maintains documentation identifying this software as necessary for operations. The software must be operated at the vendorâ€™s current patch level and must be a supported vendor release._x000D_
_x000D_
If programs or utilities that meet the above criteria are installed on the web server and appropriate documentation and signatures are in evidence, this is not a finding._x000...
```
**NIST SP 800-53 Rev 4:** CM-7 a
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-214242 - AS24-U1-000270
**Severity:** HIGH

**Rule Title:** The Apache web server must provide install options to exclude the installation of documentation, sample code, example applications, and tutorials.

**Automation Status:** Automatable

**Automation Method:** Bash (file/directory checks)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**🔧 Configuration Dependencies:**
- ⚠️ **SYSTEM-SPECIFIC**: This check depends on deployment/installation-specific configuration

**Check Content:**
```
Verify the document root directory and the configuration files do not provide for default index.html or welcome page._x000D_
_x000D_
Verify the Apache User Manual content is not installed by checking the configuration files for manual location directives._x000D_
_x000D_
Verify the Apache configuration files do not have the Server Status handler configured._x000D_
_x000D_
Verify the Server Information handler is not configured._x000D_
_x000D_
Verify that any other handler configurations such as p...
```
**NIST SP 800-53 Rev 4:** CM-7 a
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-214245 - AS24-U1-000330
**Severity:** MEDIUM

**Rule Title:** The Apache web server must have Web Distributed Authoring (WebDAV) disabled.

**Automation Status:** Automatable

**Automation Method:** Bash (apachectl/httpd commands)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**Notes:**
- Apache command-line tool verification

**Check Content:**
```
In a command line, run "httpd -M | sort" to view a list of installed modules.

If any of the following modules are present, this is a finding:

dav_module
dav_fs_module
dav_lock_module
```
**NIST SP 800-53 Rev 4:** CM-7 a
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-214246 - AS24-U1-000360
**Severity:** MEDIUM

**Rule Title:** The Apache web server must be configured to use a specified IP address and port.

**Automation Status:** Automatable

**Automation Method:** Bash (grep/awk/sed for config parsing)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**Notes:**
- Configuration file parsing (httpd.conf/ssl.conf)

**Check Content:**
```
Determine the location of the "HTTPD_ROOT" directory and the "httpd.conf" file:

# apachectl -V | egrep -i 'httpd_root|server_config_file'
-D HTTPD_ROOT="/etc/httpd"
-D SERVER_CONFIG_FILE="conf/httpd.conf"

Note: The apachectl front end is the preferred method for locating the Apache httpd file. For some Linux distributions, "apache2ctl -V" or  "httpd -V" can also be used. 
Search for the "Listen" directive:

# cat /<path_to_file>/httpd.conf | grep -i "Listen"

Verify that any enabled "Listen" d...
```
**NIST SP 800-53 Rev 4:** IA-5 (2) (b)
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-214247 - AS24-U1-000430
**Severity:** MEDIUM

**Rule Title:** Apache web server accounts accessing the directory tree, the shell, or other operating system functions and utilities must only be administrative accounts.

**Automation Status:** Automatable

**Automation Method:** Bash (file/directory checks)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**Check Content:**
```
Review the web server documentation and configuration to determine what web server accounts are available on the server.

Any directories or files owned by anyone other than an administrative service account is a finding. 

If non-privileged web server accounts are available with access to functions, directories, or files not needed for the role of the account, this is a finding.
```
**NIST SP 800-53 Rev 4:** SC-2
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-214250 - AS24-U1-000460
**Severity:** MEDIUM

**Rule Title:** The Apache web server must invalidate session identifiers upon hosted application user logout or other session termination.

**Automation Status:** Automatable

**Automation Method:** Bash (grep/awk/sed for config parsing)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**Notes:**
- Configuration file parsing (httpd.conf/ssl.conf)

**Check Content:**
```
Determine the location of the "HTTPD_ROOT" directory and the "httpd.conf" file:

# apachectl -V | egrep -i 'httpd_root|server_config_file'
-D HTTPD_ROOT="/etc/httpd"
-D SERVER_CONFIG_FILE="conf/httpd.conf"

Note: The apachectl front end is the preferred method for locating the Apache httpd file. For some Linux distributions, "apache2ctl -V" or  "httpd -V" can also be used. 

Search for the following directive:

"SessionMaxAge"

# cat /<path_to_file>/httpd.conf | grep -i "SessionMaxAge"

Verify t...
```
**NIST SP 800-53 Rev 4:** SC-23 (1)
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-214251 - AS24-U1-000470
**Severity:** MEDIUM

**Rule Title:** Cookies exchanged between the Apache web server and client, such as session cookies, must have security settings that disallow cookie access outside the originating Apache web server and hosted application.

**Automation Status:** Automatable

**Automation Method:** Bash (apachectl/httpd commands)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**Notes:**
- Apache command-line tool verification

**Check Content:**
```
Note: For web servers acting as a public facing with static content that do not require authentication, this is Not Applicable._x000D_
_x000D_
Review the web server documentation and configuration to determine if cookies between the web server and client are accessible by applications or web servers other than the originating pair._x000D_
_x000D_
grep SessionCookieName <'INSTALL LOCATION'>/mod_session.conf_x000D_
_x000D_
Confirm that the "HttpOnly" and "Secure" settings are present in the line r...
```
**NIST SP 800-53 Rev 4:** SC-23 (3)
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-214252 - AS24-U1-000510
**Severity:** MEDIUM

**Rule Title:** The Apache web server must generate a session ID long enough that it cannot be guessed through brute force.

**Automation Status:** Automatable

**Automation Method:** Bash (grep/awk/sed for config parsing)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**Notes:**
- Configuration file parsing (httpd.conf/ssl.conf)

**Check Content:**
```
Review the web server documentation and deployed configuration to determine the length of the generated session identifiers.

First ensure that "session_crypto" is enabled:

httpd -M |grep session_crypto

If the above command returns "session_crypto_module", the module is enabled in the running server.

Determine the location of the "HTTPD_ROOT" directory and the "httpd.conf" file:

# apachectl -V | egrep -i 'httpd_root|server_config_file'
-D HTTPD_ROOT="/etc/httpd"
-D SERVER_CONFIG_FILE="conf/h...
```
**NIST SP 800-53 Rev 4:** SC-23 (3)
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-214253 - AS24-U1-000520
**Severity:** HIGH

**Rule Title:** The Apache web server must generate a session ID using as much of the character set as possible to reduce the risk of brute force.

**Automation Status:** Automatable

**Automation Method:** Bash (grep/awk/sed for config parsing)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**Notes:**
- Configuration file parsing (httpd.conf/ssl.conf)

**Check Content:**
```
Determine the location of the "HTTPD_ROOT" directory and the "httpd.conf" file:

# apachectl -V | egrep -i 'httpd_root|server_config_file'
-D HTTPD_ROOT="/etc/httpd"
-D SERVER_CONFIG_FILE="conf/httpd.conf"

Note: The apachectl front end is the preferred method for locating the Apache httpd file. For some Linux distributions, "apache2ctl -V" or  "httpd -V" can also be used. 

Verify the "unique_id_module" is loaded:

run httpd -M | grep unique_id 
If no unique_id is returned, this is a finding.
```
**NIST SP 800-53 Rev 4:** SC-23 (3)
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-214255 - AS24-U1-000590
**Severity:** MEDIUM

**Rule Title:** The Apache web server must be tuned to handle the operational requirements of the hosted application.

**Automation Status:** Automatable

**Automation Method:** Bash (grep/awk/sed for config parsing)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**Notes:**
- Configuration file parsing (httpd.conf/ssl.conf)

**Check Content:**
```
Determine the location of the "HTTPD_ROOT" directory and the "httpd.conf" file:

# apachectl -V | egrep -i 'httpd_root|server_config_file'
-D HTTPD_ROOT="/etc/httpd"
-D SERVER_CONFIG_FILE="conf/httpd.conf"

Note: The apachectl front end is the preferred method for locating the Apache httpd file. For some Linux distributions, "apache2ctl -V" or "httpd -V" can also be used. 

Verify that the "Timeout" directive is specified to have a value of "60" seconds or less.

# cat /<path_to_file>/httpd.conf...
```
**NIST SP 800-53 Rev 4:** SC-5 (1)
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-214256 - AS24-U1-000620
**Severity:** MEDIUM

**Rule Title:** Warning and error messages displayed to clients must be modified to minimize the identity of the Apache web server, patches, loaded modules, and directory paths.

**Automation Status:** Automatable

**Automation Method:** Bash (grep/awk/sed for config parsing)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**🔧 Configuration Dependencies:**
- ⚠️ **SYSTEM-SPECIFIC**: This check depends on deployment/installation-specific configuration

**Notes:**
- Configuration file parsing (httpd.conf/ssl.conf)

**Check Content:**
```
Determine the location of the "HTTPD_ROOT" directory and the "httpd.conf" file:

# apachectl -V | egrep -i 'httpd_root|server_config_file'
-D HTTPD_ROOT="/etc/httpd"
-D SERVER_CONFIG_FILE="conf/httpd.conf"

Note: The apachectl front end is the preferred method for locating the Apache httpd file. For some Linux distributions, "apache2ctl -V" or "httpd -V" can also be used. 

# cat /<path_to_file>/httpd.conf | grep -i "ErrorDocument"

If the "ErrorDocument" directive is not being used for custom e...
```
**NIST SP 800-53 Rev 4:** SI-11 a
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-214257 - AS24-U1-000630
**Severity:** MEDIUM

**Rule Title:** Debugging and trace information used to diagnose the Apache web server must be disabled.

**Automation Status:** Automatable

**Automation Method:** Bash (grep/awk/sed for config parsing)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**Notes:**
- Configuration file parsing (httpd.conf/ssl.conf)

**Check Content:**
```
Determine the location of the "HTTPD_ROOT" directory and the "httpd.conf" file:

# apachectl -V | egrep -i 'httpd_root|server_config_file'
-D HTTPD_ROOT="/etc/httpd"
-D SERVER_CONFIG_FILE="conf/httpd.conf"

Note: The apachectl front end is the preferred method for locating the Apache httpd file. For some Linux distributions, "apache2ctl -V" or  "httpd -V" can also be used. 

For any enabled "TraceEnable" directives, verify they are part of the server-level configuration (i.e., not nested in a "D...
```
**NIST SP 800-53 Rev 4:** SI-11 a
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-214258 - AS24-U1-000650
**Severity:** MEDIUM

**Rule Title:** The Apache web server must set an inactive timeout for sessions.

**Automation Status:** Automatable

**Automation Method:** Bash (grep/awk/sed for config parsing)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**Notes:**
- Configuration file parsing (httpd.conf/ssl.conf)

**Check Content:**
```
Determine the location of the "HTTPD_ROOT" directory and the "httpd.conf" file:

# apachectl -V | egrep -i 'httpd_root|server_config_file'
-D HTTPD_ROOT="/etc/httpd"
-D SERVER_CONFIG_FILE="conf/httpd.conf"

Note: The apachectl front end is the preferred method for locating the Apache httpd file. For some Linux distributions, "apache2ctl -V" or  "httpd -V" can also be used. 

Verify the "reqtimeout_module" is loaded:

Change to the root directory of Apache and run the following command to verify ...
```
**NIST SP 800-53 Rev 4:** AC-12
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-214259 - AS24-U1-000670
**Severity:** MEDIUM

**Rule Title:** The Apache web server must restrict inbound connections from nonsecure zones.

**Automation Status:** Automatable

**Automation Method:** Bash (grep/awk/sed for config parsing)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**Notes:**
- Configuration file parsing (httpd.conf/ssl.conf)

**Check Content:**
```
If external controls such as host-based firewalls are used to restrict this access, this check is Not Applicable.

Determine the location of the "HTTPD_ROOT" directory and the "httpd.conf" file:

# apachectl -V | egrep -i 'httpd_root|server_config_file'
-D HTTPD_ROOT="/etc/httpd"
-D SERVER_CONFIG_FILE="conf/httpd.conf"

Note: The apachectl front end is the preferred method for locating the Apache httpd file. For some Linux distributions, "apache2ctl -V" or  "httpd -V" can also be used. 

Search ...
```
**NIST SP 800-53 Rev 4:** AC-17 (1)
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-214261 - AS24-U1-000690
**Severity:** MEDIUM

**Rule Title:** Non-privileged accounts on the hosting system must only access Apache web server security-relevant information and functions through a distinct administrative account.

**Automation Status:** Automatable

**Automation Method:** Bash (native commands)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**Notes:**
- Command-line verification possible

**Check Content:**
```
Determine which tool or control file is used to control the configuration of the web server.

If the control of the web server is done via control files, verify who has update access to them. If tools are being used to configure the web server, determine who has access to execute the tools.

If accounts other than the System Administrator (SA), the Web Manager, or the Web Manager designees have access to the web administration tool or control files, this is a finding.
```
**NIST SP 800-53 Rev 4:** AC-6 (10)
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-214265 - AS24-U1-000750
**Severity:** MEDIUM

**Rule Title:** The Apache web server must generate log records that can be mapped to Coordinated Universal Time (UTC) or Greenwich Mean Time (GMT) which are stamped at a minimum granularity of one second.

**Automation Status:** Automatable

**Automation Method:** Bash (grep/awk/sed for config parsing)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**Notes:**
- Configuration file parsing (httpd.conf/ssl.conf)

**Check Content:**
```
Review the web server documentation and configuration to determine the time stamp format for log data.

Determine the location of the "HTTPD_ROOT" directory and the "httpd.conf" file:

# apachectl -V | egrep -i 'httpd_root|server_config_file'
-D HTTPD_ROOT="/etc/httpd"
-D SERVER_CONFIG_FILE="conf/httpd.conf"

Note: The apachectl front end is the preferred method for locating the Apache httpd file. For some Linux distributions, "apache2ctl -V" or  "httpd -V" can also be used.  

Search for the "l...
```
**NIST SP 800-53 Rev 4:** AU-8 b
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-214267 - AS24-U1-000820
**Severity:** MEDIUM

**Rule Title:** The Apache web server must be protected from being stopped by a non-privileged user.

**Automation Status:** Automatable

**Automation Method:** Bash (apachectl/httpd commands)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**Notes:**
- Apache command-line tool verification

**Check Content:**
```
Review the web server documentation and deployed configuration to determine where the process ID is stored and which utilities are used to start/stop the web server.

Locate the httpd.pid file and list its permission set and owner/group

# find / -name â€œhttpd.pid
Output should be similar to: /run/httpd/httpd.pidÂ 

# ls -laH /run/httpd/httpd.pid
Output should be similar -rw-r--r--. 1 root root 5 Jun 13 03:18 /run/httpd/httpd.pid

If the file owner/group is not an administrative service account...
```
**NIST SP 800-53 Rev 4:** SC-5
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-214268 - AS24-U1-000870
**Severity:** MEDIUM

**Rule Title:** Cookies exchanged between the Apache web server and the client, such as session cookies, must have cookie properties set to prohibit client-side scripts from reading the cookie data.

**Automation Status:** Automatable

**Automation Method:** Bash (grep/awk/sed for config parsing)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**Notes:**
- Configuration file parsing (httpd.conf/ssl.conf)

**Check Content:**
```
Verify the session cookie module is loaded

# httpd -M | grep -i session_cookie_module
Output should look similar to: session_cookie_module (shared)

Determine the location of the "HTTPD_ROOT" directory and the "httpd.conf" file:

# apachectl -V | egrep -i 'httpd_root|server_config_file'
-D HTTPD_ROOT="/etc/httpd"
-D SERVER_CONFIG_FILE="conf/httpd.conf"

Note: The apachectl front end is the preferred method for locating the Apache httpd file. For some Linux distributions, "apache2ctl -V" or  "ht...
```
**NIST SP 800-53 Rev 4:** SC-8
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-214269 - AS24-U1-000900
**Severity:** MEDIUM

**Rule Title:** The Apache web server must remove all export ciphers to protect the confidentiality and integrity of transmitted information.

**Automation Status:** Automatable

**Automation Method:** Bash (grep/awk/sed for config parsing)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**Notes:**
- Configuration file parsing (httpd.conf/ssl.conf)

**Check Content:**
```
Determine the location of the "HTTPD_ROOT" directory and the "httpd.conf" and "ssl.conf" files:

Search the httpd.conf and ssl.conf file for the following uncommented directive: SSLCipherSuite

# cat httpd.conf  | grep -i SSLCipherSuite
Output: None

# cat /etc/httpd/conf.d/ssl.conf | grep -i SSLCipherSuite
Output: SSLCipherSuite HIGH:3DES:!NULL:!MD5:!SEED:!IDEA:!EXPORT

For all enabled SSLCipherSuite directives, ensure the cipher specification string contains the kill cipher from list option fo...
```
**NIST SP 800-53 Rev 4:** SC-8
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-214270 - AS24-U1-000930
**Severity:** MEDIUM

**Rule Title:** The Apache web server must install security-relevant software updates within the configured time period directed by an authoritative source (e.g., IAVM, CTOs, DTMs, and STIGs).

**Automation Status:** Automatable

**Automation Method:** Bash (apachectl/httpd commands)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**Notes:**
- Apache command-line tool verification

**Check Content:**
```
Determine the most recent patch level of the Apache Web Server 2.4 software, as posted on the Apache HTTP Server Project website. If the Apache installation is a proprietary installation supporting an application and is supported by a vendor, determine the most recent patch level of the vendorâ€™s installation.

In a command line, type "httpd -v".

If the version is more than one version behind the most recent patch level, this is a finding.

```
**NIST SP 800-53 Rev 4:** SI-2 c
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-214271 - AS24-U1-000940
**Severity:** HIGH

**Rule Title:** The account used to run the Apache web server must not have a valid login shell and password defined.

**Automation Status:** Automatable

**Automation Method:** Bash (native commands)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**Notes:**
- Command-line verification possible

**Check Content:**
```
Identify the account that is running the "httpd" process:
# ps -ef | grep -i httpd | grep -v grep

apache   29613   996  0 Feb17 ?        00:00:00 /usr/sbin/httpd
apache   29614   996  0 Feb17 ?        00:00:00 /usr/sbin/httpd

Check to see if the account has a valid login shell:

# cut -d: -f1,7 /etc/passwd | grep -i <service_account>
apache:/sbin/nologin

If the service account has a valid login shell, verify that no password is configured for the account:

# cut -d: -f1,2 /etc/shadow | grep -...
```
**NIST SP 800-53 Rev 4:** CM-6 b
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-214273 - AS24-U1-000960
**Severity:** HIGH

**Rule Title:** The Apache web server software must be a vendor-supported version.

**Automation Status:** Automatable

**Automation Method:** Bash (apachectl/httpd commands)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**Notes:**
- Apache command-line tool verification

**Check Content:**
```
Determine the version of the Apache software that is running on the system by entering the following command:

httpd -v

If the version of Apache is not at the following version or higher, this is a finding:

Apache 2.4 (February 2012)

NOTE: In some situations, the Apache software that is being used is supported by another vendor, such as Oracle in the case of the Oracle Application Server or IBM's HTTP Server. The versions of the software in these cases may not match the version number noted a...
```
**NIST SP 800-53 Rev 4:** CM-6 b
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-214274 - AS24-U1-000970
**Severity:** MEDIUM

**Rule Title:** The Apache web server htpasswd files (if present) must reflect proper ownership and permissions.

**Automation Status:** Automatable

**Automation Method:** Bash (ls -l, stat commands)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**Notes:**
- File permission verification

**Check Content:**
```
Locate the htpasswd file by entering the following command:

find / -name htpasswd

Navigate to that directory.

Run: ls -l htpasswd

Permissions should be: r-x r - x - - - (550)

If permissions on "htpasswd" are greater than "550", this is a finding.

Verify the owner is the SA or Web Manager account.

If another account has access to this file, this is a finding.
```
**NIST SP 800-53 Rev 4:** CM-6 b
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

### Partially Automatable (3 checks)

#### V-214230 - AS24-U1-000030
**Severity:** MEDIUM

**Rule Title:** The Apache web server must use cryptography to protect the integrity of remote sessions.

**Automation Status:** Partially Automatable

**Automation Method:** Bash (grep/awk/sed for config parsing)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**🔧 Configuration Dependencies:**
- ⚠️ **ENVIRONMENT-SPECIFIC**: This check requires site-specific or organizational values

**Notes:**
- Configuration file parsing (httpd.conf/ssl.conf)

**Check Content:**
```
Verify the "ssl module" module is loaded
# httpd -M | grep -i ssl_module
Output:  ssl_module (shared) 

If the "ssl_module" is not found, this is a finding. 

Determine the location of the "HTTPD_ROOT" directory and the "httpd.conf" file:

# apachectl -V | egrep -i 'httpd_root|server_config_file'
-D HTTPD_ROOT="/etc/httpd"
-D SERVER_CONFIG_FILE="conf/httpd.conf"

Note: The apachectl front end is the preferred method for locating the Apache httpd file. For some Linux distributions, "apache2ctl -V...
```
**NIST SP 800-53 Rev 4:** AC-17 (2)
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-214235 - AS24-U1-000180
**Severity:** MEDIUM

**Rule Title:** The Apache web server log files must only be accessible by privileged users.

**Automation Status:** Partially Automatable

**Automation Method:** Bash (grep/awk/sed for config parsing)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**🔧 Configuration Dependencies:**
- ⚠️ **ENVIRONMENT-SPECIFIC**: This check requires site-specific or organizational values

**Notes:**
- Configuration file parsing (httpd.conf/ssl.conf)

**Check Content:**
```
Determine the location of the "HTTPD_ROOT" directory and the "httpd.conf" file:

# apachectl -V | egrep -i 'httpd_root|server_config_file'
-D HTTPD_ROOT="/etc/httpd"
-D SERVER_CONFIG_FILE="conf/httpd.conf"

Note: The apachectl front end is the preferred method for locating the Apache httpd file. For some Linux distributions, "apache2ctl -V" or  "httpd -V" can also be used.

Work with the Administrator to locate the log files:
Example: /etc/httpd/logs

List the POSIX permission set and owner/grou...
```
**NIST SP 800-53 Rev 4:** AU-9
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-214241 - AS24-U1-000260
**Severity:** MEDIUM

**Rule Title:** The Apache web server must not be a proxy server.

**Automation Status:** Partially Automatable

**Automation Method:** Bash (grep/awk/sed for config parsing)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**🔧 Configuration Dependencies:**
- ⚠️ **ENVIRONMENT-SPECIFIC**: This check requires site-specific or organizational values

**Notes:**
- Configuration file parsing (httpd.conf/ssl.conf)

**Check Content:**
```
If the server has been approved to be a proxy server, this requirement is Not Applicable.

Determine the location of the "HTTPD_ROOT" directory and the "httpd.conf" file:

# apachectl -V | egrep -i 'httpd_root|server_config_file'
-D HTTPD_ROOT="/etc/httpd"
-D SERVER_CONFIG_FILE="conf/httpd.conf"

Note: The apachectl front end is the preferred method for locating the Apache httpd file. For some Linux distributions, "apache2ctl -V" or "httpd -V" can also be used. 

Search for the directive "ProxyR...
```
**NIST SP 800-53 Rev 4:** CM-7 a
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

### Manual Review Required (10 checks)

#### V-214233 - AS24-U1-000130
**Severity:** MEDIUM

**Rule Title:** An Apache web server, behind a load balancer or proxy server, must produce log records containing the client IP information as the source and destination and not the load balancer or proxy IP information with each event.

**Automation Status:** Manual Review Required

**Automation Method:** Requires SA Interview

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**Notes:**
- Requires system administrator interview or consultation

**Check Content:**
```
If Apache server is not behind a load balancer or proxy server, this check is Not Applicable.

Interview the System Administrator to review the configuration of the Apache web server architecture and determine if inbound web traffic is passed through a proxy.

If the Apache web server is receiving inbound web traffic through a proxy, the audit logs must be reviewed to determine if correct source information is being passed through by the proxy server.

Determine the location of the "HTTPD_ROOT" ...
```
**NIST SP 800-53 Rev 4:** AU-3
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-214236 - AS24-U1-000190
**Severity:** MEDIUM

**Rule Title:** The log information from the Apache web server must be protected from unauthorized modification or deletion.

**Automation Status:** Manual Review Required

**Automation Method:** Documentation Review

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**🔧 Configuration Dependencies:**
- ⚠️ **ENVIRONMENT-SPECIFIC**: This check requires site-specific or organizational values

**Notes:**
- Requires manual review of documentation

**Check Content:**
```
Verify the log information from the web server must be protected from unauthorized modification.

Review the web server documentation and deployed configuration settings to determine if the web server logging features protect log information from unauthorized modification.
 
Review file system settings to verify the log files have secure file permissions. Run the following command:
 
ls -l <'INSTALL PATH'>/logs
 
If the web server log files present are owned by anyone other than an administrativ...
```
**NIST SP 800-53 Rev 4:** AU-9
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-214237 - AS24-U1-000210
**Severity:** MEDIUM

**Rule Title:** The log data and records from the Apache web server must be backed up onto a different system or media.

**Automation Status:** Manual Review Required

**Automation Method:** Requires SA Interview

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**Notes:**
- Requires system administrator interview or consultation

**Check Content:**
```
Interview the Information System Security Officer, System Administrator, Web Manager, Webmaster, or developers as necessary to determine whether a tested and verifiable backup strategy has been implemented for web server software and all web server data files.

Proposed questions:
- Who maintains the backup and recovery procedures?
- Do you have a copy of the backup and recovery procedures?
- Where is the off-site backup location?
- Is the contingency plan documented?
- When was the last time th...
```
**NIST SP 800-53 Rev 4:** AU-9 (2)
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-214243 - AS24-U1-000300
**Severity:** MEDIUM

**Rule Title:** The Apache web server must have resource mappings set to disable the serving of certain file types.

**Automation Status:** Manual Review Required

**Automation Method:** Documentation Review

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**🔧 Configuration Dependencies:**
- ⚠️ **ENVIRONMENT-SPECIFIC**: This check requires site-specific or organizational values

**Notes:**
- Requires manual review of documentation

**Check Content:**
```
Determine the location of the "HTTPD_ROOT" directory and the "httpd.conf" file:

# apachectl -V | egrep -i 'httpd_root|server_config_file'
-D HTTPD_ROOT="/etc/httpd"
-D SERVER_CONFIG_FILE="conf/httpd.conf"

Note: The apachectl front end is the preferred method for locating the Apache httpd file. For some Linux distributions, "apache2ctl -V" or  "httpd -V" can also be used.

Review any "Action" or "AddHandler" directives:

# cat /<path_to_file>/httpd.conf | grep -i "Action"
# cat /<path_to_file>/...
```
**NIST SP 800-53 Rev 4:** CM-7 a
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-214244 - AS24-U1-000310
**Severity:** MEDIUM

**Rule Title:** The Apache web server must allow the mappings to unused and vulnerable scripts to be removed.

**Automation Status:** Manual Review Required

**Automation Method:** Documentation Review

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**🔧 Configuration Dependencies:**
- ⚠️ **ENVIRONMENT-SPECIFIC**: This check requires site-specific or organizational values

**Notes:**
- Requires manual review of documentation

**Check Content:**
```
Determine the location of the "HTTPD_ROOT" directory and the "httpd.conf" file:

# apachectl -V | egrep -i 'httpd_root|server_config_file'
-D HTTPD_ROOT="/etc/httpd"
-D SERVER_CONFIG_FILE="conf/httpd.conf"

Note: The apachectl front end is the preferred method for locating the Apache httpd file. For some Linux distributions, "apache2ctl -V" or  "httpd -V" can also be used.  

Locate "cgi-bin" files and directories enabled in the Apache configuration via "Script", "ScriptAlias" or "ScriptAliasMat...
```
**NIST SP 800-53 Rev 4:** CM-7 a
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-214248 - AS24-U1-000440
**Severity:** HIGH

**Rule Title:** Apache web server application directories,  libraries, and configuration files must only be accessible to privileged users.

**Automation Status:** Manual Review Required

**Automation Method:** Documentation Review

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**Notes:**
- Requires manual review of documentation

**Check Content:**
```
Obtain a list of the user accounts for the system, noting the privileges for each account.

Verify with the SA or the Information System Security Officer (ISSO) that all privileged accounts are mission essential and documented.

Verify with the SA or the ISSO that all non-administrator access to shell scripts and operating system functions are mission essential and documented.

If undocumented privileged accounts are present, this is a finding.

If undocumented access to shell scripts or operati...
```
**NIST SP 800-53 Rev 4:** CM-7 a
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-214254 - AS24-U1-000550
**Severity:** MEDIUM

**Rule Title:** The Apache web server must be built to fail to a known safe state if system initialization fails, shutdown fails, or aborts fail.

**Automation Status:** Manual Review Required

**Automation Method:** Requires SA Interview

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**Notes:**
- Requires system administrator interview or consultation

**Check Content:**
```
Interview the System Administrator for the Apache 2.4 web server.

Ask for documentation on the disaster recovery methods tested and planned for the Apache 2.4 web server in the event of the necessity for rollback.

If documentation for a disaster recovery has not been established, this is a finding.
```
**NIST SP 800-53 Rev 4:** SC-24
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-214260 - AS24-U1-000680
**Severity:** MEDIUM

**Rule Title:** The Apache web server must be configured to immediately disconnect or disable remote access to the hosted applications.

**Automation Status:** Manual Review Required

**Automation Method:** Requires SA Interview

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**Notes:**
- Requires system administrator interview or consultation

**Check Content:**
```
Interview the SA and Web Manager.

Ask for documentation for the Apache web server administration.

Verify there are documented procedures for shutting down an Apache website in the event of an attack. 

The procedure must, at a minimum, provide the following steps:

1. Determine the respective website for the application at risk of an attack.

2. Determine the location of the "HTTPD_ROOT" directory and the "httpd.conf" file:

# apachectl -V | egrep -i 'httpd_root|server_config_file|pidlog'
-D H...
```
**NIST SP 800-53 Rev 4:** AC-17 (9)
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-214266 - AS24-U1-000780
**Severity:** MEDIUM

**Rule Title:** The Apache web server must prohibit or restrict the use of nonsecure or unnecessary ports, protocols, modules, and/or services.

**Automation Status:** Manual Review Required

**Automation Method:** Documentation Review

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**🔧 Configuration Dependencies:**
- ⚠️ **ENVIRONMENT-SPECIFIC**: This check requires site-specific or organizational values

**Notes:**
- Requires manual review of documentation

**Check Content:**
```
Review the website to determine if HTTP and HTTPs are used in accordance with well known ports (e.g., 80 and 443) or those ports and services as registered and approved for use by the DoD PPSM. Any variation in PPS will be documented, registered, and approved by the PPSM. If not, this is a finding.
```
**NIST SP 800-53 Rev 4:** CM-7 (1) (b)
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-214272 - AS24-U1-000950
**Severity:** LOW

**Rule Title:** The Apache web server must be configured in accordance with the security configuration settings based on DoD security configuration or implementation guidance, including STIGs, NSA configuration guides, CTOs, and DTMs.

**Automation Status:** Manual Review Required

**Automation Method:** Documentation Review

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**🔧 Configuration Dependencies:**
- ⚠️ **ENVIRONMENT-SPECIFIC**: This check requires site-specific or organizational values

**Notes:**
- Requires manual review of documentation

**Check Content:**
```
Review the website to determine if "HTTP" and "HTTPS" are used in accordance with well-known ports (e.g., 80 and 443) or those ports and services as registered and approved for use by the DoD Ports, Protocols, and Services Management (PPSM).

Verify that any variation in PPS is documented, registered, and approved by the PPSM.

If well-known ports and services are not approved for used by PPSM, this is a finding.
```
**NIST SP 800-53 Rev 4:** CM-6 b
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

### Needs Analysis (5 checks)

#### V-214234 - AS24-U1-000160
**Severity:** MEDIUM

**Rule Title:** The Apache web server must use a logging mechanism that is configured to alert the Information System Security Officer (ISSO) and System Administrator (SA) in the event of a processing failure.

**Automation Status:** Needs Analysis

**Automation Method:** TBD

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**Notes:**
- Automation feasibility needs further analysis

**Check Content:**
```
Work with the SIEM administrator to determine if an alert is configured when audit data is no longer received as expected.

If there is no alert configured, this is a finding.
```
**NIST SP 800-53 Rev 4:** AU-5 a
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-214249 - AS24-U1-000450
**Severity:** MEDIUM

**Rule Title:** The Apache web server must separate the hosted applications from hosted Apache web server management functionality.

**Automation Status:** Needs Analysis

**Automation Method:** TBD

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**Notes:**
- Automation feasibility needs further analysis

**Check Content:**
```
Review the web server documentation and deployed configuration to determine whether hosted application functionality is separated from web server management functions.

If the functions are not separated, this is a finding.
```
**NIST SP 800-53 Rev 4:** SC-2
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-214262 - AS24-U1-000710
**Severity:** MEDIUM

**Rule Title:** The Apache web server must use a logging mechanism that is configured to allocate log record storage capacity large enough to accommodate the logging requirements of the Apache web server.

**Automation Status:** Needs Analysis

**Automation Method:** TBD

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**Notes:**
- Automation feasibility needs further analysis

**Check Content:**
```
Work with SIEM administrator to determine log storage capacity. 

If there is no setting within a SIEM to accommodate enough a large logging capacity, this is a finding.
```
**NIST SP 800-53 Rev 4:** AU-4
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-214263 - AS24-U1-000720
**Severity:** MEDIUM

**Rule Title:** The Apache web server must not impede the ability to write specified log record content to an audit log server.

**Automation Status:** Needs Analysis

**Automation Method:** TBD

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**Notes:**
- Automation feasibility needs further analysis

**Check Content:**
```
Work with SIEM administrator to determine audit configurations. 

If there is a setting within the SIEM that could impede the ability to write specific log record content, this is a finding.
```
**NIST SP 800-53 Rev 4:** AU-4 (1)
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-214264 - AS24-U1-000730
**Severity:** MEDIUM

**Rule Title:** The Apache web server must be configured to integrate with an organizations security infrastructure.

**Automation Status:** Needs Analysis

**Automation Method:** TBD

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**Notes:**
- Automation feasibility needs further analysis

**Check Content:**
```
Work with the SIEM administrator to determine current security integrations. 

If the SIEM is not integrated with security, this is a finding.
```
**NIST SP 800-53 Rev 4:** AU-4 (1)
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

