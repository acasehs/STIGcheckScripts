# Apache Server 2.4 UNIX Site STIG Check Analysis Report
**Generated:** 2025-11-22 15:11:52
**STIG:** Apache Server 2.4 UNIX Site :: Release: 6 Benchmark Date: 02 Apr 2025
**Total Checks:** 27

---

## 📊 Executive Summary

### Automation Status Overview

| Automation Status | Count | Percentage | Status |
|------------------|-------|------------|--------|
| ✅ Automatable | 16 | 59.3% | Can be fully automated |
| ⚠️ Partially Automatable | 3 | 11.1% | Requires some manual validation |
| 📝 Manual Review Required | 7 | 25.9% | Cannot be automated |
| 🔍 Needs Analysis | 1 | 3.7% | Automation feasibility TBD |
| **TOTAL** | **27** | **100.0%** | |

### Automation Status by Severity

| Severity | Total | Automatable | Partial | Manual | Automation Rate |
|----------|-------|-------------|---------|--------|----------------|
| MEDIUM | 26 | 16 | 3 | 6 | 73.1% |
| LOW | 1 | 0 | 0 | 1 | 0.0% |
| **TOTAL** | **27** | **16** | **3** | **7** | **70.4%** |

### Configuration Dependencies

| Dependency Type | Count | Percentage | Description |
|----------------|-------|------------|-------------|
| 🌐 Environment-Specific | 7 | 25.9% | Requires site-specific/organizational values |
| 🖥️ System-Specific | 2 | 7.4% | Depends on deployment/installation config |
| ✓ Standard | 18 | 66.7% | No special dependencies |

### Severity Distribution

| Severity | Count | Percentage |
|----------|-------|------------|
| 🔴 HIGH | 0 | 0.0% |
| 🟡 MEDIUM | 26 | 96.3% |
| 🟢 LOW | 1 | 3.7% |
| **TOTAL** | **27** | **100.0%** |

### Tool Preference (Priority: Bash > PowerShell > Python > Third-Party)

| Tool Type | Count | Notes |
|-----------|-------|-------|
| Bash (Native) | 19 | Primary method - no dependencies |
| Python (Native) | 0 | Fallback - uses stdlib only |
| Third-Party Optional | 0 | All checks use native commands |
| **Minimal Third-Party** | **19** | **70.4% can run without third-party tools** |

## Summary
- **Automatable Checks:** 16 (59.3%)
- **Partially Automatable:** 3 (11.1%)
- **Manual Review Required:** 7 (25.9%)
- **Needs Analysis:** 1 (3.7%)

### Environment/System Specific Checks
- **Environment-Specific:** 7 (25.9%)
  - *These checks require site-specific, organizational, or approved values*
- **System-Specific:** 2 (7.4%)
  - *These checks depend on deployment or installation-specific configurations*

### Severity Distribution
- **High:** 0
- **Medium:** 26
- **Low:** 1

---

## Detailed Check Analysis

### Automatable (16 checks)

#### V-214277 - AS24-U2-000020
**Severity:** MEDIUM

**Rule Title:** The Apache web server must perform server-side session management.

**Automation Status:** Automatable

**Automation Method:** Bash (apachectl/httpd commands)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**Notes:**
- Apache command-line tool verification

**Check Content:**
```
In a command line, run "httpd -M | grep -i session_module" and "httpd -M | grep -i usertrack_module". 
 
If "session_module" module and "usertrack_module" are not enabled or do not exist, this is a finding.
```
**NIST SP 800-53 Rev 4:** AC-10
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-214279 - AS24-U2-000090
**Severity:** MEDIUM

**Rule Title:** The Apache web server must produce log records containing sufficient information to establish what type of events occurred.

**Automation Status:** Automatable

**Automation Method:** Bash (grep/awk/sed for config parsing)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**Notes:**
- Configuration file parsing (httpd.conf/ssl.conf)

**Check Content:**
```
In a command line, run "httpd -M | grep -i log_config_module".  
 
If the "log_config_module" is not enabled, this is a finding. 
 
Determine the location of the "HTTPD_ROOT" directory and the "httpd.conf" file: 
 
# apachectl -V | egrep -i 'httpd_root|server_config_file'
-D HTTPD_ROOT="/etc/httpd"
-D SERVER_CONFIG_FILE="conf/httpd.conf"

Note: The apachectl front end is the preferred method for locating the Apache httpd file. For some Linux distributions "apache2ctl -V" or  "httpd -V" can also ...
```
**NIST SP 800-53 Rev 4:** AU-3
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-214284 - AS24-U2-000350
**Severity:** MEDIUM

**Rule Title:** Users and scripts running on behalf of users must be contained to the document root or home directory tree of the Apache web server.

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

Note: The apachectl front end is the preferred method for locating the Apache httpd file. For some Linux distributions "apache2ctl -V" or  "httpd -V" can also be used. 
 
Verify there is a single "Require" directive with the value of "all denied". 
 
Verify there are no "Allow" or "Deny" di...
```
**NIST SP 800-53 Rev 4:** CM-7 a
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-214285 - AS24-U2-000360
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

Note: The apachectl front end is the preferred method for locating the Apache httpd file. For some Linux distributions "apache2ctl -V" or  "httpd -V" can also be used. 
 
Verify that for each "VirtualHost" directive, there is an IP address and port. 
 
If there is not, this is a finding.
```
**NIST SP 800-53 Rev 4:** CM-7 b
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-214288 - AS24-U2-000470
**Severity:** MEDIUM

**Rule Title:** Cookies exchanged between the Apache web server and client, such as session cookies, must have security settings that disallow cookie access outside the originating Apache web server and hosted application.

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

Note: The apachectl front end is the preferred method for locating the Apache httpd file. For some Linux distributions "apache2ctl -V" or  "httpd -V" can also be used. 

Search for the "Header" directive:

# cat /<path_to_file>/httpd.conf | grep -i "Header"
 
If "HttpOnly" "secure" is not c...
```
**NIST SP 800-53 Rev 4:** SC-23 (3)
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-214290 - AS24-U2-000580
**Severity:** MEDIUM

**Rule Title:** The Apache web server document directory must be in a separate partition from the Apache web servers system files.

**Automation Status:** Automatable

**Automation Method:** Bash (grep/awk/sed for config parsing)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**Notes:**
- Configuration file parsing (httpd.conf/ssl.conf)

**Check Content:**
```
Run the following command: 
 
grep "DocumentRoot"<'INSTALL PATH'>/conf/httpd.conf 
 
Note each location following the "DocumentRoot" string. This is the configured path to the document root directory(s). 
 
Use the command df -k to view each document root's partition setup. 
 
Compare that against the results for the operating system file systems and against the partition for the web server system files, which is the result of the command: 
 
df -k <'INSTALL PATH'>/bin 
 
If the document root pa...
```
**NIST SP 800-53 Rev 4:** SC-3
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-214291 - AS24-U2-000590
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

Note: The apachectl front end is the preferred method for locating the Apache httpd file. For some Linux distributions, "apache2ctl -V" or  "httpd -V" can also be used. 

Verify the "Timeout" directive is specified to have a value of "60" seconds or less.

# cat /<path_to_file>/httpd.conf | g...
```
**NIST SP 800-53 Rev 4:** SC-5 (1)
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-214292 - AS24-U2-000620
**Severity:** MEDIUM

**Rule Title:** The Apache web server must display a default hosted application web page, not a directory listing, when a requested web page cannot be found.

**Automation Status:** Automatable

**Automation Method:** Bash (grep/awk/sed for config parsing)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**Notes:**
- Configuration file parsing (httpd.conf/ssl.conf)

**Check Content:**
```
View the "DocumentRoot" value by entering the following command: 
 
awk '{print $1,$2,$3}' <'INSTALL PATH'>/conf/httpd.conf|grep -i DocumentRoot|grep -v '^#' 
 
Note each location following the "DocumentRoot" string. This is the configured path(s) to the document root directory(s). 
 
To view a list of the directories and subdirectories and the file "index.html", from each stated "DocumentRoot" location enter the following commands: 
 
find . -type d 
find . -type f -name index.html 
 
Review th...
```
**NIST SP 800-53 Rev 4:** SI-11 a
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-214293 - AS24-U2-000630
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
In a command line, run "httpd -M | grep -i ssl_module". 
 
If the "ssl_module" is not enabled, this is a finding. 
 
Determine the location of the "HTTPD_ROOT" directory and the "httpd.conf" file: 
 
# apachectl -V | egrep -i 'httpd_root|server_config_file'
-D HTTPD_ROOT="/etc/httpd"
-D SERVER_CONFIG_FILE="conf/httpd.conf"

Note: The apachectl front end is the preferred method for locating the Apache httpd file. For some Linux distributions "apache2ctl -V" or  "httpd -V" can also be used. 
 
If ...
```
**NIST SP 800-53 Rev 4:** SI-11 a
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-214294 - AS24-U2-000640
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

Note: The apachectl front end is the preferred method for locating the Apache httpd file. For some Linux distributions "apache2ctl -V" or  "httpd -V" can also be used. 
 
For any enabled "TraceEnable" directives, verify they are part of the server-level configuration (i.e., not nested in a ...
```
**NIST SP 800-53 Rev 4:** SI-11 a
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-214295 - AS24-U2-000650
**Severity:** MEDIUM

**Rule Title:** The Apache web server must set an absolute timeout for sessions.

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

Note: The apachectl front end is the preferred method for locating the Apache httpd file. For some Linux distributions "apache2ctl -V" or  "httpd -V" can also be used. 
 
Verify the "SessionMaxAge" directive exists and is set to "600". 
 
If the "SessionMaxAge" directive does not exist or i...
```
**NIST SP 800-53 Rev 4:** SC-5 (3) (b)
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-214296 - AS24-U2-000660
**Severity:** MEDIUM

**Rule Title:** The Apache web server must set an inactive timeout for sessions.

**Automation Status:** Automatable

**Automation Method:** Bash (apachectl/httpd commands)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**Notes:**
- Apache command-line tool verification

**Check Content:**
```
In a command line, run "httpd -M | grep -i Reqtimeout_module". 
 
If the "Reqtimeout_module" is not enabled, this is a finding.
```
**NIST SP 800-53 Rev 4:** SC-5 (3) (b)
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-214297 - AS24-U2-000680
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

Note: The apachectl front end is the preferred method for locating the Apache httpd file. For some Linux distributions "apache2ctl -V" or  "httpd -V" can also be used. 

Search f...
```
**NIST SP 800-53 Rev 4:** AC-23
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-214298 - AS24-U2-000700
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
 
If accounts other than the System Administrator, Web Manager, or the Web Manager designees have access to the web administration tool or control files, this is a finding.
```
**NIST SP 800-53 Rev 4:** AC-16 b
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-214301 - AS24-U2-000870
**Severity:** MEDIUM

**Rule Title:** The Apache web server cookies, such as session cookies, sent to the client using SSL/TLS must not be compressed.

**Automation Status:** Automatable

**Automation Method:** Bash (grep/awk/sed for config parsing)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**Notes:**
- Configuration file parsing (httpd.conf/ssl.conf)

**Check Content:**
```
In a command line, run "httpd -M | grep -i ssl_module". 
 
If "ssl_module" is not listed, this is a finding. 
 
Determine the location of the "HTTPD_ROOT" directory and the "httpd.conf" file: 
 
# apachectl -V | egrep -i 'httpd_root|server_config_file'
-D HTTPD_ROOT="/etc/httpd"
-D SERVER_CONFIG_FILE="conf/httpd.conf"

Note: The apachectl front end is the preferred method for locating the Apache httpd file. For some Linux distributions "apache2ctl -V" or  "httpd -V" can also be used. 
 
If the "...
```
**NIST SP 800-53 Rev 4:** SC-12 (3)
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-214303 - AS24-U2-000890
**Severity:** MEDIUM

**Rule Title:** Cookies exchanged between the Apache web server and the client, such as session cookies, must have cookie properties set to force the encryption of cookies.

**Automation Status:** Automatable

**Automation Method:** Bash (grep/awk/sed for config parsing)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**Notes:**
- Configuration file parsing (httpd.conf/ssl.conf)

**Check Content:**
```
In a command line, run "httpd -M | grep -i session_cookie_module". 
 
If "session_cookie_module" is not listed, this is a finding. 
 
Determine the location of the "HTTPD_ROOT" directory and the "httpd.conf" file:

# apachectl -V | egrep -i 'httpd_root|server_config_file'
-D HTTPD_ROOT="/etc/httpd"
-D SERVER_CONFIG_FILE="conf/httpd.conf"

Note: The apachectl front end is the preferred method for locating the Apache httpd file. For some Linux distributions "apache2ctl -V" or  "httpd -V" can also ...
```
**NIST SP 800-53 Rev 4:** SC-12 (3)
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

### Partially Automatable (3 checks)

#### V-214278 - AS24-U2-000030
**Severity:** MEDIUM

**Rule Title:** The Apache web server must use encryption strength in accordance with the categorization of data hosted by the Apache web server when remote connections are provided.

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
 
If the "ssl_module" is not enabled, this is a finding. 
 
Determine the location of the ssl.conf file:
# find / -name ssl.conf
Output: /etc/httpd/conf.d/ssl.conf

Search the ssl.conf file for the SSLProtocol
# cat /<path_to_file>/ssl.conf | grep -i "SSLProtocol" 
Output: SSLProtocol -ALL +TLSv1.2
 
If the "SSLProtocol" directive is missing or does not look like the following, this is a finding...
```
**NIST SP 800-53 Rev 4:** AC-17 (2)
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-214287 - AS24-U2-000390
**Severity:** MEDIUM

**Rule Title:** Only authenticated system administrators or the designated PKI Sponsor for the Apache web server must have access to the Apache web servers private key.

**Automation Status:** Partially Automatable

**Automation Method:** Bash (grep/awk/sed for config parsing)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**🔧 Configuration Dependencies:**
- ⚠️ **ENVIRONMENT-SPECIFIC**: This check requires site-specific or organizational values
- ⚠️ **SYSTEM-SPECIFIC**: This check depends on deployment/installation-specific configuration

**Notes:**
- Configuration file parsing (httpd.conf/ssl.conf)

**Check Content:**
```
Verify the "ssl module" module is loaded
# httpd -M | grep -i ssl_module
Output:  ssl_module (shared) 

If the "ssl_module" is not enabled, this is a finding. 

Determine the location of the ssl.conf file:
# find / -name ssl.conf
Output: /etc/httpd/conf.d/ssl.conf

Search the ssl.conf file for the SSLCertificateKeyFile location.
# cat <path to file>/ssl.conf | grep -i SSLCertificateKeyFile
Output: SSLCertificateKeyFile /etc/pki/tls/private/localhost.key

Identify the correct permission set and o...
```
**NIST SP 800-53 Rev 4:** IA-5 (2) (b)
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-214300 - AS24-U2-000810
**Severity:** MEDIUM

**Rule Title:** The Apache web server must only accept client certificates issued by DOD PKI or DoD-approved PKI Certification Authorities (CAs).

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
Verify the â€œssl moduleâ€ module is loaded:
# httpd -M | grep -i ssl_module
Output:  ssl_module (shared) 

If the "ssl_module" is not found, this is a finding. 

Determine the location of the ssl.conf file:
# find / -name ssl.conf
Output: /etc/httpd/conf.d/ssl.conf

Search the ssl.conf file for the following:
# cat /etc/httpd/conf.d/ssl.conf | grep -i "SSLCACertificateFile"
Output should be similar to: SSLCACertificateFile /etc/pki/tls/certs/ca-bundle.crt

Review the path of the "SSLCACertific...
```
**NIST SP 800-53 Rev 4:** SC-23 (5)
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

### Manual Review Required (7 checks)

#### V-214280 - AS24-U2-000240
**Severity:** MEDIUM

**Rule Title:** The Apache web server must not perform user management for hosted applications.

**Automation Status:** Manual Review Required

**Automation Method:** Requires SA Interview

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**Notes:**
- Requires system administrator interview or consultation

**Check Content:**
```
Interview the System Administrator (SA) about the role of the Apache web server. 
 
If the web server is hosting an application, have the SA provide supporting documentation on how the application's user management is accomplished outside of the web server. 
 
If the web server is not hosting an application, this is Not Applicable. 
 
If the web server is performing user management for hosted applications, this is a finding. 
 
If the web server is hosting an application and the SA cannot provid...
```
**NIST SP 800-53 Rev 4:** CM-7 a
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-214281 - AS24-U2-000300
**Severity:** MEDIUM

**Rule Title:** The Apache web server must have Multipurpose Internet Mail Extensions (MIME) that invoke operating system shell programs disabled.

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
In a command line, run "httpd -M | grep -i ssl_module". 
 
If the "ssl_module" is not enabled, this is a finding. 
 
Determine the location of the "HTTPD_ROOT" directory and the "httpd.conf" file: 
 
# apachectl -V | egrep -i 'httpd_root|server_config_file'
-D HTTPD_ROOT="/etc/httpd"
-D SERVER_CONFIG_FILE="conf/httpd.conf"

Note: The apachectl front end is the preferred method for locating the Apache httpd file. For some Linux distributions "apache2ctl -V" or  "httpd -V" can also be used. 
 
If ...
```
**NIST SP 800-53 Rev 4:** CM-7 a
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-214282 - AS24-U2-000310
**Severity:** MEDIUM

**Rule Title:** The Apache web server must allow mappings to unused and vulnerable scripts to be removed.

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

Note: The apachectl front end is the preferred method for locating the Apache httpd file. For some Linux distributions "apache2ctl -V" or  "httpd -V" can also be used.  
Review "Script", "ScriptAlias" or "ScriptAliasMatch", or "ScriptInterpreterSource" directives. 
 
Go into each directory ...
```
**NIST SP 800-53 Rev 4:** CM-7 a
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-214283 - AS24-U2-000320
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

Note: The apachectl front end is the preferred method for locating the Apache httpd file. For some Linux distributions "apache2ctl -V" or  "httpd -V" can also be used. 
 
If "Action" or "AddHandler" exist and they configure .exe, .dll, .com, .bat, or .csh, or any other shell as a viewer for...
```
**NIST SP 800-53 Rev 4:** CM-7 a
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-214289 - AS24-U2-000540
**Severity:** MEDIUM

**Rule Title:** The Apache web server must augment re-creation to a stable and known baseline.

**Automation Status:** Manual Review Required

**Automation Method:** Requires SA Interview

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**Notes:**
- Requires system administrator interview or consultation

**Check Content:**
```
Interview the System Administrator for the Apache web server. 
 
Ask for documentation on the disaster recovery methods tested and planned for the Apache web server in the event of the necessity for rollback. 
 
If documentation for a disaster recovery has not been established, this is a finding.
```
**NIST SP 800-53 Rev 4:** SC-24
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-214299 - AS24-U2-000780
**Severity:** MEDIUM

**Rule Title:** The Apache web server application, libraries, and configuration files must only be accessible to privileged users.

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
 
Verify with the system administrator (SA) or the information system security officer (ISSO) that all privileged accounts are mission essential and documented. 
 
Verify with the SA or the ISSO that all nonadministrator access to shell scripts and operating system functions are mission essential and documented. 
 
If undocumented privileged accounts are found, this is a finding. 
 
If undocumented access...
```
**NIST SP 800-53 Rev 4:** CM-5 (1)
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-214304 - AS24-U2-000960
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
Review the website to determine if HTTP and HTTPs are used in accordance with well-known ports (e.g., 80 and 443) or those ports and services as registered and approved for use by the DoD PPSM. 
 
Verify that any variation in PPS is documented, registered, and approved by the PPSM. 
 
If well-known ports and services are not approved for used by PPSM, this is a finding.
```
**NIST SP 800-53 Rev 4:** CM-6 b
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

### Needs Analysis (1 checks)

#### V-214286 - AS24-U2-000380
**Severity:** MEDIUM

**Rule Title:** The Apache web server must perform RFC 5280-compliant certification path validation.

**Automation Status:** Needs Analysis

**Automation Method:** TBD

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**Notes:**
- Automation feasibility needs further analysis

**Check Content:**
```
Review the Apache server documentation and deployed configuration to determine whether the application server provides PKI functionality that validates certification paths in accordance with RFC 5280.

If PKI is not being used, this is NA.

If the Apache server is using PKI, but it does not perform this requirement, this is a finding.
```
**NIST SP 800-53 Rev 4:** IA-5 (2) (a)
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

