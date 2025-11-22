# Apache Server 2.4 Windows Server STIG Check Analysis Report
**Generated:** 2025-11-22 15:11:52
**STIG:** Apache Server 2.4 Windows Server :: Release: 3 Benchmark Date: 02 Apr 2025
**Total Checks:** 54

---

## 📊 Executive Summary

### Automation Status Overview

| Automation Status | Count | Percentage | Status |
|------------------|-------|------------|--------|
| ✅ Automatable | 33 | 61.1% | Can be fully automated |
| ⚠️ Partially Automatable | 6 | 11.1% | Requires some manual validation |
| 📝 Manual Review Required | 7 | 13.0% | Cannot be automated |
| 🔍 Needs Analysis | 8 | 14.8% | Automation feasibility TBD |
| **TOTAL** | **54** | **100.0%** | |

### Automation Status by Severity

| Severity | Total | Automatable | Partial | Manual | Automation Rate |
|----------|-------|-------------|---------|--------|----------------|
| HIGH | 4 | 2 | 1 | 1 | 75.0% |
| MEDIUM | 49 | 31 | 5 | 5 | 73.5% |
| LOW | 1 | 0 | 0 | 1 | 0.0% |
| **TOTAL** | **54** | **33** | **6** | **7** | **72.2%** |

### Configuration Dependencies

| Dependency Type | Count | Percentage | Description |
|----------------|-------|------------|-------------|
| 🌐 Environment-Specific | 6 | 11.1% | Requires site-specific/organizational values |
| 🖥️ System-Specific | 5 | 9.3% | Depends on deployment/installation config |
| ✓ Standard | 43 | 79.6% | No special dependencies |

### Severity Distribution

| Severity | Count | Percentage |
|----------|-------|------------|
| 🔴 HIGH | 4 | 7.4% |
| 🟡 MEDIUM | 49 | 90.7% |
| 🟢 LOW | 1 | 1.9% |
| **TOTAL** | **54** | **100.0%** |

### Tool Preference (Priority: Bash > PowerShell > Python > Third-Party)

| Tool Type | Count | Notes |
|-----------|-------|-------|
| Bash (Native) | 39 | Primary method - no dependencies |
| Python (Native) | 0 | Fallback - uses stdlib only |
| Third-Party Optional | 0 | All checks use native commands |
| **Minimal Third-Party** | **39** | **72.2% can run without third-party tools** |

## Summary
- **Automatable Checks:** 33 (61.1%)
- **Partially Automatable:** 6 (11.1%)
- **Manual Review Required:** 7 (13.0%)
- **Needs Analysis:** 8 (14.8%)

### Environment/System Specific Checks
- **Environment-Specific:** 6 (11.1%)
  - *These checks require site-specific, organizational, or approved values*
- **System-Specific:** 5 (9.3%)
  - *These checks depend on deployment or installation-specific configurations*

### Severity Distribution
- **High:** 4
- **Medium:** 49
- **Low:** 1

---

## Detailed Check Analysis

### Automatable (33 checks)

#### V-214306 - AS24-W1-000010
**Severity:** MEDIUM

**Rule Title:** The Apache web server must limit the number of allowed simultaneous session requests.

**Automation Status:** Automatable

**Automation Method:** Bash (file/directory checks)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**Check Content:**
```
With an editor, open the configuration file:

<installed path>\Apache24\conf\extra\httpd-default

Search for the following directive:

MaxKeepAliveRequests

Verify the value is "100" or greater.

If the "MaxKeepAliveRequests" directive is not "100" or greater, this is a finding.
```
**NIST SP 800-53 Rev 4:** AC-10
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-214307 - AS24-W1-000020
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
In a command line, navigate to "<'INSTALLED PATH'>\bin". Run "httpd -M" to view a list of installed modules.

If "mod_session" module and "mod_usertrack" are not enabled, this is a finding.

session_module (shared)
usertrack_module (shared)
```
**NIST SP 800-53 Rev 4:** AC-10
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-214308 - AS24-W1-000030
**Severity:** MEDIUM

**Rule Title:** The Apache web server must use encryption strength in accordance with the categorization of data hosted by the Apache web server when remote connections are provided.

**Automation Status:** Automatable

**Automation Method:** Bash (grep/awk/sed for config parsing)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**Notes:**
- Configuration file parsing (httpd.conf/ssl.conf)

**Check Content:**
```
In a command line, navigate to "<'INSTALLED PATH'>\bin". Run "httpd -M" to view a list of installed modules.

If the "ssl_module" is not enabled, this is a finding.

Review the <'INSTALL PATH'>\conf\httpd.conf file to determine if the "SSLProtocol" directive exists and looks like the following:

SSLProtocol -ALL +TLSv1.2 -SSLv2 -SSLv3

If the directive does not exist or exists but does not contain "-ALL +TLSv1.2 -SSLv2 -SSLv3", this is a finding.
```
**NIST SP 800-53 Rev 4:** AC-17 (2)
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-214309 - AS24-W1-000065
**Severity:** MEDIUM

**Rule Title:** System logging must be enabled.

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
In a command line, navigate to "<'INSTALLED PATH'>\bin\conf". 
Edit the "httpd.conf" file and search for the directive "CustomLog".

If the "CustomLog" directive is missing or does not look like the following, this is a finding:

CustomLog "Logs/access_log" common
```
**NIST SP 800-53 Rev 4:** CM-6 b
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-214310 - AS24-W1-000070
**Severity:** MEDIUM

**Rule Title:** The Apache web server must generate, at a minimum, log records for system startup and shutdown, system access, and system authentication events.

**Automation Status:** Automatable

**Automation Method:** Bash (apachectl/httpd commands)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**Notes:**
- Apache command-line tool verification

**Check Content:**
```
In a command line, navigate to "<'INSTALLED PATH'>\bin". Run "httpd -M" to view a list of installed modules.

If the "log_config_module" is not enabled, this is a finding.
```
**NIST SP 800-53 Rev 4:** AU-12 a
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-214311 - AS24-W1-000090
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
Items to be logged are as shown in this sample line in the <'INSTALL PATH'>\conf\httpd.conf file:

LogFormat "%a %A %h %H %l %m %s %t %u %U \"%{Referer}i\" " combined

If the web server is not configured to capture the required audit events for all sites and virtual directories, this is a finding.
```
**NIST SP 800-53 Rev 4:** AU-3
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-214319 - AS24-W1-000250
**Severity:** MEDIUM

**Rule Title:** The Apache web server must only contain services and functions necessary for operation.

**Automation Status:** Automatable

**Automation Method:** Bash (file/directory checks)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**🔧 Configuration Dependencies:**
- ⚠️ **SYSTEM-SPECIFIC**: This check depends on deployment/installation-specific configuration

**Check Content:**
```
Verify the document root directory and the configuration files do not provide for default index.html or welcome page.

Verify the Apache User Manual content is not installed by checking the configuration files for manual location directives.

Verify the Apache configuration files do not have the Server Status handler configured.

Verify that the Server Information handler is not configured.

Verify that any other handler configurations such as perl-status is not enabled.

If any of these are pre...
```
**NIST SP 800-53 Rev 4:** CM-7 a
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-214321 - AS24-W1-000270
**Severity:** HIGH

**Rule Title:** The Apache web server must provide install options to exclude the installation of documentation, sample code, example applications, and tutorials.

**Automation Status:** Automatable

**Automation Method:** Bash (file/directory checks)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**Check Content:**
```
If the site requires the use of a particular piece of software, the Information System Security Officer (ISSO) will need to maintain documentation identifying this software as necessary for operations. The software must be operated at the vendor's current patch level and must be a supported vendor release.

If programs or utilities that meet the above criteria are installed on the web server, and appropriate documentation and signatures are in evidence, this is not a finding.

Determine whether ...
```
**NIST SP 800-53 Rev 4:** CM-7 a
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-214323 - AS24-W1-000300
**Severity:** MEDIUM

**Rule Title:** The Apache web server must have resource mappings set to disable the serving of certain file types.

**Automation Status:** Automatable

**Automation Method:** Bash (grep/awk/sed for config parsing)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**Notes:**
- Configuration file parsing (httpd.conf/ssl.conf)

**Check Content:**
```
Review the <'INSTALL PATH'>\conf\httpd.conf file.

If "Action" or "AddHandler" exist and they configure .exe, .dll, .com, .bat, or .csh, or any other shell as a viewer for documents, this is a finding.
```
**NIST SP 800-53 Rev 4:** CM-7 a
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-214324 - AS24-W1-000310
**Severity:** MEDIUM

**Rule Title:** The Apache web server must allow the mappings to unused and vulnerable scripts to be removed.

**Automation Status:** Automatable

**Automation Method:** Bash (grep/awk/sed for config parsing)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**Notes:**
- Configuration file parsing (httpd.conf/ssl.conf)

**Check Content:**
```
Review the <'INSTALL PATH'>\conf\httpd.conf file.

Locate cgi-bin files and directories enabled in the "Script", "ScriptAlias" or "ScriptAliasMatch", or "ScriptInterpreterSource" directives.

If any script is not needed for application operation, this is a finding.
```
**NIST SP 800-53 Rev 4:** CM-7 a
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-214325 - AS24-W1-000330
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
In a command line, navigate to "<'INSTALLED PATH'>\bin". Run "httpd -M" to view a list of installed modules.

If any of the following modules are present, this is a finding:

dav_module
dav_fs_module
dav_lock_module
```
**NIST SP 800-53 Rev 4:** CM-7 a
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-214326 - AS24-W1-000360
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
Review the <'INSTALL PATH'>\conf\httpd.conf file and search for the following directive:

Listen

For any enabled "Listen" directives, verify they specify both an IP address and port number.

If the "Listen" directive is found with only an IP address or only a port number specified, this is finding.

If the IP address is all zeros (i.e., 0.0.0.0:80 or [::ffff:0.0.0.0]:80), this is a finding.

If the "Listen" directive does not exist, this is a finding.
```
**NIST SP 800-53 Rev 4:** CM-7 b
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-214327 - AS24-W1-000370
**Severity:** MEDIUM

**Rule Title:** The Apache web server must encrypt passwords during transmission.

**Automation Status:** Automatable

**Automation Method:** Bash (grep/awk/sed for config parsing)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**Notes:**
- Configuration file parsing (httpd.conf/ssl.conf)

**Check Content:**
```
Review the <'INSTALL PATH'>\conf\httpd.conf file.

Ensure SSL is enabled by looking at the "SSLVerifyClient" directive.

If the value of "SSLVerifyClient" is not set to "require", this is a finding.
```
**NIST SP 800-53 Rev 4:** IA-5 (1) (c)
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-214329 - AS24-W1-000430
**Severity:** MEDIUM

**Rule Title:** Apache web server accounts accessing the directory tree, the shell, or other operating system functions and utilities must only be administrative accounts.

**Automation Status:** Automatable

**Automation Method:** Bash (ls -l, stat commands)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**Notes:**
- File permission verification

**Check Content:**
```
Review the web server documentation and configuration to determine what web server accounts are available on the hosting server.

Review permissions in the web and Apache directories.
 
If the files are owned by anyone other than the Apache user set up to run Apache, this is a finding.

If non-privileged web server accounts are available with access to functions, directories, or files not needed for the role of the account, this is a finding.
```
**NIST SP 800-53 Rev 4:** SC-2
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-214331 - AS24-W1-000460
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
Review the <'INSTALL PATH'>\conf\httpd.conf file.

Search for the following directive: 

SessionMaxAge

Verify the value of "SessionMaxAge" is set to "600" or less.

If "SessionMaxAge" does not exist or is set to more than "600", this is a finding.

```
**NIST SP 800-53 Rev 4:** SC-23 (1)
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-214332 - AS24-W1-000470
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
Review the <'INSTALL PATH'>\conf\httpd.conf file.

If "HttpOnly;secure" is not configured, this is a finding.

Review the code. If when creating cookies, the following is not occurring, this is a finding:

function setCookie() { document.cookie = "ALEPH_SESSION_ID = $SESS; path = /; secure"; }
```
**NIST SP 800-53 Rev 4:** SC-23 (3)
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-214333 - AS24-W1-000480
**Severity:** MEDIUM

**Rule Title:** The Apache web server must accept only system-generated session identifiers.

**Automation Status:** Automatable

**Automation Method:** Bash (grep/awk/sed for config parsing)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**Notes:**
- Configuration file parsing (httpd.conf/ssl.conf)

**Check Content:**
```
Review the <'INSTALL PATH'>\conf\httpd.conf file.

Verify the "mod_unique_id" is loaded.

If it does not exist, this is a finding.
```
**NIST SP 800-53 Rev 4:** SC-23 (3)
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-214334 - AS24-W1-000500
**Severity:** MEDIUM

**Rule Title:** The Apache web server must generate unique session identifiers that cannot be reliably reproduced.

**Automation Status:** Automatable

**Automation Method:** Bash (grep/awk/sed for config parsing)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**Notes:**
- Configuration file parsing (httpd.conf/ssl.conf)

**Check Content:**
```
Review the <'INSTALL PATH'>\conf\httpd.conf file.

Check to see if the "mod_unique_id" is loaded.

If it does not exist, this is a finding.
```
**NIST SP 800-53 Rev 4:** SC-23 (3)
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-214335 - AS24-W1-000530
**Severity:** MEDIUM

**Rule Title:** The Apache web server must generate unique session identifiers with definable entropy.

**Automation Status:** Automatable

**Automation Method:** Bash (grep/awk/sed for config parsing)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**Notes:**
- Configuration file parsing (httpd.conf/ssl.conf)

**Check Content:**
```
Review the <'INSTALLED PATH'>\conf\httpd.conf file.

Verify the "ssl_module" is loaded.

If it does not exist, this is a finding.

If the "SSLRandomSeed" directive is missing or does not look like the following, this is a finding:

SSLRandomSeed startup builtin
SSLRandomSeed connect builtin
```
**NIST SP 800-53 Rev 4:** SC-23 (3)
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-214338 - AS24-W1-000590
**Severity:** MEDIUM

**Rule Title:** The Apache web server must restrict the ability of users to launch denial-of-service (DoS) attacks against other information systems or networks.

**Automation Status:** Automatable

**Automation Method:** Bash (grep/awk/sed for config parsing)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**Notes:**
- Configuration file parsing (httpd.conf/ssl.conf)

**Check Content:**
```
Review the <'INSTALLED PATH'>\conf\httpd.conf file.

Verify the "Timeout" directive is specified in the "httpd.conf" file to have a value of "10" seconds or less.

If the "Timeout" directive is not configured or set for more than "10" seconds, this is a finding.
```
**NIST SP 800-53 Rev 4:** SC-5 (1)
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-214339 - AS24-W1-000620
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
Review the <'INSTALL PATH'>\conf\httpd.conf file.

If the "ErrorDocument" directive is not being used, this is a finding.
```
**NIST SP 800-53 Rev 4:** SI-11 a
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-214340 - AS24-W1-000630
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
Review the <'INSTALL PATH'>\conf\httpd.conf file.

For any enabled "TraceEnable" directives, verify they are part of the server=level configuration (i.e., not nested in a "Directory" or "Location" directive).

Also verify the "TraceEnable" directive is set to "Off".

If the "TraceEnable directive is not part of the server-level configuration and/or is not set to "Off", this is a finding.

If the directive does not exist in the conf file, this is a finding because the default value is "On".
```
**NIST SP 800-53 Rev 4:** SI-11 a
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-214341 - AS24-W1-000640
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
Review the <'INSTALL PATH'>\conf\httpd.conf file.

Search for the following directive:

SessionMaxAge

Verify the value of "SessionMaxAge" is set to "600" or less.

If the "SessionMaxAge" does not exist or is set to more than "600", this is a finding.
```
**NIST SP 800-53 Rev 4:** AC-12
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-214342 - AS24-W1-000650
**Severity:** MEDIUM

**Rule Title:** The Apache web server must set an inactive timeout for completing the TLS handshake

**Automation Status:** Automatable

**Automation Method:** Bash (grep/awk/sed for config parsing)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**Notes:**
- Configuration file parsing (httpd.conf/ssl.conf)

**Check Content:**
```
Review the <'INSTALL PATH'>\conf\httpd.conf file.

Verify the "mod_reqtimeout" is loaded.

If it does not exist, this is a finding.

If the "mod_reqtimeout" module is loaded and the "RequestReadTimeout" directive is not configured, this is a finding.

Note: The "RequestReadTimeout" directive must be explicitly configured (i.e., not left to a default value) to a value compatible with the organization's operations.
```
**NIST SP 800-53 Rev 4:** AC-12
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-214343 - AS24-W1-000670
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
Review the <'INSTALL PATH'>\conf\httpd.conf file.

If "IP Address Restrictions" are not configured or IP ranges configured to be "Allow" are not restrictive enough to prevent connections from nonsecure zones, this is a finding.
```
**NIST SP 800-53 Rev 4:** AC-17 (1)
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-214345 - AS24-W1-000690
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

#### V-214346 - AS24-W1-000700
**Severity:** MEDIUM

**Rule Title:** An Apache web server that is part of a web server cluster must route all remote management through a centrally managed access control point.

**Automation Status:** Automatable

**Automation Method:** Bash (grep/awk/sed for config parsing)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**Notes:**
- Configuration file parsing (httpd.conf/ssl.conf)

**Check Content:**
```
Review the <'INSTALL PATH'>\conf\httpd.conf file.

Verify the "mod_proxy" is loaded.

If it does not exist, this is a finding.

If the "mod_proxy" module is loaded and the "ProxyPass" directive is not configured, this is a finding.
```
**NIST SP 800-53 Rev 4:** AU-6 (4)
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-214351 - AS24-W1-000760
**Severity:** MEDIUM

**Rule Title:** The Apache web server must generate log records that can be mapped to Coordinated Universal Time (UTC) or Greenwich Mean Time (GMT) with a minimum granularity of one second.

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

In a command line, navigate to "<'INSTALLED PATH'>\bin". Run "httpd -M" to view a list of installed modules.

If "log_config_module" is not listed, this is a finding.

In a command line, navigate to "<'INSTALLED PATH'>\bin". Determine the location of the "httpd.conf" file by running the following command:

httpd -V

Review the "HTTPD_ROOT" path.

Navigate to the "HTTPD_ROOT"/conf directory.

E...
```
**NIST SP 800-53 Rev 4:** AU-8 b
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-214353 - AS24-W1-000820
**Severity:** MEDIUM

**Rule Title:** The Apache web server must be protected from being stopped by a non-privileged user.

**Automation Status:** Automatable

**Automation Method:** Bash (ls -l, stat commands)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**🔧 Configuration Dependencies:**
- ⚠️ **SYSTEM-SPECIFIC**: This check depends on deployment/installation-specific configuration

**Notes:**
- File permission verification

**Check Content:**
```
Right-click <'Install Path'>\bin\httpd.exe.

Click "Properties" from the "Context" menu.

Select the "Security" tab.

Review the groups and user names.

The following account may have Full control privileges:

TrustedInstaller
Web Managers
Web Manager designees

The following accounts may have read and execute, or read permissions:

Non Web Manager Administrators
ALL APPLICATION PACKAGES (built-in security group)
SYSTEM
Users

Specific users may be granted read and execute and read permissions.
...
```
**NIST SP 800-53 Rev 4:** SC-5
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-214354 - AS24-W1-000830
**Severity:** MEDIUM

**Rule Title:** The Apache web server must be tuned to handle the operational requirements of the hosted application.

**Automation Status:** Automatable

**Automation Method:** Bash (file/directory checks)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**Check Content:**
```
Verify the "Timeout" directive is specified in the Apache configuration files to have a value of "60" seconds or less.

If the "Timeout" directive is not configured or set for more than "60" seconds, this is a finding.
```
**NIST SP 800-53 Rev 4:** SC-5
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-214355 - AS24-W1-000860
**Severity:** MEDIUM

**Rule Title:** The Apache web server cookies, such as session cookies, sent to the client using SSL/TLS must not be compressed.

**Automation Status:** Automatable

**Automation Method:** Bash (file/directory checks)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**Check Content:**
```
Search the Apache configuration files for the "SSLCompression" directive.

If the "SSLCompression" directive does not exist, this is a not a finding.

If the "SSLCompression" directive exists and is not set to "Off", this is a finding.
```
**NIST SP 800-53 Rev 4:** SC-8
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-214356 - AS24-W1-000930
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
Determine the most recent patch level of the Apache web server 2.4 software, as posted on the Apache HTTP Server Project website.

In a command line, type "httpd -v".

If the version is more than one version behind the most recent patch level, this is a finding.
```
**NIST SP 800-53 Rev 4:** SI-2 c
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-214359 - AS24-W1-000960
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
Determine the version of the Apache software that is running on the system.

In a command line, navigate to "<'INSTALLED PATH'>\bin". Run "httpd -v" to view the Apache version.

If the version of Apache is not at the following version or higher, this is a finding:

Apache 2.4 (February 2012)
```
**NIST SP 800-53 Rev 4:** CM-6 b
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

### Partially Automatable (6 checks)

#### V-214314 - AS24-W1-000180
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
Review the <'INSTALL PATH'>\conf\httpd.conf file to determine the location of the logs.

Determine permissions for log files. From the command line, navigate to the directory where the log files are located and enter the following command:

icacls <'Apache Directory'>\logs\*

ex: icacls c:\Apache24\logs\*

Only the Auditors, Web Managers, Administrators, and the account that runs the web server should have permissions to the files.

If any users other than those authorized have read access to th...
```
**NIST SP 800-53 Rev 4:** AU-9
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-214315 - AS24-W1-000200
**Severity:** MEDIUM

**Rule Title:** The log information from the Apache web server must be protected from unauthorized deletion and modification.

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
Query the System Administrator (SA) to determine who has update access to the web server log files. 

The role of auditor and the role of SA should be distinctly separate. An individual functioning as an auditor should not also serve as an SA due to a conflict of interest.

Only management-authorized individuals with a privileged ID or group ID associated with an auditor role will have access permission to log files that are greater than read on web servers he or she has been authorized to audit...
```
**NIST SP 800-53 Rev 4:** AU-9
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-214320 - AS24-W1-000260
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

Open the <'INSTALL PATH'>\conf\httpd.conf file with an editor and search for the following directive:

ProxyRequests

If the ProxyRequests directive is set to "On", this is a finding.
```
**NIST SP 800-53 Rev 4:** CM-7 a
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-214328 - AS24-W1-000380
**Severity:** MEDIUM

**Rule Title:** The Apache web server must perform RFC 5280-compliant certification path validation.

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
Review the <'INSTALL PATH'>/conf/extra/httpd-ssl.conf file.

Look for the "SSLCACertificateFile" directive.

Review the path of the "SSLCACertificateFile" directive.

Review the contents of <'path of cert'>\ca-bundle.crt.

Examine the contents of this file to determine if the trusted CAs are DoD approved. If the trusted CA that is used to authenticate users to the website does not lead to an approved DoD CA, this is a finding.

NOTE: There are non-DoD roots that must be on the server for it to f...
```
**NIST SP 800-53 Rev 4:** IA-5 (2) (a)
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-214352 - AS24-W1-000800
**Severity:** MEDIUM

**Rule Title:** The Apache web server must only accept client certificates issued by DoD PKI or DoD-approved PKI Certification Authorities (CAs).

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
Review the "ssl.conf" file.

Look for the "SSLCACertificateFile" directive.

Review the path of the "SSLCACertificateFile" directive.

Review the contents of <'path of cert'>\ca-bundle.crt.

Examine the contents of this file to determine if the trusted CAs are DoD approved.

If the trusted CA that is used to authenticate users to the website does not lead to an approved DoD CA, this is a finding.

NOTE: There are non-DoD roots that must be on the server for it to function. Some applications, suc...
```
**NIST SP 800-53 Rev 4:** SC-23 (5)
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-214357 - AS24-W1-000940
**Severity:** HIGH

**Rule Title:** All accounts installed with the Apache web server software and tools must have passwords assigned and default passwords changed.

**Automation Status:** Partially Automatable

**Automation Method:** Bash/Python (needs validation)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**🔧 Configuration Dependencies:**
- ⚠️ **SYSTEM-SPECIFIC**: This check depends on deployment/installation-specific configuration

**Notes:**
- Automation possible but may require manual validation

**Check Content:**
```
Access "Apps" menu. Under "Administrative Tools", select "Computer Management".

In left pane, expand "Local Users and Groups" and click on "Users".

Review the local users listed in the middle pane. 

If any local accounts are present and are used by Apache Web Server, verify with System Administrator that default passwords have been changed.

If passwords have not been changed from the default, this is a finding.
```
**NIST SP 800-53 Rev 4:** CM-6 b
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

### Manual Review Required (7 checks)

#### V-214312 - AS24-W1-000130
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
Interview the System Administrator to review the configuration of the Apache web server architecture and determine if inbound web traffic is passed through a proxy.

If the Apache web server is receiving inbound web traffic through a proxy, the audit logs must be reviewed to determine if correct source information is being passed through by the proxy server.

View Apache log files as configured in "httpd.conf" files.

When the log file is displayed, review source IP information in log entries an...
```
**NIST SP 800-53 Rev 4:** AU-3
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-214316 - AS24-W1-000210
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
Interview the Information System Security Officer (ISSO), System Administrator (SA), Web Manager, Webmaster, or developers as necessary to determine whether a tested and verifiable backup strategy has been implemented for web server software as well as all web server data files.

Proposed Questions:
Who maintains the backup and recovery procedures?
Do you have a copy of the backup and recovery procedures?
Where is the off-site backup location?
Is the contingency plan documented?
When was the las...
```
**NIST SP 800-53 Rev 4:** AU-9 (2)
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-214318 - AS24-W1-000240
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

If the web server is hosting an application and the SA cannot provide suppor...
```
**NIST SP 800-53 Rev 4:** CM-7 a
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-214322 - AS24-W1-000280
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

Verify with the System Administrator (SA) or the Information System Security Officer (ISSO) that all privileged accounts are mission essential and documented.

Verify with the SA or the ISSO that all non-administrator access to shell scripts and operating system functions are mission essential and documented.

If undocumented privileged accounts are present, this is a finding.

If undocumented access to s...
```
**NIST SP 800-53 Rev 4:** CM-7 a
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-214336 - AS24-W1-000550
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

#### V-214344 - AS24-W1-000680
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
Interview the System Administrator and Web Manager.

Ask for documentation for the Apache web server administration.

Verify there are documented procedures for shutting down an Apache website in the event of an attack. The procedure should, at a minimum, provide the following steps:

Determine the respective website for the application at risk of an attack.

Stop the Apache service.

If the web server is not capable of or cannot be configured to disconnect or disable remote access to the hosted...
```
**NIST SP 800-53 Rev 4:** AC-17 (9)
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-214358 - AS24-W1-000950
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

If it is not, this is a finding.
```
**NIST SP 800-53 Rev 4:** CM-6 b
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

### Needs Analysis (8 checks)

#### V-214313 - AS24-W1-000160
**Severity:** MEDIUM

**Rule Title:** The Apache web server must use a logging mechanism that is configured to alert the (ISSO) and System Administrator (SA) in the event of a processing failure.

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

#### V-214330 - AS24-W1-000450
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

#### V-214337 - AS24-W1-000580
**Severity:** MEDIUM

**Rule Title:** The Apache web server document directory must be in a separate partition from the Apache web servers system files.

**Automation Status:** Needs Analysis

**Automation Method:** TBD

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**Notes:**
- Automation feasibility needs further analysis

**Check Content:**
```
Determine whether the public web server has a two-way trusted relationship with any private asset located within the network. Private web server resources (e.g., drives, folders, printers, etc.) will not be directly mapped to or shared with public web servers.

If sharing is selected for any web folder, this is a finding.

If private resources (e.g., drives, partitions, folders/directories, printers, etc.) are shared with the public web server, this is a finding.
```
**NIST SP 800-53 Rev 4:** SC-3
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-214347 - AS24-W1-000710
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

#### V-214348 - AS24-W1-000720
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
Work with the SIEM administrator to determine current security integrations. 

If the SIEM is not integrated with security, this is a finding.
```
**NIST SP 800-53 Rev 4:** AU-4 (1)
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-214349 - AS24-W1-000730
**Severity:** MEDIUM

**Rule Title:** The Apache web server must be configurable to integrate with an organizations security infrastructure.

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

#### V-214350 - AS24-W1-000740
**Severity:** MEDIUM

**Rule Title:** The Apache web server must use a logging mechanism that is configured to provide a warning to the Information System Security Officer (ISSO) and System Administrator (SA) when allocated record storage volume reaches 75 percent of maximum log record storage capacity.

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
**NIST SP 800-53 Rev 4:** AU-5 (1)
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-214360 - AS24-W1-000970
**Severity:** MEDIUM

**Rule Title:** The Apache web server must alert the ISSO and SA (at a minimum) in the event of an audit processing failure.

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
**NIST SP 800-53 Rev 4:** CM-6 b
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

