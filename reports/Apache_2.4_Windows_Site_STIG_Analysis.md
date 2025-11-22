# Apache Server 2.4 Windows Site STIG Check Analysis Report
**Generated:** 2025-11-22 15:11:52
**STIG:** Apache Server 2.4 Windows Site :: Release: 2 Benchmark Date: 02 Apr 2025
**Total Checks:** 36

---

## 📊 Executive Summary

### Automation Status Overview

| Automation Status | Count | Percentage | Status |
|------------------|-------|------------|--------|
| ✅ Automatable | 25 | 69.4% | Can be fully automated |
| ⚠️ Partially Automatable | 5 | 13.9% | Requires some manual validation |
| 📝 Manual Review Required | 4 | 11.1% | Cannot be automated |
| 🔍 Needs Analysis | 2 | 5.6% | Automation feasibility TBD |
| **TOTAL** | **36** | **100.0%** | |

### Automation Status by Severity

| Severity | Total | Automatable | Partial | Manual | Automation Rate |
|----------|-------|-------------|---------|--------|----------------|
| HIGH | 2 | 0 | 1 | 1 | 50.0% |
| MEDIUM | 33 | 25 | 4 | 2 | 87.9% |
| LOW | 1 | 0 | 0 | 1 | 0.0% |
| **TOTAL** | **36** | **25** | **5** | **4** | **83.3%** |

### Configuration Dependencies

| Dependency Type | Count | Percentage | Description |
|----------------|-------|------------|-------------|
| 🌐 Environment-Specific | 6 | 16.7% | Requires site-specific/organizational values |
| 🖥️ System-Specific | 2 | 5.6% | Depends on deployment/installation config |
| ✓ Standard | 28 | 77.8% | No special dependencies |

### Severity Distribution

| Severity | Count | Percentage |
|----------|-------|------------|
| 🔴 HIGH | 2 | 5.6% |
| 🟡 MEDIUM | 33 | 91.7% |
| 🟢 LOW | 1 | 2.8% |
| **TOTAL** | **36** | **100.0%** |

### Tool Preference (Priority: Bash > PowerShell > Python > Third-Party)

| Tool Type | Count | Notes |
|-----------|-------|-------|
| Bash (Native) | 30 | Primary method - no dependencies |
| Python (Native) | 0 | Fallback - uses stdlib only |
| Third-Party Optional | 0 | All checks use native commands |
| **Minimal Third-Party** | **30** | **83.3% can run without third-party tools** |

## Summary
- **Automatable Checks:** 25 (69.4%)
- **Partially Automatable:** 5 (13.9%)
- **Manual Review Required:** 4 (11.1%)
- **Needs Analysis:** 2 (5.6%)

### Environment/System Specific Checks
- **Environment-Specific:** 6 (16.7%)
  - *These checks require site-specific, organizational, or approved values*
- **System-Specific:** 2 (5.6%)
  - *These checks depend on deployment or installation-specific configurations*

### Severity Distribution
- **High:** 2
- **Medium:** 33
- **Low:** 1

---

## Detailed Check Analysis

### Automatable (25 checks)

#### V-214362 - AS24-W2-000010
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
Open the <'INSTALL PATH'>\conf\httpd.conf file with an editor and search for the following directive:

MaxKeepAliveRequests

Verify the value is "100" or greater.

If the directive is not set to "100" or greater, this is a finding.
```
**NIST SP 800-53 Rev 4:** AC-10
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-214363 - AS24-W2-000020
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
In a command line, navigate to <'INSTALL PATH'>\bin. Run "httpd -M" to view a list of installed modules.

If the module "mod_session" is not enabled, this is a finding.
```
**NIST SP 800-53 Rev 4:** AC-10
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-214364 - AS24-W2-000090
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
Review the access log file. If necessary, review the <'INSTALLED PATH'>\conf\httpd.conf file to determine the location of the logs.

Items to be logged are as shown in this sample line in the <'INSTALLED PATH'>\conf\httpd.conf file:

<IfModule log_config_module>
LogFormat "%a %A %h %H %l %m %s %t %u %U \"%{Referer}i\" " combined
</IfModule>

If the web server is not configured to capture the required audit events for all sites and virtual directories, this is a finding.
```
**NIST SP 800-53 Rev 4:** AU-3
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-214366 - AS24-W2-000300
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
Review the <'INSTALLED PATH'>\conf\httpd.conf file.

If "Action" or "AddHandler" exist and they configure .exe, .dll, .com, .bat, or .csh, or any other shell as a viewer for documents, this is a finding.
```
**NIST SP 800-53 Rev 4:** CM-7 a
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-214367 - AS24-W2-000310
**Severity:** MEDIUM

**Rule Title:** The Apache web server must allow the mappings to unused and vulnerable scripts to be removed.

**Automation Status:** Automatable

**Automation Method:** Bash (file/directory checks)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**Check Content:**
```
Locate cgi-bin files and directories enabled in the Apache configuration via "Script", "ScriptAlias" or "ScriptAliasMatch", or "ScriptInterpreterSource" directives.

If any script is present that is not needed for application operation, this is a finding.
```
**NIST SP 800-53 Rev 4:** CM-7 a
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-214368 - AS24-W2-000350
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
Review the <'INSTALLED PATH'>\conf\httpd.conf file and search for the following directive:

Directory

For every root directory entry (i.e., <Directory />), verify the following exists. If it does not, this is a finding:

Require all denied

If the statement above is not found in the root directory statement, this is a finding.

```
**NIST SP 800-53 Rev 4:** CM-7 a
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-214369 - AS24-W2-000360
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
Review the <'INSTALLED PATH'>\conf\httpd.conf file and search for the following directive:

Listen

For any enabled "Listen" directives, verify they specify both an IP address and port number.

If the "Listen" directive is found with only an IP address or only a port number specified, this is finding.
 
If the IP address is all zeros (i.e. 0.0.0.0:80 or [::ffff:0.0.0.0]:80), this is a finding.

If the "Listen" directive does not exist, this is a finding.
```
**NIST SP 800-53 Rev 4:** CM-7 b
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-214370 - AS24-W2-000380
**Severity:** MEDIUM

**Rule Title:** The Apache web server must perform RFC 5280-compliant certification path validation.

**Automation Status:** Automatable

**Automation Method:** Bash (grep/awk/sed for config parsing)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**Notes:**
- Configuration file parsing (httpd.conf/ssl.conf)

**Check Content:**
```
Review the <'INSTALLED PATH'>\conf\httpd.conf file to determine if the "SSLVerifyClient" and "SSLVerifyDepth" directives exist and look like the following.

If they do not, this is a finding.

SSLVerifyClient require

SSLVerifyDepth 1 

If "SSLVerifyDepth" is set to "0", this is a finding.
```
**NIST SP 800-53 Rev 4:** IA-5 (2) (a)
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-214372 - AS24-W2-000430
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

If any directories or files are owned by anyone other than root, this is a finding.

If non-privileged web server accounts are available with access to functions, directories, or files not needed for the role of the account, this is a finding.
```
**NIST SP 800-53 Rev 4:** SC-2
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-214376 - AS24-W2-000470
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
Review the <'INSTALLED PATH'>\conf\httpd.conf file.

If "HttpOnly; secure" is not configured, this is a finding.

Review the code. If when creating cookies, the following is not occurring, this is a finding:

function setCookie() { document.cookie = "ALEPH_SESSION_ID = $SESS; path = /; secure"; }
```
**NIST SP 800-53 Rev 4:** SC-23 (3)
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-214377 - AS24-W2-000480
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

#### V-214378 - AS24-W2-000500
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
Review the <'INSTALLED PATH'>\conf\httpd.conf file.

Verify the "mod_unique_id" is loaded.

If it does not exist, this is a finding.
```
**NIST SP 800-53 Rev 4:** SC-23 (3)
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-214379 - AS24-W2-000520
**Severity:** MEDIUM

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
Review the <'INSTALLED PATH'>\conf\httpd.conf file.

Check to see if the "mod_unique_id" is loaded.

If it does not exist, this is a finding.
```
**NIST SP 800-53 Rev 4:** SC-23 (3)
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-214381 - AS24-W2-000560
**Severity:** MEDIUM

**Rule Title:** The Apache web server must be configured to provide clustering.

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

Verify the "mod_proxy" is loaded.

If it does not exist, this is a finding.

If the "mod_proxy" module is loaded and the "ProxyPass" directive is not configured, this is a finding.
```
**NIST SP 800-53 Rev 4:** SC-24
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-214383 - AS24-W2-000610
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
Review the DocumentRoot directive in the <'INSTALLED PATH'>\conf\httpd.conf file.

Note each location following the "DocumentRoot" string. This is the configured path(s) to the document root directory(s).

To view a list of the directories and sub-directories and the file "index.html", from each stated "DocumentRoot" location, enter the following command:

dir "index.html"

Review the results for each document root directory and its subdirectories.

If a directory does not contain an "index.html...
```
**NIST SP 800-53 Rev 4:** SI-11 a
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-214384 - AS24-W2-000620
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
Review the <'INSTALLED PATH'>\conf\httpd.conf file.

If the "ErrorDocument" directive is not being used, this is a finding.
```
**NIST SP 800-53 Rev 4:** SI-11 a
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-214385 - AS24-W2-000630
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
Review the <'INSTALLED PATH'>\conf\httpd.conf file.

For any enabled "TraceEnable" directives, verify they are part of the server-level configuration (i.e., not nested in a "Directory" or "Location" directive).

Also, verify the "TraceEnable" directive is set to "Off".

If the "TraceEnable" directive is not part of the server-level configuration and/or is not set to "Off", this is a finding.

If the directive does not exist in the "conf" file, this is a finding because the default value is "On".
```
**NIST SP 800-53 Rev 4:** SI-11 a
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-214386 - AS24-W2-000640
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

#### V-214387 - AS24-W2-000650
**Severity:** MEDIUM

**Rule Title:** The Apache web server must set an inactive timeout for completing the TLS handshake.

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

Verify the "mod_reqtimeout" is loaded.

If it does not exist, this is a finding.

If the "mod_reqtimeout" module is loaded but the "RequestReadTimeout" directive is not configured, this is a finding.

Note: The "RequestReadTimeout" directive must be explicitly configured (i.e., not left to a default value) to a value compatble with the organization's operations.
```
**NIST SP 800-53 Rev 4:** AC-12
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-214388 - AS24-W2-000670
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
Review the <'INSTALLED PATH'>\conf\httpd.conf file.

If "IP Address Restrictions" are not configured or IP ranges configured to be "Allow" are not restrictive enough to prevent connections from nonsecure zones, this is a finding.
```
**NIST SP 800-53 Rev 4:** AC-17 (1)
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-214389 - AS24-W2-000690
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

#### V-214390 - AS24-W2-000780
**Severity:** MEDIUM

**Rule Title:** The Apache web server must prohibit or restrict the use of nonsecure or unnecessary ports, protocols, modules, and/or services.

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
Review the web server documentation and deployment configuration to determine which ports and protocols are enabled.
 
Verify
 the ports and protocols being used are permitted, necessary for the 
operation of the web server and the hosted applications, and are secure 
for a production system.
 
Open the <'INSTALLED PATH'>\conf\httpd.conf file.
 
Verify only the listener for IANA well-known ports for HTTP and HTTPS are in use.
 
If
 any of the ports or protocols are not permitted, are nonsecure, ...
```
**NIST SP 800-53 Rev 4:** CM-7 (1) (b)
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-214392 - AS24-W2-000830
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
Review the <'INSTALLED PATH'>\conf\httpd.conf file. 

Verify the "Timeout" directive is specified to have a value of "60" seconds or less.

If the "Timeout" directive is not configured or is set for more than "60" seconds, this is a finding.
```
**NIST SP 800-53 Rev 4:** SC-5 (1)
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-214393 - AS24-W2-000860
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

If the directive does not exist, this is a not a finding.

If the directive exists and is not set to "off", this is a finding.
```
**NIST SP 800-53 Rev 4:** SC-8
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-214394 - AS24-W2-000870
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
Verify the  "session_cookie_module"  module is installed.

Inspect the httpd.conf file to confirm the "session_cookie_module" is being used.

If the "session_cookie_module" module is not being used, this is a finding.

Search for the "Session" and "SessionCookieName" directives.

If "Session" is not "on" and "SessionCookieName" does not contain "httpOnly" and "secure", this is a finding.
```
**NIST SP 800-53 Rev 4:** SC-8
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

### Partially Automatable (5 checks)

#### V-214371 - AS24-W2-000390
**Severity:** MEDIUM

**Rule Title:** Only authenticated system administrators or the designated PKI Sponsor for the Apache web server must have access to the Apache web servers private key.

**Automation Status:** Partially Automatable

**Automation Method:** Bash (file/directory checks)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**🔧 Configuration Dependencies:**
- ⚠️ **ENVIRONMENT-SPECIFIC**: This check requires site-specific or organizational values

**Notes:**
- Requires environment-specific paths

**Check Content:**
```
If the Apache web server does not have a private key, this is Not Applicable.

Review the private key path in the "SSLCertificateFile" directive. Verify only authenticated System Administrators and the designated PKI Sponsor for the web server can access the web server private key.

If the private key is accessible by unauthenticated or unauthorized users, this is a finding.
```
**NIST SP 800-53 Rev 4:** IA-5 (2) (b)
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-214375 - AS24-W2-000460
**Severity:** MEDIUM

**Rule Title:** The Apache web server must invalidate session identifiers upon hosted application user logout or other session termination.

**Automation Status:** Partially Automatable

**Automation Method:** Bash/Python (needs validation)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**🔧 Configuration Dependencies:**
- ⚠️ **ENVIRONMENT-SPECIFIC**: This check requires site-specific or organizational values

**Notes:**
- Automation possible but may require manual validation

**Check Content:**
```
Working with the administrator, inspect the module used to invalidate sessions upon logout or other organizationally defined event (such as removing a CAC).

Verify SessionMaxAge in that module is set to "1".

If SessionMaxAge does not exist, this is a finding.

If SessionMaxAge is not set to "1", this is a finding.

Alternative instruction:
Log in to the site using a test account.

Log out of the site.

Confirm the session and session ID were terminated and use of the website is no longer possi...
```
**NIST SP 800-53 Rev 4:** SC-23 (1)
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-214391 - AS24-W2-000800
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

#### V-214395 - AS24-W2-000880
**Severity:** MEDIUM

**Rule Title:** Cookies exchanged between the Apache web server and the client, such as session cookies, must have cookie properties set to force the encryption of cookies.

**Automation Status:** Partially Automatable

**Automation Method:** Bash/Python (needs validation)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**🔧 Configuration Dependencies:**
- ⚠️ **ENVIRONMENT-SPECIFIC**: This check requires site-specific or organizational values

**Notes:**
- Automation possible but may require manual validation

**Check Content:**
```
Verify the "mod_session_crypto" module is installed.

If the mod_session_crypto module is not being used, this is a finding.
```
**NIST SP 800-53 Rev 4:** SC-8
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-214396 - AS24-W2-000890
**Severity:** HIGH

**Rule Title:** An Apache web server must maintain the confidentiality of controlled information during transmission through the use of an approved TLS version.

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
In a command line, navigate to "<'INSTALLED PATH'>\bin". Run "httpd -M" to view a list of installed modules.

If the module "mod_ssl" is not enabled, this is a finding.

Review the <'INSTALLED PATH'>\conf\httpd.conf file to determine if the "SSLProtocol" directive exists and looks like the following:

SSLProtocol -ALL +TLSv1.2

If the directive does not exist and does not contain "-ALL +TLSv1.2", this is a finding.
```
**NIST SP 800-53 Rev 4:** AC-17 (2)
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

### Manual Review Required (4 checks)

#### V-214365 - AS24-W2-000240
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

#### V-214373 - AS24-W2-000440
**Severity:** HIGH

**Rule Title:** Anonymous user access to the Apache web server application directories must be prohibited.

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
**NIST SP 800-53 Rev 4:** SC-2
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-214380 - AS24-W2-000540
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

#### V-214397 - AS24-W2-000950
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
Review the website to determine if "HTTP" and "HTTPS" are used in accordance with well-known ports (e.g., 80 and 443) or those ports and services as registered and approved for use by the DoD PPSM. 

Verify that any variation in PPS is documented, registered, and approved by the PPSM.

If it is not, this is a finding.
```
**NIST SP 800-53 Rev 4:** CM-6 b
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

### Needs Analysis (2 checks)

#### V-214374 - AS24-W2-000450
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

#### V-214382 - AS24-W2-000580
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

