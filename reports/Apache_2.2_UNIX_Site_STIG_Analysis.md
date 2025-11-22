# APACHE 2.2 Site for UNIX STIG Check Analysis Report
**Generated:** 2025-11-22 15:11:52
**STIG:** APACHE 2.2 Site for UNIX :: Release: 11 Benchmark Date: 25 Jan 2019
**Total Checks:** 29

---

## 📊 Executive Summary

### Automation Status Overview

| Automation Status | Count | Percentage | Status |
|------------------|-------|------------|--------|
| ✅ Automatable | 22 | 75.9% | Can be fully automated |
| ⚠️ Partially Automatable | 3 | 10.3% | Requires some manual validation |
| 📝 Manual Review Required | 4 | 13.8% | Cannot be automated |
| 🔍 Needs Analysis | 0 | 0.0% | Automation feasibility TBD |
| **TOTAL** | **29** | **100.0%** | |

### Automation Status by Severity

| Severity | Total | Automatable | Partial | Manual | Automation Rate |
|----------|-------|-------------|---------|--------|----------------|
| HIGH | 4 | 2 | 1 | 1 | 75.0% |
| MEDIUM | 21 | 18 | 2 | 1 | 95.2% |
| LOW | 4 | 2 | 0 | 2 | 50.0% |
| **TOTAL** | **29** | **22** | **3** | **4** | **86.2%** |

### Configuration Dependencies

| Dependency Type | Count | Percentage | Description |
|----------------|-------|------------|-------------|
| 🌐 Environment-Specific | 7 | 24.1% | Requires site-specific/organizational values |
| 🖥️ System-Specific | 19 | 65.5% | Depends on deployment/installation config |
| ✓ Standard | 3 | 10.3% | No special dependencies |

### Severity Distribution

| Severity | Count | Percentage |
|----------|-------|------------|
| 🔴 HIGH | 4 | 13.8% |
| 🟡 MEDIUM | 21 | 72.4% |
| 🟢 LOW | 4 | 13.8% |
| **TOTAL** | **29** | **100.0%** |

### Tool Preference (Priority: Bash > PowerShell > Python > Third-Party)

| Tool Type | Count | Notes |
|-----------|-------|-------|
| Bash (Native) | 25 | Primary method - no dependencies |
| Python (Native) | 0 | Fallback - uses stdlib only |
| Third-Party Optional | 0 | All checks use native commands |
| **Minimal Third-Party** | **25** | **86.2% can run without third-party tools** |

## Summary
- **Automatable Checks:** 22 (75.9%)
- **Partially Automatable:** 3 (10.3%)
- **Manual Review Required:** 4 (13.8%)
- **Needs Analysis:** 0 (0.0%)

### Environment/System Specific Checks
- **Environment-Specific:** 7 (24.1%)
  - *These checks require site-specific, organizational, or approved values*
- **System-Specific:** 19 (65.5%)
  - *These checks depend on deployment or installation-specific configurations*

### Severity Distribution
- **High:** 4
- **Medium:** 21
- **Low:** 4

---

## Detailed Check Analysis

### Automatable (22 checks)

#### V-13687 - WG237 A22
**Severity:** MEDIUM

**Rule Title:** Remote authors or content providers must have all files scanned for viruses and malicious code before uploading files to the Document Root directory.

**Automation Status:** Automatable

**Automation Method:** Bash (file/directory checks)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**Check Content:**
```
Remote web authors should not be able to upload files to the Document Root directory structure without virus checking and checking for malicious or mobile code. _x000D_
_x000D_
Query the SA to determine if there is anti-virus software active on the server with auto-protect enabled, or if there is another process in place for the scanning of files being posted by remote authors. _x000D_
_x000D_
If there is no virus software on the system with auto-protect enabled, or if there is not a process in ...
```

--------------------------------------------------------------------------------

#### V-13688 - WG242 A22
**Severity:** MEDIUM

**Rule Title:** Log file data must contain required data elements.

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
To verify the log settings:_x000D_
_x000D_
Default UNIX location: /usr/local/apache/logs/access_log_x000D_
_x000D_
If this directory does not exist, you can search the web server for the httpd.conf file to determine the location of the logs._x000D_
_x000D_
Items to be logged are as shown in this sample line in the httpd.conf file:_x000D_
_x000D_
LogFormat "%a %A %h %H %l %m %s %t %u %U \"%{Referer}i\" " combined_x000D_
_x000D_
If the web server is not configured to capture the required audit eve...
```

--------------------------------------------------------------------------------

#### V-13689 - WG255 A22
**Severity:** MEDIUM

**Rule Title:** Access to the web server log files must be restricted to administrators, web administrators, and auditors.

**Automation Status:** Automatable

**Automation Method:** Bash (ls -l, stat commands)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**🔧 Configuration Dependencies:**
- ⚠️ **ENVIRONMENT-SPECIFIC**: This check requires site-specific or organizational values
- ⚠️ **SYSTEM-SPECIFIC**: This check depends on deployment/installation-specific configuration

**Notes:**
- File permission verification

**Check Content:**
```
Look for the presence of log files at:_x000D_
_x000D_
/usr/local/apache/logs/access_log _x000D_
_x000D_
To ensure the correct location of the log files, examine the "ServerRoot" directive in the htttpd.conf file and then navigate to that directory where you will find a subdirectory for the logs. _x000D_
_x000D_
Determine permissions for log files, from the command line: cd to the directory where the log files are located and enter the command: _x000D_
_x000D_
ls â€“al *log and note the owner and...
```

--------------------------------------------------------------------------------

#### V-13694 - WG342 A22
**Severity:** MEDIUM

**Rule Title:** Public web servers must use TLS if authentication is required.

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
Enter the following command: _x000D_
_x000D_
/usr/local/apache2/bin/httpd â€“M _x000D_
_x000D_
This will provide a list of all the loaded modules. Verify that the â€œssl_moduleâ€ is loaded. If this module is not found, this is a finding. _x000D_
_x000D_
After determining that the ssl module is active, enter the following command: _x000D_
_x000D_
grep "SSL" /usr/local/apache2/conf/httpd.conf _x000D_
_x000D_
Review the SSL sections of the httpd.conf file, all enabled SSLProtocol directives for Ap...
```

--------------------------------------------------------------------------------

#### V-2226 - WG210 A22
**Severity:** MEDIUM

**Rule Title:** Web content directories must not be anonymously shared.

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
To view the DocumentRoot enter the following command: _x000D_
_x000D_
grep "DocumentRoot" /usr/local/apache2/conf/httpd.conf _x000D_
_x000D_
To view the ServerRoot enter the following command: _x000D_
_x000D_
grep "serverRoot" /usr/local/apache2/conf/httpd.conf _x000D_
_x000D_
Note the location following the DocumentRoot and ServerRoot directives. _x000D_
_x000D_
Enter the following commands to determine if file sharing is running: _x000D_
_x000D_
ps -ef | grep nfs, ps -ef | grep smb _x000D_
_x0...
```

--------------------------------------------------------------------------------

#### V-2227 - WG360 A22
**Severity:** HIGH

**Rule Title:** Symbolic links must not be used in the web content directory tree.

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
Locate the directories containing the web content, (i.e., /usr/local/apache/htdocs). _x000D_
_x000D_
Use ls â€“al. _x000D_
_x000D_
An entry, such as the following, would indicate the presence and use of symbolic links:_x000D_
_x000D_
lr-xrâ€”r--  4000 wwwusr  wwwgrp	2345	Apr 15	  data  -> /usr/local/apache/htdocs_x000D_
_x000D_
Such a result found in a web document directory is a finding. Additional Apache configuration check in the httpd.conf file:_x000D_
_x000D_
<Directory /[website root dir]>...
```

--------------------------------------------------------------------------------

#### V-2228 - WG400 A22
**Severity:** MEDIUM

**Rule Title:** All interactive programs (CGI) must be placed in a designated directory with appropriate permissions.

**Automation Status:** Automatable

**Automation Method:** Bash (grep/awk/sed for config parsing)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**Notes:**
- Configuration file parsing (httpd.conf/ssl.conf)

**Check Content:**
```
To preclude access to the servers root directory, ensure the following directive is in the httpd.conf file. This entry will also stop users from setting up .htaccess files which can override security features configured in httpd.conf._x000D_
_x000D_
<DIRECTORY /[website root dir]>_x000D_
AllowOverride None_x000D_
</DIRECTORY>_x000D_
_x000D_
If the AllowOverride None is not set, this is a finding._x000D_

```

--------------------------------------------------------------------------------

#### V-2240 - WG110 A22
**Severity:** MEDIUM

**Rule Title:** The number of allowed simultaneous requests must be set.

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
To view the MaxKeepAliveRequests value, enter the following command: _x000D_
_x000D_
grep "MaxKeepAliveRequests" /usr/local/apache2/conf/httpd.conf _x000D_
_x000D_
If the returned value of MaxKeepAliveRequests is not set to 100 or greater, this is a finding. _x000D_

```

--------------------------------------------------------------------------------

#### V-2245 - WG170 A22
**Severity:** LOW

**Rule Title:** Each readable web document directory must contain either a default, home, index, or equivalent file.

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
To view the DocumentRoot value enter the following command: _x000D_
awk '{print $1,$2,$3}' /usr/local/apache2/conf/httpd.conf|grep -i DocumentRoot|grep -v '^#'_x000D_
Note each location following the DocumentRoot string, this is the configured path(s) to the document root directory(s). _x000D_
To view a list of the directories and sub-directories and the file index.html, from each stated DocumentRoot location enter the following commands:_x000D_
find . -type d_x000D_
find . -type f -name index.h...
```

--------------------------------------------------------------------------------

#### V-2250 - WG240 A22
**Severity:** MEDIUM

**Rule Title:** Logs of web server access and errors must be established and maintained

**Automation Status:** Automatable

**Automation Method:** Bash (apachectl/httpd commands)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**🔧 Configuration Dependencies:**
- ⚠️ **SYSTEM-SPECIFIC**: This check depends on deployment/installation-specific configuration

**Notes:**
- Apache command-line tool verification

**Check Content:**
```
To view a list of loaded modules enter the following command: _x000D_
_x000D_
/usr/local/apache2/bin/httpd -M _x000D_
_x000D_
If the following module is not found, this is a finding: "log_config_module"
```

--------------------------------------------------------------------------------

#### V-2252 - WG250 A22
**Severity:** MEDIUM

**Rule Title:** Log file access must be restricted to System Administrators, Web Administrators or Auditors.

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
Enter the following command to determine the directory the log files are located in:_x000D_
_x000D_
grep "ErrorLog" /usr/local/apache2/conf/httpd.conf_x000D_
_x000D_
grep "CustomLog" /usr/local/apache2/conf/httpd.conf_x000D_
_x000D_
Verify the permission of the ErrorLog & CustomLog files by entering the following command:_x000D_
_x000D_
ls -al /usr/local/apache2/logs/*.log _x000D_
_x000D_
Unix file permissions should be 640 or less for all web log files if not, this is a finding.  _x000D_

```

--------------------------------------------------------------------------------

#### V-2258 - WG290 A22
**Severity:** HIGH

**Rule Title:** Web client access to the content directories must be restricted to read and execute.

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
To view the value of Alias enter the following command: _x000D_
_x000D_
grep "Alias" /usr/local/apache2/conf/httpd.conf _x000D_
_x000D_
Alias_x000D_
ScriptAlias_x000D_
ScriptAliasMatch_x000D_
_x000D_
Review the results to determine the location of the files listed above. _x000D_
_x000D_
Enter the following command to determine the permissions of the above file: _x000D_
_x000D_
ls -Ll /file-path_x000D_
_x000D_
The only accounts listed should be the web administrator, developers, and the account a...
```

--------------------------------------------------------------------------------

#### V-2260 - WG310 A22
**Severity:** MEDIUM

**Rule Title:** A web site must not contain a robots.txt file.

**Automation Status:** Automatable

**Automation Method:** Bash (grep/awk/sed for config parsing)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**Notes:**
- Configuration file parsing (httpd.conf/ssl.conf)

**Check Content:**
```
Locate the Apache httpd.conf file._x000D_
_x000D_
If unable to locate the file, perform a search of the system to find the location of the file._x000D_
_x000D_
Open the httpd.conf file with an editor and search for the following uncommented directives: DocumentRoot & Alias_x000D_
_x000D_
Navigate to the location(s) specified in the Include statement(s), and review each file for the following uncommented directives: DocumentRoot & Alias_x000D_
_x000D_
At the top level of the directories identifie...
```

--------------------------------------------------------------------------------

#### V-2263 - WG350 A22
**Severity:** MEDIUM

**Rule Title:** A private web server will have a valid DoD server certificate.

**Automation Status:** Automatable

**Automation Method:** Bash (native commands)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**Notes:**
- Command-line verification possible

**Check Content:**
```
Open browser window and browse to the appropriate site. Before entry to the site, you should be presented with the server's DoD PKI credentials. Review these credentials for authenticity._x000D_
_x000D_
Find an entry which cites:_x000D_
_x000D_
Issuer:_x000D_
CN = DOD CLASS 3 CA-3_x000D_
OU = PKI_x000D_
OU = DoD_x000D_
O = U.S. Government_x000D_
C = US_x000D_
_x000D_
If the server is running as a public web server, this finding should be Not Applicable._x000D_
_x000D_
NOTE: In some cases, the we...
```

--------------------------------------------------------------------------------

#### V-2265 - WG490 A22
**Severity:** LOW

**Rule Title:** Java software on production web servers must be limited to class files and the JAVA virtual machine.

**Automation Status:** Automatable

**Automation Method:** Bash (native commands)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**Notes:**
- Command-line verification possible

**Check Content:**
```
Enter the commands: _x000D_
_x000D_
find / -name *.java _x000D_
_x000D_
find / -name *.jpp _x000D_
_x000D_
If either file type is found, this is a finding.
```

--------------------------------------------------------------------------------

#### V-2270 - WG430 A22
**Severity:** MEDIUM

**Rule Title:** Anonymous FTP user access to interactive scripts is prohibited.

**Automation Status:** Automatable

**Automation Method:** Bash (ls -l, stat commands)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**Notes:**
- File permission verification

**Check Content:**
```
Locate the directories containing the CGI scripts. These directories should be language-specific (e.g., PERL, ASP, JS, JSP, etc.). _x000D_
_x000D_
Using ls â€“al, examine the file permissions on the CGI, the cgi-bin, and the cgi-shl directories._x000D_
_x000D_
Anonymous FTP users must not have access to these directories._x000D_
_x000D_
If the CGI, the cgi-bin, or the cgi-shl directories can be accessed by any group that does not require access, this is a finding._x000D_

```

--------------------------------------------------------------------------------

#### V-2272 - WG460 A22
**Severity:** MEDIUM

**Rule Title:** PERL scripts must use the TAINT option.

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
When a PERL script is invoked for execution on a UNIX server, the method which invokes the script must utilize the TAINT option._x000D_
_x000D_
The serverâ€™s interpreter examines the first line of the script. Typically, the first line of the script contains a reference to the scriptâ€™s language and processing options._x000D_
_x000D_
The first line of a PERL script will be as follows:_x000D_
_x000D_
#!/usr/local/bin/perl â€“T_x000D_
_x000D_
The â€“T at the end of the line referenced above, tell...
```

--------------------------------------------------------------------------------

#### V-26279 - WA00605 A22
**Severity:** MEDIUM

**Rule Title:** Error logging must be enabled.

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
Enter the following command:_x000D_
_x000D_
grep "ErrorLog" /usr/local/apache2/conf/httpd.conf_x000D_
_x000D_
This directive lists the name and location of the error log. _x000D_
 _x000D_
If the command result lists no data, this is a finding._x000D_

```

--------------------------------------------------------------------------------

#### V-26280 - WA00612 A22
**Severity:** MEDIUM

**Rule Title:** The sites error logs must log the correct format.

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
Enter the following command:_x000D_
_x000D_
grep "LogFormat" /usr/local/apache2/conf/httpd.conf._x000D_
_x000D_
The command should return the following value: _x000D_
_x000D_
LogFormat "%a %A %h %H %l %m %s %t %u %U \"%{Referer}i\" " combined._x000D_
_x000D_
If the above value is not returned, this is a finding. 
```

--------------------------------------------------------------------------------

#### V-26281 - WA00615 A22
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
Enter the following command:_x000D_
_x000D_
grep "CustomLog" /usr/local/apache2/conf/httpd.conf_x000D_
_x000D_
The command should return the following value:._x000D_
_x000D_
CustomLog "Logs/access_log" common_x000D_
_x000D_
If the above value is not returned, this is a finding._x000D_

```

--------------------------------------------------------------------------------

#### V-26282 - WA00620 A22
**Severity:** MEDIUM

**Rule Title:** The LogLevel directive must be enabled.

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
Enter the following command:_x000D_
_x000D_
grep "LogLevel" /usr/local/apache2/conf/httpd.conf_x000D_
_x000D_
The command should return the following value: _x000D_
_x000D_
LogLevel warn_x000D_
_x000D_
If the above value is not returned, this is a finding._x000D_
Note:  If LogLevel is set to error, crit, alert, or emerg which are higher thresholds this is not a finding._x000D_

```

--------------------------------------------------------------------------------

#### V-3333 - WG205 A22
**Severity:** MEDIUM

**Rule Title:** The web document (home) directory must be in a separate partition from the web serverâ€™s system files.

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
grep "DocumentRoot" /usr/local/apache2/conf/httpd.conf _x000D_
_x000D_
Note each location following the DocumentRoot string, this is the configured path to the document root directory(s). _x000D_
_x000D_
Use the command df -k to view each document root's partition setup. _x000D_
_x000D_
Compare that against the results for the Operating System file systems, and against the partition for the web server system files, which is the result of the command: _x000D_
_x000D_
df -k /usr/local/apache2/bin_...
```

--------------------------------------------------------------------------------

### Partially Automatable (3 checks)

#### V-13686 - WG235 A22
**Severity:** HIGH

**Rule Title:** Web Administrators must only use encrypted connections for Document Root directory uploads.

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
Determine if there is a process for the uploading of files to the web site. This process should include the requirement for the use of a secure encrypted logon and secure encrypted connection. If the remote users are uploading files without utilizing approved encryption methods, this is a finding.
```

--------------------------------------------------------------------------------

#### V-2262 - WG340 A22
**Severity:** MEDIUM

**Rule Title:** A private web server must utilize an approved TLS version.

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
Enter the following command:_x000D_
_x000D_
/usr/local/apache2/bin/httpd â€“M |grep -i ssl_x000D_
_x000D_
This will provide a list of all the loaded modules. Verify that the â€œssl_moduleâ€ is loaded. If this module is not found, determine if it is loaded as a dynamic module. Enter the following command:_x000D_
_x000D_
grep ^LoadModule /usr/local/apache2/conf/httpd.conf_x000D_
_x000D_
If the SSL module is not enabled this is a finding. _x000D_
_x000D_
After determining that the ssl module is ac...
```

--------------------------------------------------------------------------------

#### V-6531 - WG140 A22
**Severity:** MEDIUM

**Rule Title:** Private web servers must require certificates issued from a DoD-authorized Certificate Authority.

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
To view the SSLVerifyClient value enter the following command:_x000D_
_x000D_
grep "SSLVerifyClient" /usr/local/apache2/conf/httpd.conf._x000D_
_x000D_
If the value of SSLVerifyClient is not set to â€œrequireâ€, this is a finding.
```

--------------------------------------------------------------------------------

### Manual Review Required (4 checks)

#### V-15334 - WG610 A22
**Severity:** LOW

**Rule Title:** Web sites must utilize ports, protocols, and services according to PPSM guidelines.

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
Review the web site to determine if HTTP and HTTPs are used in accordance with well known ports (e.g., 80 and 443) or those ports and services as registered and approved for use by the DoD PPSM. Any variation in PPS will be documented, registered, and approved by the PPSM. If not, this is a finding.
```

--------------------------------------------------------------------------------

#### V-2249 - WG230 A22
**Severity:** HIGH

**Rule Title:** Web server administration must be performed over a secure path or at the local console.

**Automation Status:** Manual Review Required

**Automation Method:** Documentation Review

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**🔧 Configuration Dependencies:**
- ⚠️ **ENVIRONMENT-SPECIFIC**: This check requires site-specific or organizational values
- ⚠️ **SYSTEM-SPECIFIC**: This check depends on deployment/installation-specific configuration

**Notes:**
- Requires manual review of documentation

**Check Content:**
```
If web administration is performed remotely the following checks will apply:_x000D_
_x000D_
If administration of the server is performed remotely, it will only be performed securely by system administrators._x000D_
_x000D_
If web site administration or web application administration has been delegated, those users will be documented and approved by the ISSO._x000D_
_x000D_
Remote administration must be in compliance with any requirements contained within the Unix Server STIGs, and any applicable...
```

--------------------------------------------------------------------------------

#### V-2254 - WG260 A22
**Severity:** MEDIUM

**Rule Title:** Only web sites that have been fully reviewed and tested must exist on a production web server.

**Automation Status:** Manual Review Required

**Automation Method:** Requires SA Interview

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**Notes:**
- Requires system administrator interview or consultation

**Check Content:**
```
Query the ISSO, the SA, and the web administrator to find out if development web sites are being housed on production web servers. _x000D_
_x000D_
Proposed Questions:_x000D_
Do you have development sites on your production web server?_x000D_
What is your process to get development web sites / content posted to the production server?_x000D_
Do you use under construction notices on production web pages?_x000D_
_x000D_
The reviewer can also do a manual check or perform a navigation of the web site ...
```

--------------------------------------------------------------------------------

#### V-6373 - WG265 A22
**Severity:** LOW

**Rule Title:** The required DoD banner page must be displayed to authenticated users accessing a DoD private website.

**Automation Status:** Manual Review Required

**Automation Method:** Policy Review

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**🔧 Configuration Dependencies:**
- ⚠️ **ENVIRONMENT-SPECIFIC**: This check requires site-specific or organizational values

**Notes:**
- Requires review of organizational policies/procedures

**Check Content:**
```
The document, DoDI 8500.01, establishes the policy on the use of DoD information systems. It requires the use of a standard Notice and Consent Banner and standard text to be included in user agreements. _x000D_
_x000D_
The requirement for the banner is for websites with security and access controls. These are restricted and not publicly accessible. If the website does not require authentication/authorization for use, then the banner does not need to be present._x000D_
_x000D_
If a banner is requ...
```

--------------------------------------------------------------------------------

