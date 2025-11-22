# APACHE 2.2 Site for Windows STIG Check Analysis Report
**Generated:** 2025-11-22 15:11:52
**STIG:** APACHE 2.2 Site for Windows :: Release: 13 Benchmark Date: 25 Jan 2019
**Total Checks:** 28

---

## 📊 Executive Summary

### Automation Status Overview

| Automation Status | Count | Percentage | Status |
|------------------|-------|------------|--------|
| ✅ Automatable | 18 | 64.3% | Can be fully automated |
| ⚠️ Partially Automatable | 6 | 21.4% | Requires some manual validation |
| 📝 Manual Review Required | 4 | 14.3% | Cannot be automated |
| 🔍 Needs Analysis | 0 | 0.0% | Automation feasibility TBD |
| **TOTAL** | **28** | **100.0%** | |

### Automation Status by Severity

| Severity | Total | Automatable | Partial | Manual | Automation Rate |
|----------|-------|-------------|---------|--------|----------------|
| HIGH | 3 | 1 | 1 | 1 | 66.7% |
| MEDIUM | 21 | 15 | 5 | 1 | 95.2% |
| LOW | 4 | 2 | 0 | 2 | 50.0% |
| **TOTAL** | **28** | **18** | **6** | **4** | **85.7%** |

### Configuration Dependencies

| Dependency Type | Count | Percentage | Description |
|----------------|-------|------------|-------------|
| 🌐 Environment-Specific | 9 | 32.1% | Requires site-specific/organizational values |
| 🖥️ System-Specific | 4 | 14.3% | Depends on deployment/installation config |
| ✓ Standard | 15 | 53.6% | No special dependencies |

### Severity Distribution

| Severity | Count | Percentage |
|----------|-------|------------|
| 🔴 HIGH | 3 | 10.7% |
| 🟡 MEDIUM | 21 | 75.0% |
| 🟢 LOW | 4 | 14.3% |
| **TOTAL** | **28** | **100.0%** |

### Tool Preference (Priority: Bash > PowerShell > Python > Third-Party)

| Tool Type | Count | Notes |
|-----------|-------|-------|
| Bash (Native) | 24 | Primary method - no dependencies |
| Python (Native) | 0 | Fallback - uses stdlib only |
| Third-Party Optional | 0 | All checks use native commands |
| **Minimal Third-Party** | **24** | **85.7% can run without third-party tools** |

## Summary
- **Automatable Checks:** 18 (64.3%)
- **Partially Automatable:** 6 (21.4%)
- **Manual Review Required:** 4 (14.3%)
- **Needs Analysis:** 0 (0.0%)

### Environment/System Specific Checks
- **Environment-Specific:** 9 (32.1%)
  - *These checks require site-specific, organizational, or approved values*
- **System-Specific:** 4 (14.3%)
  - *These checks depend on deployment or installation-specific configurations*

### Severity Distribution
- **High:** 3
- **Medium:** 21
- **Low:** 4

---

## Detailed Check Analysis

### Automatable (18 checks)

#### V-13688 - WG242 W22
**Severity:** MEDIUM

**Rule Title:** Log file data must contain required data elements.

**Automation Status:** Automatable

**Automation Method:** Bash (grep/awk/sed for config parsing)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**Notes:**
- Configuration file parsing (httpd.conf/ssl.conf)

**Check Content:**
```
To verify the log settings:_x000D_
_x000D_
Default Windows location: :\Program Files\Apache Group\Apache2\logs\access.log or :\Program Files\Apache Software Foundation\Apache2.2\logs\access.log._x000D_
_x000D_
If these directories do not exist, you can search the web server for the httpd.conf config file to determine the location of the logs._x000D_
_x000D_
Items to be logged are as shown in this sample line in the httpd.conf file:_x000D_
_x000D_
LogFormat "%a %A %h %H %l %m %s %t %u %U \"%{Refe...
```

--------------------------------------------------------------------------------

#### V-13689 - WG255 W22
**Severity:** MEDIUM

**Rule Title:** Access to the web server log files must be restricted to Administrators, the user assigned to run the web server software, Web Manager, and Auditors.

**Automation Status:** Automatable

**Automation Method:** Bash (grep/awk/sed for config parsing)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**Notes:**
- Configuration file parsing (httpd.conf/ssl.conf)

**Check Content:**
```
Determine permissions for log files_x000D_
_x000D_
Find the httpd.conf configuration file to determine the location of the log files. The location is indicated at the "ServerRoot" directive. The log directory is a sub-directory under the ServerRoot. _x000D_
_x000D_
ex. :\Apache Group\Apache2\logs or :\Apache Software Foundation\Apache2.2\logs_x000D_
_x000D_
After locating the logs, use the Explorer to move to these files and examine their properties: _x000D_
_x000D_
Properties >> Security >> Per...
```

--------------------------------------------------------------------------------

#### V-13694 - WG342 W22
**Severity:** MEDIUM

**Rule Title:** Public web servers must use TLS if authentication is required.

**Automation Status:** Automatable

**Automation Method:** Bash (grep/awk/sed for config parsing)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**Notes:**
- Configuration file parsing (httpd.conf/ssl.conf)

**Check Content:**
```
Verify that the ssl module is loaded. Open a command prompt and run the following command from the directory when httpd.exe is located: httpd â€“M_x000D_
_x000D_
This will provide a list of all the loaded modules. Verify that the â€œssl_moduleâ€ is loaded. If this module is not found, this is a finding._x000D_
_x000D_
After determining that the ssl module is active, locate the Apache httpd.conf file._x000D_
_x000D_
If unable to locate the file, perform a search of the system to find the locatio...
```

--------------------------------------------------------------------------------

#### V-2228 - WG400 W22
**Severity:** MEDIUM

**Rule Title:** All interactive programs must be placed in a designated directory with appropriate permissions.

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
If the AllowOverride None is not set, this is a finding.
```

--------------------------------------------------------------------------------

#### V-2229 - WG410 W22
**Severity:** MEDIUM

**Rule Title:** Interactive scripts used on a web server must have proper access controls.

**Automation Status:** Automatable

**Automation Method:** Bash (ls -l, stat commands)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**Notes:**
- File permission verification

**Check Content:**
```
Query the SA to determine if CGI scripts are used as part of the web site. _x000D_
_x000D_
If interactive scripts are being used, check the permissions of these files to ensure they meet the following permissions:_x000D_
_x000D_
interactive script files_x000D_
_x000D_
Administrators Full Control_x000D_
WebManagers Modify_x000D_
System Read/Execute_x000D_
Webserver Account Read/Execute _x000D_
_x000D_
If the interactive scripts do not meet the above permissions or are less restrictive, this is a ...
```

--------------------------------------------------------------------------------

#### V-2240 - WG110 W22
**Severity:** MEDIUM

**Rule Title:** The number of allowed simultaneous requests must be set.

**Automation Status:** Automatable

**Automation Method:** Bash (grep/awk/sed for config parsing)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**Notes:**
- Configuration file parsing (httpd.conf/ssl.conf)

**Check Content:**
```
NOTE: This setting must be explicitly set._x000D_
_x000D_
Locate the Apache httpd.conf file._x000D_
_x000D_
If unable to locate the file, perform a search of the system to find the location of the file._x000D_
_x000D_
Open the httpd.conf file with an editor such as notepad, and search for the following uncommented directive: MaxKeepAliveRequests_x000D_
_x000D_
Every enabled MaxKeepAliveRequests value needs to be 100 or greater. If any directive is less than 100, this is a finding.
```

--------------------------------------------------------------------------------

#### V-2245 - WG170 W22
**Severity:** LOW

**Rule Title:** Each readable web document directory must contain either a default, home, index, or equivalent file.

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
Open the httpd.conf file with an editor such as notepad, and search for the following uncommented directive: DocumentRoot_x000D_
_x000D_
Note the name of the DocumentRoot directory._x000D_
_x000D_
Review the results for each document root directory and its subdirectories. If a directory does not contain an index.html or equivalent default...
```

--------------------------------------------------------------------------------

#### V-2250 - WG240 W22
**Severity:** MEDIUM

**Rule Title:** Logs of web server access and errors must be established and maintained.

**Automation Status:** Automatable

**Automation Method:** Bash (file/directory checks)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**Check Content:**
```
Open a command prompt window._x000D_
_x000D_
Navigate to the â€œbinâ€ directory (in many cases this may be [Drive Letter]:\[directory path]\Apache Software Foundation\Apache2.2\bin>)._x000D_
_x000D_
Enter the following command and press Enter: httpd â€“M_x000D_
_x000D_
This will provide a list of all loaded modules. If the following module is not found this is a finding: log_config_module.
```

--------------------------------------------------------------------------------

#### V-2258 - WG290 W22
**Severity:** HIGH

**Rule Title:** The web client account access to the content and scripts directories must be limited to read and execute.

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
Open the httpd.conf file with an editor such as Notepad, and search for the following uncommented directives:  DocumentRoot, Alias, ScriptAlias, & ScriptAliasMatch _x000D_
_x000D_
Navigate to the locations specified after each enabled DocumentRoot, Alias, ScriptAlias, & ScriptAliasMatch directives. _x000D_
Right click on the file or direc...
```

--------------------------------------------------------------------------------

#### V-2260 - WG310 W22
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

#### V-2263 - WG350 W22
**Severity:** MEDIUM

**Rule Title:** A private web server must have a valid DoD server certificate.

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

#### V-2265 - WG490 W22
**Severity:** LOW

**Rule Title:** Java software on production web servers must be limited to class files and the JAVA virtual machine.

**Automation Status:** Automatable

**Automation Method:** Bash (file/directory checks)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**Check Content:**
```
Search the web content and scripts directories (found in check WG290) for .java and .jpp files._x000D_
_x000D_
If either file type is found, this is a finding._x000D_
_x000D_
Note: Executables such as java.exe, jre.exe, and jrew.exe are permitted.
```

--------------------------------------------------------------------------------

#### V-2270 - WG430 W22
**Severity:** MEDIUM

**Rule Title:** Anonymous FTP user access to interactive scripts must be prohibited.

**Automation Status:** Automatable

**Automation Method:** Bash (file/directory checks)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**Check Content:**
```
Locate the directories containing the CGI scripts. These directories should be language-specific (e.g., PERL, ASP, JS, JSP, etc.). _x000D_
_x000D_
Right-click on the web content directory and the related CGI directories. On the Properties tab, examine the access rights for the CGI, cgi-bin, or cgi-shl directories. _x000D_
_x000D_
Anonymous FTP users must not have access to these directories._x000D_
_x000D_
If the CGI, the cgi-bin, or the cgi-shl directories can be accessed by any group that does...
```

--------------------------------------------------------------------------------

#### V-26279 - WA00605 W22
**Severity:** MEDIUM

**Rule Title:** Error logging must be enabled.

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
Open the httpd.conf file with an editor such as notepad, and search for the following uncommented directives: ErrorLog_x000D_
_x000D_
This directive specifies the name and location of the error log, if not found, this is a finding._x000D_
_x000D_
Note: This check is applicable to every host and virtual host the web server is supporting.
```

--------------------------------------------------------------------------------

#### V-26280 - WA00612 W22
**Severity:** MEDIUM

**Rule Title:** The sites error logs must log the correct format.

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
Open the httpd.conf file with an editor such as notepad, and search for the following uncommented directive:  LogFormat_x000D_
_x000D_
The minimum items to be logged are as shown in the sample below:_x000D_
_x000D_
LogFormat "%a %A %h %H %l %m %s %t %u %U \"%{Referer}i\"" combined_x000D_
_x000D_
Verify the information following the LogFor...
```

--------------------------------------------------------------------------------

#### V-26281 - WA00615 W22
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
Locate the Apache httpd.conf file._x000D_
_x000D_
If unable to locate the file, perform a search of the system to find the location of the file._x000D_
Open the httpd.conf file with an editor such as Notepad, and search for the following uncommented directives: _x000D_
LoadModule log_config_module modules/mod_log_config.so_x000D_
If the LoadModule log_config_module directive is commented out or does not exist, this is a finding._x000D_
_x000D_
Search for both of the following uncommented directi...
```

--------------------------------------------------------------------------------

#### V-26282 - WA00620 W22
**Severity:** MEDIUM

**Rule Title:** The LogLevel directive must be enabled.

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
Open the httpd.conf file with an editor such as notepad, and search for the following uncommented directives: LogLevel_x000D_
_x000D_
All enabled LogLevel directives should be set to a minimum of â€œwarnâ€, if not, this is a finding._x000D_
_x000D_
Note:  If LogLevel is set to error, crit, alert, or emerg which are higher thresholds this...
```

--------------------------------------------------------------------------------

#### V-3333 - WG205 W22
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
Verify that installation directories for Apache HTTP server are located on another partition, other than the OS partition._x000D_
_x000D_
Locate the Apache httpd.conf file._x000D_
_x000D_
If unable to locate the file, perform a search of the system to find the location of the file._x000D_
_x000D_
Open the httpd.conf file with an editor such as notepad, and search for the following uncommented directives: DocumentRoot, ErrorLog, CustomLog _x000D_
_x000D_
Note the location specified for each of th...
```

--------------------------------------------------------------------------------

### Partially Automatable (6 checks)

#### V-13686 - WG235 W22
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
Query the SA to determine if there is a process for the uploading of files to the web site. This process should include the requirement for the use of a secure encrypted logon and secure encrypted connection._x000D_
_x000D_
If the remote users are uploading files without utilizing approved encryption methods, this is a finding.
```

--------------------------------------------------------------------------------

#### V-2226 - WG210 W22
**Severity:** MEDIUM

**Rule Title:** Web content directories must not be anonymously shared.

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
Locate the Apache httpd.conf file._x000D_
_x000D_
If unable to locate the file, perform a search of the system to find the location of the file._x000D_
_x000D_
Open the httpd.conf file with an editor such as notepad, and search for the following uncommented directives: DocumentRoot & ServerRoot_x000D_
_x000D_
Note the location following each enabled DocumentRoot and ServerRoot directives._x000D_
_x000D_
Navigate to the DocumentRoot, and ServerRoot, using the path identified above. Right click on...
```

--------------------------------------------------------------------------------

#### V-2252 - WG250 W22
**Severity:** MEDIUM

**Rule Title:** Log file access must be restricted to System Administrators, Web Administrators or Auditors.

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
Locate the Apache httpd.conf file._x000D_
_x000D_
If unable to locate the file, perform a search of the system to find the location of the file._x000D_
_x000D_
Open the httpd.conf file with an editor such as Notepad, and search for the following uncommented directives:  ErrorLog & CustomLog_x000D_
_x000D_
Navigate to the location of the file specified after each enabled ErrorLog & CustomLog directive and verify the permissions assigned to these files. Right click on the file to be examined. Sele...
```

--------------------------------------------------------------------------------

#### V-2262 - WG340 W22
**Severity:** MEDIUM

**Rule Title:** A private web server must utilize an approved TLS version.

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
Verify that the ssl module is loaded. _x000D_
_x000D_
Open a command prompt and run the following command from the directory where httpd.exe is located: httpd â€“M_x000D_
This will provide a list of all the loaded modules. Verify that the â€œssl_moduleâ€ is loaded. _x000D_
_x000D_
If this module is not found, this is a finding._x000D_
_x000D_
After determining that the ssl module is active, locate the Apache httpd.conf file. _x000D_
_x000D_
If unable to locate the file, perform a search of the ...
```

--------------------------------------------------------------------------------

#### V-2272 - WG460 W22
**Severity:** MEDIUM

**Rule Title:** PERL scripts must use the TAINT option.

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
Locate the Apache httpd.conf file._x000D_
_x000D_
If unable to locate the file, perform a search of the system to find the location of the file._x000D_
_x000D_
Open the httpd.conf file with an editor such as Notepad, and search for the following uncommented directive: ScriptInterpreterSource_x000D_
_x000D_
For any enabled ScriptInterpreterSource directives the only authorized entries are Registry-Strict or Script. If any other entry (i.e. Registry) is found, this is a finding._x000D_
_x000D_
For...
```

--------------------------------------------------------------------------------

#### V-6531 - WG140 W22
**Severity:** MEDIUM

**Rule Title:** Private web servers must require certificates issued from a DoD-authorized Certificate Authority.

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
Locate the Apache httpd.conf file._x000D_
_x000D_
If unable to locate the file, perform a search of the system to find the location of the file._x000D_
_x000D_
Open the httpd.conf file with an editor such as notepad, and search for the following uncommented directive: SSLVerifyClient_x000D_
_x000D_
If SSLVerifyClient is not set to â€œrequireâ€ this is a finding as the client is not required to present a valid certificate.
```

--------------------------------------------------------------------------------

### Manual Review Required (4 checks)

#### V-15334 - WG610 W22
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

#### V-2249 - WG230 W22
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
If web administration is performed at the console, this check is N/A._x000D_
_x000D_
If web administration is performed remotely the following checks will apply:_x000D_
1. If administration of the server is performed remotely, it will only be performed securely by system administrators._x000D_
2. If web site administration or web application administration has been delegated, those users will be documented and approved by the ISSO._x000D_
3. Remote administration must be in compliance with any r...
```

--------------------------------------------------------------------------------

#### V-2254 - WG260 W22
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
Definition: A production web server is any web server connected to a production network, regardless of its role._x000D_
_x000D_
Proposed Questions:_x000D_
Do you have development sites on your production web server?_x000D_
What is your process to get development web sites / content posted to the production server?_x000D_
Do you use under construction ...
```

--------------------------------------------------------------------------------

#### V-6373 - WG265 W22
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

