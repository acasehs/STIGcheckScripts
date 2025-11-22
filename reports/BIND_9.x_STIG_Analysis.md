# BIND 9.x STIG Check Analysis Report
**Generated:** 2025-11-22 15:11:52
**STIG:** BIND 9.x :: Release: 3 Benchmark Date: 15 May 2024
**Total Checks:** 70

---

## 📊 Executive Summary

### Automation Status Overview

| Automation Status | Count | Percentage | Status |
|------------------|-------|------------|--------|
| ✅ Automatable | 51 | 72.9% | Can be fully automated |
| ⚠️ Partially Automatable | 17 | 24.3% | Requires some manual validation |
| 📝 Manual Review Required | 2 | 2.9% | Cannot be automated |
| 🔍 Needs Analysis | 0 | 0.0% | Automation feasibility TBD |
| **TOTAL** | **70** | **100.0%** | |

### Automation Status by Severity

| Severity | Total | Automatable | Partial | Manual | Automation Rate |
|----------|-------|-------------|---------|--------|----------------|
| HIGH | 8 | 5 | 3 | 0 | 100.0% |
| MEDIUM | 45 | 32 | 12 | 1 | 97.8% |
| LOW | 17 | 14 | 2 | 1 | 94.1% |
| **TOTAL** | **70** | **51** | **17** | **2** | **97.1%** |

### Configuration Dependencies

| Dependency Type | Count | Percentage | Description |
|----------------|-------|------------|-------------|
| 🌐 Environment-Specific | 12 | 17.1% | Requires site-specific/organizational values |
| 🖥️ System-Specific | 6 | 8.6% | Depends on deployment/installation config |
| ✓ Standard | 52 | 74.3% | No special dependencies |

### Severity Distribution

| Severity | Count | Percentage |
|----------|-------|------------|
| 🔴 HIGH | 8 | 11.4% |
| 🟡 MEDIUM | 45 | 64.3% |
| 🟢 LOW | 17 | 24.3% |
| **TOTAL** | **70** | **100.0%** |

### Tool Preference (Priority: Bash > PowerShell > Python > Third-Party)

| Tool Type | Count | Notes |
|-----------|-------|-------|
| Bash (Native) | 68 | Primary method - no dependencies |
| Python (Native) | 0 | Fallback - uses stdlib only |
| Third-Party Optional | 0 | All checks use native commands |
| **Minimal Third-Party** | **68** | **97.1% can run without third-party tools** |

## Summary
- **Automatable Checks:** 51 (72.9%)
- **Partially Automatable:** 17 (24.3%)
- **Manual Review Required:** 2 (2.9%)
- **Needs Analysis:** 0 (0.0%)

### Environment/System Specific Checks
- **Environment-Specific:** 12 (17.1%)
  - *These checks require site-specific, organizational, or approved values*
- **System-Specific:** 6 (8.6%)
  - *These checks depend on deployment or installation-specific configurations*

### Severity Distribution
- **High:** 8
- **Medium:** 45
- **Low:** 17

---

## Detailed Check Analysis

### Automatable (51 checks)

#### V-207532 - BIND-9X-000001
**Severity:** LOW

**Rule Title:** A BIND 9.x server implementation must be running in a chroot(ed) directory structure.

**Automation Status:** Automatable

**Automation Method:** Bash (native commands)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**Notes:**
- Command-line verification possible

**Check Content:**
```
Verify the directory structure where the primary BIND 9.x Server configuration files are stored is running in a chroot(ed) environment:

# ps -ef | grep named

named 3015 1 0 12:59 ? 00:00:00 /usr/sbin/named -u named -t /var/named/chroot

If the output does not contain "-t <chroot_path>", this is a finding.
```
**NIST SP 800-53 Rev 4:** SC-4
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-207535 - BIND-9X-001003
**Severity:** MEDIUM

**Rule Title:** The BIND 9.x server software must run with restricted privileges.

**Automation Status:** Automatable

**Automation Method:** Bash (native commands)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**Notes:**
- Command-line verification possible

**Check Content:**
```
Verify the BIND 9.x process is not running as root:

# ps -ef | grep named

named 3015 1 0 12:59 ? 00:00:00 /usr/sbin/named -u named -t /var/named/chroot

If the output shows "/usr/sbin/named -u root", this is a finding.
```
**NIST SP 800-53 Rev 4:** CM-6 b
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-207539 - BIND-9X-001010
**Severity:** LOW

**Rule Title:** A BIND 9.x server implementation must be configured to allow DNS administrators to audit all DNS server components, based on selectable event criteria, and produce audit records within all DNS server components that contain information for failed security verification tests, information to establish the outcome and source of the events, any information necessary to determine cause of failure, and any information necessary to return to operations with least disruption to mission processes.

**Automation Status:** Automatable

**Automation Method:** Bash (grep/awk for named.conf parsing)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**Notes:**
- BIND configuration file parsing (named.conf)

**Check Content:**
```
Verify the name server is configured to generate audit records:

Inspect the "named.conf" file for the following:

logging {
channel channel_name {
severity info;
};
category default { channel_name; };
};

If there is no "logging" statement, this is a finding.

If the "logging" statement does not contain a "channel", this is a finding.

If the "logging" statement does not contain a "category" that utilizes a "channel", this is a finding.
```
**NIST SP 800-53 Rev 4:** AU-3
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-207540 - BIND-9X-001017
**Severity:** LOW

**Rule Title:** The BIND 9.x server implementation must not be configured with a channel to send audit records to null.

**Automation Status:** Automatable

**Automation Method:** Bash (grep/awk for named.conf parsing)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**Notes:**
- BIND configuration file parsing (named.conf)

**Check Content:**
```
Verify that the BIND 9.x server is not configured to send audit logs to the null channel.

Inspect the "named.conf" file for the following:

category null { null; }

If there is a category defined to send audit logs to the "null" channel, this is a finding.
```
**NIST SP 800-53 Rev 4:** AU-9 (2)
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-207541 - BIND-9X-001020
**Severity:** LOW

**Rule Title:** The BIND 9.x server logging configuration must be configured to generate audit records for all DoD-defined auditable events to a local file by enabling triggers for all events with a severity of info, notice, warning, error, and critical for all DNS components.

**Automation Status:** Automatable

**Automation Method:** Bash (grep/awk for named.conf parsing)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**🔧 Configuration Dependencies:**
- ⚠️ **SYSTEM-SPECIFIC**: This check depends on deployment/installation-specific configuration

**Notes:**
- BIND configuration file parsing (named.conf)

**Check Content:**
```
Verify the name server is configured to generate all DoD-defined audit records._x000D_
_x000D_
Inspect the "named.conf" file for the following:_x000D_
_x000D_
logging {_x000D_
channel channel_name {_x000D_
severity info;_x000D_
};_x000D_
};_x000D_
_x000D_
If a channel is not configured to log messages with the severity of info and higher, this is a finding._x000D_
_x000D_
Note: "info" is the lowest severity level and will automatically log all messages with a severity of "info" or higher.
```
**NIST SP 800-53 Rev 4:** AU-12 a
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-207542 - BIND-9X-001021
**Severity:** LOW

**Rule Title:** In the event of an error when validating the binding of other DNS servers identity to the BIND 9.x information, when anomalies in the operation of the signed zone transfers are discovered, for the success and failure of start and stop of the name server service or daemon, and for the success and failure of all name server events, a BIND 9.x server implementation must generate a log entry.

**Automation Status:** Automatable

**Automation Method:** Bash (grep/awk for named.conf parsing)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**Notes:**
- BIND configuration file parsing (named.conf)

**Check Content:**
```
Verify the name server is configured to log error messages with a severity of â€œinfoâ€:

Inspect the "named.conf" file for the following:

logging {
channel channel_name {
severity info;
};

If the "severity" sub statement is not set to "info", this is a finding.

Note: Setting the "severity" sub statement to "info" will log all messages for the following severity levels: Critical, Error, Warning, Notice, and Info.
```
**NIST SP 800-53 Rev 4:** AU-12 c
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-207543 - BIND-9X-001030
**Severity:** LOW

**Rule Title:** The print-severity variable for the configuration of BIND 9.x server logs must be configured to produce audit records containing information to establish what type of events occurred.

**Automation Status:** Automatable

**Automation Method:** Bash (grep/awk for named.conf parsing)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**Notes:**
- BIND configuration file parsing (named.conf)

**Check Content:**
```
For each logging channel that is defined, verify that the "print-severity" sub statement is listed:

Inspect the "named.conf" file for the following:

logging {
channel channel_name {
print-severity yes;
};
};

If the "print-severity" statement is missing, this is a finding.

If the "print-severity" statement is not set to "yes", this is a finding.
```
**NIST SP 800-53 Rev 4:** AU-3
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-207544 - BIND-9X-001031
**Severity:** LOW

**Rule Title:** The print-time variable for the configuration of BIND 9.x server logs must be configured to establish when (date and time) the events occurred.

**Automation Status:** Automatable

**Automation Method:** Bash (grep/awk for named.conf parsing)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**Notes:**
- BIND configuration file parsing (named.conf)

**Check Content:**
```
For each logging channel that is defined, verify that the "print-time" sub statement is listed.

Inspect the "named.conf" file for the following:

logging {
channel channel_name {
print-time yes;
};
};

If the "print-time" statement is missing, this is a finding.

If the "print-time" statement is not set to "yes", this is a finding.
```
**NIST SP 800-53 Rev 4:** AU-3
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-207545 - BIND-9X-001032
**Severity:** LOW

**Rule Title:** The print-category variable for the configuration of BIND 9.x server logs must be configured to record information indicating which process generated the events.

**Automation Status:** Automatable

**Automation Method:** Bash (grep/awk for named.conf parsing)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**Notes:**
- BIND configuration file parsing (named.conf)

**Check Content:**
```
For each logging channel that is defined, verify that the "print-category" sub statement is listed.

Inspect the "named.conf" file for the following:

logging {
channel channel_name {
print-category yes;
};
};

If the "print-category" statement is missing, this is a finding.

If the "print-category" statement is not set to "yes", this is a finding.
```
**NIST SP 800-53 Rev 4:** AU-3
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-207546 - BIND-9X-001040
**Severity:** LOW

**Rule Title:** The BIND 9.x server implementation must be configured with a channel to send audit records to a remote syslog.

**Automation Status:** Automatable

**Automation Method:** Bash (grep/awk for named.conf parsing)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**🔧 Configuration Dependencies:**
- ⚠️ **SYSTEM-SPECIFIC**: This check depends on deployment/installation-specific configuration

**Notes:**
- BIND configuration file parsing (named.conf)

**Check Content:**
```
Verify that the BIND 9.x server is configured to send audit logs to the syslog service._x000D_
_x000D_
NOTE: syslog and local file channel must be defined for every defined category._x000D_
_x000D_
Inspect the "named.conf" file for the following:_x000D_
_x000D_
logging {_x000D_
channel <syslog_channel> {_x000D_
syslog <syslog_facility>;_x000D_
};_x000D_
_x000D_
category <category_name> { <syslog_channel>; };_x000D_
_x000D_
If a logging channel is not defined for syslog, this is a finding._x000D_...
```
**NIST SP 800-53 Rev 4:** AU-9 (2)
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-207547 - BIND-9X-001041
**Severity:** LOW

**Rule Title:** The BIND 9.x server implementation must be configured with a channel to send audit records to a local file.

**Automation Status:** Automatable

**Automation Method:** Bash (grep/awk for named.conf parsing)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**🔧 Configuration Dependencies:**
- ⚠️ **SYSTEM-SPECIFIC**: This check depends on deployment/installation-specific configuration

**Notes:**
- BIND configuration file parsing (named.conf)

**Check Content:**
```
Verify that the BIND 9.x server is configured to send audit logs to a local log file._x000D_
_x000D_
NOTE: syslog and local file channel must be defined for every defined category._x000D_
_x000D_
Inspect the "named.conf" file for the following:_x000D_
_x000D_
logging {_x000D_
channel local_file_channel {_x000D_
file "path_name" versions 3;_x000D_
print-time yes;_x000D_
print-severity yes;_x000D_
print-category yes;_x000D_
};_x000D_
_x000D_
category category_name { local_file_channel; };_x000D_
_...
```
**NIST SP 800-53 Rev 4:** AU-9 (2)
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-207548 - BIND-9X-001042
**Severity:** LOW

**Rule Title:** The BIND 9.x server implementation must maintain at least 3 file versions of the local log file.

**Automation Status:** Automatable

**Automation Method:** Bash (grep/awk for named.conf parsing)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**🔧 Configuration Dependencies:**
- ⚠️ **SYSTEM-SPECIFIC**: This check depends on deployment/installation-specific configuration

**Notes:**
- BIND configuration file parsing (named.conf)

**Check Content:**
```
Verify that the BIND 9.x server is configured to retain at least 3 versions of the local log file.

Inspect the "named.conf" file for the following:

logging {
channel local_file_channel {
file "path_name" versions 3;
};

If the "versions" variable is not defined, this is a finding.

If the "versions" variable is configured to retain less than 3 versions of the local log file, this is a finding.
```
**NIST SP 800-53 Rev 4:** AU-9 (2)
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-207549 - BIND-9X-001050
**Severity:** MEDIUM

**Rule Title:** The BIND 9.x secondary name server must limit the number of zones requested from a single master name server.

**Automation Status:** Automatable

**Automation Method:** Bash (grep/awk for named.conf parsing)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**Notes:**
- BIND configuration file parsing (named.conf)

**Check Content:**
```
If this is not a secondary name server, this requirement is Not Applicable.

Verify that the secondary name server is configured to limit the number of zones requested from a single master name server.

Inspect the "named.conf" file for the following:

options {
transfers-per-ns 2;
};

If the "options" statement does not contain a "transfers-per-ns" sub statement, this is a finding.
```
**NIST SP 800-53 Rev 4:** AC-10
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-207550 - BIND-9X-001051
**Severity:** MEDIUM

**Rule Title:** The BIND 9.x secondary name server must limit the total number of zones the name server can request at any one time.

**Automation Status:** Automatable

**Automation Method:** Bash (grep/awk for named.conf parsing)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**Notes:**
- BIND configuration file parsing (named.conf)

**Check Content:**
```
If this is not a secondary name server, this requirement is Not Applicable.

Verify the name server is configured to limit the total number of zones that can be requested at one time:

Inspect the "named.conf" file for the following:

options {
transfers-in 10;
};

If the "options" statement does not contain a "transfers-in" sub statement, this is a finding.
```
**NIST SP 800-53 Rev 4:** AC-10
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-207551 - BIND-9X-001052
**Severity:** MEDIUM

**Rule Title:** The BIND 9.x server implementation must limit the number of concurrent session client connections to the number of allowed dynamic update clients.

**Automation Status:** Automatable

**Automation Method:** Bash (grep/awk for named.conf parsing)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**Notes:**
- BIND configuration file parsing (named.conf)

**Check Content:**
```
Verify the name server is configured to limit the number of concurrent client connections to the number of allowed dynamic update clients:

Inspect the "named.conf" file for the following:

options {
transfers-out 10;
};

If the "options" statement does not contain a "transfers-out" sub statement, this is a finding.
```
**NIST SP 800-53 Rev 4:** AC-10
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-207557 - BIND-9X-001059
**Severity:** LOW

**Rule Title:** On the BIND 9.x server the platform on which the name server software is hosted must be configured to send outgoing DNS messages from a random port.

**Automation Status:** Automatable

**Automation Method:** Bash (grep/awk for named.conf parsing)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**Notes:**
- BIND configuration file parsing (named.conf)

**Check Content:**
```
Verify that the BIND 9.x server does not limit outgoing DNS messages to a specific port.

Inspect the "named.conf" file for the any instance of the "port" flag:

options {
listen-on port 53 { <ip_address>; };
listen-on-v6 port 53 { <ip_v6_address>; };
};

If any "port" flag is found outside of the "listen-on" or "listen-on-v6" statements, this is a finding.
```
**NIST SP 800-53 Rev 4:** CM-6 b
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-207558 - BIND-9X-001060
**Severity:** MEDIUM

**Rule Title:** A BIND 9.x caching name server must implement DNSSEC validation to check all DNS queries for invalid input.

**Automation Status:** Automatable

**Automation Method:** Bash (grep/awk for named.conf parsing)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**Notes:**
- BIND configuration file parsing (named.conf)

**Check Content:**
```
If the server is not a caching name server, this is Not Applicable.

If the server is in a classified network, this is Not Applicable.

If the caching name server is only forwarding to the DISA ERS for query resolution and is not authoritative for any zones, DNSSEC awareness is not required since the ERS is validating.
Verify the server is configured to use DNSSEC validation for all DNS queries.

Inspect the "named.conf" file for the following:

options {
dnssec-validation yes;
dnssec-enable yes...
```
**NIST SP 800-53 Rev 4:** SI-10 (3)
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-207560 - BIND-9X-001080
**Severity:** MEDIUM

**Rule Title:** A BIND 9.x implementation configured as a caching name server must restrict recursive queries to only the IP addresses and IP address ranges of known supported clients.

**Automation Status:** Automatable

**Automation Method:** Bash (grep/awk for named.conf parsing)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**Notes:**
- BIND configuration file parsing (named.conf)

**Check Content:**
```
This check is only applicable to caching name servers.

Verify the allow-query and allow-recursion phrases are properly configured.

Inspect the "named.conf" file for the following:

allow-query {trustworthy_hosts;};
allow-recursion {trustworthy_hosts;};

The name of the ACL does not need to be "trustworthy_hosts" but the name should match the ACL name defined earlier in "named.conf" for this purpose. If not, this is a finding.

Verify non-internal IP addresses do not appear in either the refere...
```
**NIST SP 800-53 Rev 4:** SC-5 (1)
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-207561 - BIND-9X-001100
**Severity:** HIGH

**Rule Title:** The BIND 9.x server implementation must uniquely identify and authenticate the other DNS server before responding to a server-to-server transaction, zone transfer and/or dynamic update request using cryptographically based bidirectional authentication to protect the integrity of the information in transit.

**Automation Status:** Automatable

**Automation Method:** Bash (grep/awk for named.conf parsing)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**Notes:**
- BIND configuration file parsing (named.conf)

**Check Content:**
```
If zone transfers are disabled with the "allow-transfer { none; };" directive, this is Not Applicable.
If the server is in a classified network, this is Not Applicable.

Verify that the BIND 9.x server is configured to uniquely identify a name server before responding to a zone transfer.

Inspect the "named.conf" file for the presence of TSIG key statements:

On the master name server, this is an example of a configured key statement:

key tsig_example. {
algorithm hmac-SHA1;
include "tsig-examp...
```
**NIST SP 800-53 Rev 4:** IA-3
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-207562 - BIND-9X-001106
**Severity:** MEDIUM

**Rule Title:** The BIND 9.x server implementation must utilize separate TSIG key-pairs when securing server-to-server transactions.

**Automation Status:** Automatable

**Automation Method:** Bash (grep/awk for named.conf parsing)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**Notes:**
- BIND configuration file parsing (named.conf)

**Check Content:**
```
Verify that the BIND 9.x server is configured to utilize separate TSIG key-pairs when securing server-to-server transactions.
Inspect the "named.conf" file for the presence of TSIG key statements:

On the master name server, this is an example of a configured key statement:

key tsig_example. {
algorithm hmac-SHA1;
include "tsig-example.key";
};

zone "disa.mil" {
type master;
file "db.disa.mil";
allow-transfer { key tsig_example.; };
};

On the slave name server, this is an example of a configu...
```
**NIST SP 800-53 Rev 4:** IA-3
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-207563 - BIND-9X-001110
**Severity:** MEDIUM

**Rule Title:** The TSIG keys used with the BIND 9.x implementation must be owned by a privileged account.

**Automation Status:** Automatable

**Automation Method:** Bash (native commands)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**Notes:**
- Command-line verification possible

**Check Content:**
```
With the assistance of the DNS Administrator, identify all of the TSIG keys used by the BIND 9.x implementation.

Identify the account that the "named" process is running as:

# ps -ef | grep named
named 3015 1 0 12:59 ? 00:00:00 /usr/sbin/named -u named -t /var/named/chroot

With the assistance of the DNS Administrator, determine the location of the TSIG keys used by the BIND 9.x implementation.

# ls â€“al <TSIG_Key_Location>
-rw-------. 1 named named 76 May 10 20:35 tsig-example.key

If any o...
```
**NIST SP 800-53 Rev 4:** IA-5 (2) (b)
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-207564 - BIND-9X-001111
**Severity:** MEDIUM

**Rule Title:** The TSIG keys used with the BIND 9.x implementation must be group owned by a privileged account.

**Automation Status:** Automatable

**Automation Method:** Bash (native commands)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**Notes:**
- Command-line verification possible

**Check Content:**
```
With the assistance of the DNS Administrator, identify all of the TSIG keys used by the BIND 9.x implementation.

Identify the account that the "named" process is running as:

# ps -ef | grep named
named 3015 1 0 12:59 ? 00:00:00 /usr/sbin/named -u named -t /var/named/chroot

With the assistance of the DNS Administrator, determine the location of the TSIG keys used by the BIND 9.x implementation.

# ls â€“al <TSIG_Key_Location>
-rw-------. 1 named named 76 May 10 20:35 tsig-example.key

If any o...
```
**NIST SP 800-53 Rev 4:** IA-5 (2) (b)
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-207565 - BIND-9X-001112
**Severity:** MEDIUM

**Rule Title:** The read and write access to a TSIG key file used by a BIND 9.x server must be restricted to only the account that runs the name server software.

**Automation Status:** Automatable

**Automation Method:** Bash (ls -l, stat commands)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**Notes:**
- File permission verification

**Check Content:**
```
Verify permissions assigned to the TSIG keys enforce read-write access to the key owner and deny access to group or system users:

With the assistance of the DNS Administrator, determine the location of the TSIG keys used by the BIND 9.x implementation:

# ls â€“al <TSIG_Key_Location>
-rw-------. 1 named named 76 May 10 20:35 tsig-example.key

If the key files are more permissive than 600, this is a finding.
```
**NIST SP 800-53 Rev 4:** IA-5 (2) (b)
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-207566 - BIND-9X-001113
**Severity:** MEDIUM

**Rule Title:** The BIND 9.X implementation must not utilize a TSIG or DNSSEC key for more than one year.

**Automation Status:** Automatable

**Automation Method:** Bash (native commands)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**Notes:**
- Command-line verification possible

**Check Content:**
```
With the assistance of the DNS Administrator, identify all of the cryptographic key files used by the BIND 9.x implementation.

With the assistance of the DNS Administrator, determine the location of the cryptographic key files used by the BIND 9.x implementation.

# ls â€“al <Crypto_Key_Location>
-rw-------. 1 named named 76 May 10 20:35 crypto-example.key

If the server is in a classified network, the DNSSEC portion of the requirement is Not Applicable.

For DNSSEC Keys:
Verify that the â€œCre...
```
**NIST SP 800-53 Rev 4:** CM-6 b
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-207568 - BIND-9X-001130
**Severity:** MEDIUM

**Rule Title:** The DNSSEC keys used with the BIND 9.x implementation must be owned by a privileged account.

**Automation Status:** Automatable

**Automation Method:** Bash (native commands)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**Notes:**
- Command-line verification possible

**Check Content:**
```
If the server is in a classified network, this is Not Applicable.

With the assistance of the DNS Administrator, identify all of the DNSSEC keys used by the BIND 9.x implementation.

Identify the account that the "named" process is running as:

# ps -ef | grep named
named 3015 1 0 12:59 ? 00:00:00 /usr/sbin/named -u named -t /var/named/chroot

With the assistance of the DNS Administrator, determine the location of the DNSSEC keys used by the BIND 9.x implementation.

# ls â€“al <DNSSEC_Key_Locat...
```
**NIST SP 800-53 Rev 4:** SC-28
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-207569 - BIND-9X-001131
**Severity:** MEDIUM

**Rule Title:** The DNSSEC keys used with the BIND 9.x implementation must be group owned by a privileged account.

**Automation Status:** Automatable

**Automation Method:** Bash (native commands)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**Notes:**
- Command-line verification possible

**Check Content:**
```
If the server is in a classified network, this is Not Applicable.

With the assistance of the DNS Administrator, identify all of the DNSSEC keys used by the BIND 9.x implementation.

Identify the account that the "named" process is running as:

# ps -ef | grep named
named 3015 1 0 12:59 ? 00:00:00 /usr/sbin/named -u named -t /var/named/chroot

With the assistance of the DNS Administrator, determine the location of the DNSSEC keys used by the BIND 9.x implementation.

# ls â€“al <DNSSEC_Key_Locat...
```
**NIST SP 800-53 Rev 4:** SC-28
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-207570 - BIND-9X-001132
**Severity:** MEDIUM

**Rule Title:** Permissions assigned to the DNSSEC keys used with the BIND 9.x implementation must enforce read-only access to the key owner and deny access to all other users.

**Automation Status:** Automatable

**Automation Method:** Bash (ls -l, stat commands)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**Notes:**
- File permission verification

**Check Content:**
```
If the server is in a classified network, this is Not Applicable.

Verify permissions assigned to the DNSSEC keys enforce read-only access to the key owner and deny access to group or system users:

With the assistance of the DNS Administrator, determine the location of the DNSSEC keys used by the BIND 9.x implementation:

# ls â€“al <DNSSEC_Key_Location>
-r--------. 1 named named 76 May 10 20:35 DNSSEC-example.key

If the key files are more permissive than 400, this is a finding.
```
**NIST SP 800-53 Rev 4:** SC-28
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-207571 - BIND-9X-001133
**Severity:** HIGH

**Rule Title:** The BIND 9.x server private key corresponding to the ZSK pair must be the only DNSSEC key kept on a name server that supports dynamic updates.

**Automation Status:** Automatable

**Automation Method:** Bash (grep/awk for named.conf parsing)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**Notes:**
- BIND configuration file parsing (named.conf)

**Check Content:**
```
If the server is in a classified network, this is Not Applicable.

Determine if the BIND 9.x server is configured to allow dynamic updates.

Review the "named.conf" file for any instance of the "allow-update" statement. The following example disables dynamic updates:

allow-update {none;};

If the BIND 9.x implementation is not configured to allow dynamic updates, verify with the SA that the ZSK private key is stored offline. If it is not, this is a finding.

If the BIND 9.x implementation is co...
```
**NIST SP 800-53 Rev 4:** IA-5 (2) (b)
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-207572 - BIND-9X-001134
**Severity:** MEDIUM

**Rule Title:** On the BIND 9.x server the private keys corresponding to both the ZSK and the KSK must not be kept on the BIND 9.x DNSSEC-aware primary authoritative name server when the name server does not support dynamic updates.

**Automation Status:** Automatable

**Automation Method:** Bash (grep/awk for named.conf parsing)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**Notes:**
- BIND configuration file parsing (named.conf)

**Check Content:**
```
If the server is in a classified network, this is Not Applicable.

Determine if the BIND 9.x server is configured to allow dynamic updates.

Review the "named.conf" file for any instance of the "allow-update" statement. The following example disables dynamic updates:

allow-update {none;};

If the BIND 9.x implementation is not configured to allow dynamic updates, verify with the SA that the private ZSKs and private KSKs are stored offline, if not, this is a finding.
```
**NIST SP 800-53 Rev 4:** CM-6 b
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-207573 - BIND-9X-001140
**Severity:** MEDIUM

**Rule Title:** The two files generated by the BIND 9.x server dnssec-keygen program must be owned by the root account, or deleted, after they have been copied to the key file in the name server.

**Automation Status:** Automatable

**Automation Method:** Bash (native commands)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**Notes:**
- Command-line verification possible

**Check Content:**
```
If the server is in a classified network, this is Not Applicable.

With the assistance of the DNS Administrator, identify all dnssec-keygen key files that reside on the BIND 9.x server.

An example dnssec-keygen key file will look like:

Kns1.example.com_ns2.example.com.+161+28823.key
OR
Kns1.example.com_ns2.example.com.+161+28823.private

For each key file identified, verify that the key file is owned by "root":

# ls -al
-r-------- 1 root root 77 Jul 1 15:00 Kns1.example.com_ns2.example.com+16...
```
**NIST SP 800-53 Rev 4:** CM-6 b
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-207574 - BIND-9X-001141
**Severity:** MEDIUM

**Rule Title:** The two files generated by the BIND 9.x server dnssec-keygen program must be group owned by the server administrator account, or deleted, after they have been copied to the key file in the name server.

**Automation Status:** Automatable

**Automation Method:** Bash (native commands)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**Notes:**
- Command-line verification possible

**Check Content:**
```
If the server is in a classified network, this is Not Applicable.

With the assistance of the DNS Administrator, identify all dnssec-keygen key files that reside on the BIND 9.x server.

An example dnssec-keygen key file will look like:

Kns1.example.com_ns2.example.com.+161+28823.key
OR
Kns1.example.com_ns2.example.com.+161+28823.private

For each key file identified, verify that the key file is group-owned by "root":

# ls â€“la
-r-------- 1 root root 77 Jul 1 15:00 Kns1.example.com_ns2.exampl...
```
**NIST SP 800-53 Rev 4:** CM-6 b
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-207575 - BIND-9X-001142
**Severity:** MEDIUM

**Rule Title:** Permissions assigned to the dnssec-keygen keys used with the BIND 9.x implementation must enforce read-only access to the key owner and deny access to all other users.

**Automation Status:** Automatable

**Automation Method:** Bash (ls -l, stat commands)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**Notes:**
- File permission verification

**Check Content:**
```
If the server is in a classified network, this is Not Applicable.

With the assistance of the DNS Administrator, identify all dnssec-keygen key files that reside on the BIND 9.x server.

An example dnssec-keygen key file will look like:

Kns1.example.com_ns2.example.com.+161+28823.key
OR
Kns1.example.com_ns2.example.com.+161+28823.private

For each key file identified, verify that the key file is owned by "root":

# ls -al
-r-------- 1 root root 77 Jul 1 15:00 Kns1.example.com_ns2.example.com+16...
```
**NIST SP 800-53 Rev 4:** CM-6 b
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-207576 - BIND-9X-001150
**Severity:** HIGH

**Rule Title:** The BIND 9.x server signature generation using the KSK must be done off-line, using the KSK-private key stored off-line.

**Automation Status:** Automatable

**Automation Method:** Bash (file/directory checks)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**Check Content:**
```
If the server is in a classified network, this is Not Applicable.

Ensure that there are no private KSKs stored on the name sever. 

With the assistance of the DNS Administrator, obtain a list of all DNSSEC private keys that are stored on the name server. 

Inspect the signed zone files(s) and look for the KSK key id:

DNSKEY 257 3 8 ( <hash_algorithm) ; KSK ; alg = ECDSAP256SHA256; key id = 52807

Verify that none of the identified private keys, are KSKs.

An example private KSK would look like...
```
**NIST SP 800-53 Rev 4:** IA-5 (2) (b)
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-207577 - BIND-9X-001200
**Severity:** HIGH

**Rule Title:** A BIND 9.x server implementation must maintain the integrity and confidentiality of DNS information while it is being prepared for transmission, in transmission, and in use and t must perform integrity verification and data origin verification for all DNS information.

**Automation Status:** Automatable

**Automation Method:** Bash (grep/awk for named.conf parsing)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**Notes:**
- BIND configuration file parsing (named.conf)

**Check Content:**
```
If the server is in a classified network, this is Not Applicable.
If the server is forwarding all queries to the ERS, this is Not Applicable as the ERS validates.

Verify that DNSSEC is enabled.

Inspect the "named.conf" file for the following:

dnssec-enable yes;

If "dnssec-enable" does not exist or is not set to "yes", this is a finding.

Verify that each zone on the name server has been signed.

Identify each zone file that the name sever is responsible for and search each file for the "DNSK...
```
**NIST SP 800-53 Rev 4:** SC-20 a
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-207578 - BIND-9X-001310
**Severity:** MEDIUM

**Rule Title:** A BIND 9.x server implementation must provide the means to indicate the security status of child zones.

**Automation Status:** Automatable

**Automation Method:** Bash (grep/awk for named.conf parsing)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**Notes:**
- BIND configuration file parsing (named.conf)

**Check Content:**
```
If the server is in a classified network, this is Not Applicable.

Verify that there is a DS record set for each child zone defined in "/etc/named.conf" file.

For each child zone listed in "/etc/named.conf" file, verify there is a corresponding "dsset-zone_name" file.

If any child zone does not have a corresponding DS record set, this is a finding.
```
**NIST SP 800-53 Rev 4:** SC-20 b
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-207580 - BIND-9X-001320
**Severity:** MEDIUM

**Rule Title:** The core BIND 9.x server files must be owned by the root or BIND 9.x process account.

**Automation Status:** Automatable

**Automation Method:** Bash (grep/awk for named.conf parsing)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**Notes:**
- BIND configuration file parsing (named.conf)

**Check Content:**
```
Verify that the core BIND 9.x server files are owned by the root or BIND 9.x process account.

With the assistance of the DNS administrator, identify the following files:

named.conf
root hints 
master zone file(s)
slave zone files(s)

Note: The name of the root hints file is defined in named.conf. Common names for the file are root.hints, named.cache, or db.cache.

If the identified files are not owned by the root or BIND 9.x process account, this is a finding.
```
**NIST SP 800-53 Rev 4:** CM-6 b
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-207581 - BIND-9X-001321
**Severity:** MEDIUM

**Rule Title:** The core BIND 9.x server files must be group owned by a group designated for DNS administration only.

**Automation Status:** Automatable

**Automation Method:** Bash (grep/awk for named.conf parsing)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**Notes:**
- BIND configuration file parsing (named.conf)

**Check Content:**
```
Verify that the core BIND 9.x server files are group owned by a group designated for DNS administration only.

With the assistance of the DNS administrator, identify the following files:

named.conf
root hints 
master zone file(s)
slave zone file(s)

Note: The name of the root hints file is defined in named.conf. Common names for the file are root.hints, named.cache, or db.cache.

If the identified files are not group owned by a group designated for DNS administration, this is a finding.
```
**NIST SP 800-53 Rev 4:** CM-6 b
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-207582 - BIND-9X-001322
**Severity:** MEDIUM

**Rule Title:** The permissions assigned to the core BIND 9.x server files must be set to utilize the least privilege possible.

**Automation Status:** Automatable

**Automation Method:** Bash (grep/awk for named.conf parsing)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**Notes:**
- BIND configuration file parsing (named.conf)

**Check Content:**
```
With the assistance of the DNS administrator, identify the following files:

named.conf : rw-r----- 
root hints : rw-r-----
master zone file(s): rw-r-----
slave zone file(s): rw-rw----

Note: The name of the root hints file is defined in named.conf. Common names for the file are root.hints, named.cache, or db.cache.

Verify that the permissions for the core BIND 9.x server files are at least as restrictive as listed above. 

If the identified files are not as least as restrictive as listed above...
```
**NIST SP 800-53 Rev 4:** CM-6 b
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-207583 - BIND-9X-001400
**Severity:** MEDIUM

**Rule Title:** On a BIND 9.x server for zones split between the external and internal sides of a network, the RRs for the external hosts must be separate from the RRs for the internal hosts.

**Automation Status:** Automatable

**Automation Method:** Bash (grep/awk for named.conf parsing)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**Notes:**
- BIND configuration file parsing (named.conf)

**Check Content:**
```
If the BIND 9.x name server is not configured for split DNS, this is Not Applicable.

Verify that the BIND 9.x server is configured to use separate views and address space for internal and external DNS operations when operating in a split configuration.

Inspect the "named.conf" file for the following:

view "internal" {
match-clients { <ip_address> | <address_match_list> };
zone "example.com" {
type master;
file "internals.example.com";
};
};
view "external" {
match-clients { <ip_address> | <ad...
```
**NIST SP 800-53 Rev 4:** CM-6 b
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-207584 - BIND-9X-001401
**Severity:** MEDIUM

**Rule Title:** On a BIND 9.x server in a split DNS configuration, where separate name servers are used between the external and internal networks, the external name server must be configured to not be reachable from inside resolvers.

**Automation Status:** Automatable

**Automation Method:** Bash (grep/awk for named.conf parsing)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**Notes:**
- BIND configuration file parsing (named.conf)

**Check Content:**
```
If the BIND 9.x name server is not configured for split DNS, this is Not Applicable.

Verify that the external view of the BIND 9.x server is configured to only serve external hosts.

Inspect the "named.conf" file for the following:

view "external" {
match-clients { <ip_address> | <address_match_list>; };
};

If the "match-clients" sub statement does not limit the external view to external hosts only, this is a finding.
```
**NIST SP 800-53 Rev 4:** CM-6 b
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-207586 - BIND-9X-001403
**Severity:** HIGH

**Rule Title:** A BIND 9.x server implementation must implement internal/external role separation.

**Automation Status:** Automatable

**Automation Method:** Bash (grep/awk for named.conf parsing)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**Notes:**
- BIND configuration file parsing (named.conf)

**Check Content:**
```
Severity Override Guidance:
If the internal and external views are on separate network segments, this finding may be downgraded to a CAT II.

If the BIND 9.x name server is not configured for split DNS, this is Not Applicable.

Verify that the BIND 9.x server is configured to use separate views and address space for internal and external DNS operations when operating in a split configuration.

Inspect the "named.conf" file for the following:

view "internal" {
match-clients { <ip_address> | <add...
```
**NIST SP 800-53 Rev 4:** CM-6 b
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-207587 - BIND-9X-001404
**Severity:** MEDIUM

**Rule Title:** On the BIND 9.x server the IP address for hidden master authoritative name servers must not appear in the name servers set in the zone database.

**Automation Status:** Automatable

**Automation Method:** Bash (file/directory checks)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**Check Content:**
```
If the BIND 9.x name server is not configured for split DNS, this is Not Applicable.

With the assistance of the DNS administrator, identify if the BIND 9.x implementation is using a hidden master name server, if it is not, this is Not Applicable.

In a split DNS configuration that is using a hidden master name server, verify that the name server IP address is not listed in the zone file.

With the assistance of the DNS administrator, obtain the IP address of the hidden master name server.

Insp...
```
**NIST SP 800-53 Rev 4:** CM-6 b
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-207589 - BIND-9X-001410
**Severity:** MEDIUM

**Rule Title:** On the BIND 9.x server the private key corresponding to the ZSK, stored on name servers accepting dynamic updates, must be owned by root.

**Automation Status:** Automatable

**Automation Method:** Bash (ls -l, stat commands)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**Notes:**
- File permission verification

**Check Content:**
```
If the server is in a classified network, this is Not Applicable.
Note: This check only verifies for ZSK key file ownership. Permissions for key files are required under V-72451, BIND-9X-001132 and V-72461, BIND-9X-001142.

For each signed zone file, identify the ZSK "key id" number:

# cat <signed_zone_file> | grep -i "zsk"
ZSK; alg = ECDSAP256SHA256; key id = 22335

Using the ZSK "key id", identify the private ZSK.

Kexample.com.+008+22335.private

Verify that the private ZSK is owned by root:...
```
**NIST SP 800-53 Rev 4:** CM-6 b
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-207590 - BIND-9X-001411
**Severity:** MEDIUM

**Rule Title:** On the BIND 9.x server the private key corresponding to the ZSK, stored on name servers accepting dynamic updates, must be group owned by root.

**Automation Status:** Automatable

**Automation Method:** Bash (ls -l, stat commands)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**Notes:**
- File permission verification

**Check Content:**
```
If the server is in a classified network, this is Not Applicable.
Note: This check only verifies for ZSK key file ownership. Permissions for key files are required under V-72451, BIND-9X-001132 and V-72461, BIND-9X-001142.

For each signed zone file, identify the ZSK "key id" number:

# cat <signed_zone_file> | grep -i "zsk"
ZSK; alg = ECDSAP256SHA256; key id = 22335

Using the ZSK "key id", verify the private ZSK.

Kexample.com.+008+22335.private

Verify that the private ZSK is owned by root:

...
```
**NIST SP 800-53 Rev 4:** CM-6 b
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-207593 - BIND-9X-001610
**Severity:** MEDIUM

**Rule Title:** A BIND 9.x server NSEC3 must be used for all internal DNS zones.

**Automation Status:** Automatable

**Automation Method:** Bash (grep/awk for named.conf parsing)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**Notes:**
- BIND configuration file parsing (named.conf)

**Check Content:**
```
If the server is in a classified network, this is Not Applicable. If the server is on an internal, restricted network with reserved IP space, this is Not Applicable.


With the assistance of the DNS Administrator, identify each internal DNS zone listed in the "named.conf" file.

For each internal zone identified, inspect the signed zone file for the NSEC resource records:

86400 NSEC example.com. A RRSIG NSEC

If the zone file does not contain an NSEC record for the zone, this is a finding.

```
**NIST SP 800-53 Rev 4:** CM-6 b
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-207594 - BIND-9X-001611
**Severity:** MEDIUM

**Rule Title:** Every NS record in a zone file on a BIND 9.x server must point to an active name server and that name server must be authoritative for the domain specified in that record.

**Automation Status:** Automatable

**Automation Method:** Bash (grep/awk for named.conf parsing)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**Notes:**
- BIND configuration file parsing (named.conf)

**Check Content:**
```
Verify that each name server listed on the BIND 9.x server is authoritative for the domain it supports.

Inspect the "named.conf" file and identify all of the zone files that the BIND 9.x server is using.

zone "example.com" {
file "zone_file";
};

Inspect each zone file and identify each NS record listed.

86400 NS ns1.example.com
86400 NS ns2.example.com

With the assistance of the DNS Administrator, verify that each name server listed is authoritative for that domain.

If there are name serve...
```
**NIST SP 800-53 Rev 4:** CM-6 b
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-207595 - BIND-9X-001612
**Severity:** MEDIUM

**Rule Title:** On a BIND 9.x server all authoritative name servers for a zone must be located on different network segments.

**Automation Status:** Automatable

**Automation Method:** Bash (grep/awk for named.conf parsing)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**Notes:**
- BIND configuration file parsing (named.conf)

**Check Content:**
```
Verify that each name server listed on the BIND 9.x server is on a separate network segment.

Inspect the "named.conf" file and identify all of the zone files that the BIND 9.x server is using.

zone "example.com" {
file "zone_file";
};

Inspect each zone file and identify each A record for each NS record listed:

ns1.example.com 86400 IN A 192.168.1.4
ns2.example.com 86400 IN A 192.168.2.4

If there are name servers listed in the zone file that are not on different network segments for the spec...
```
**NIST SP 800-53 Rev 4:** CM-6 b
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-207596 - BIND-9X-001613
**Severity:** MEDIUM

**Rule Title:** On a BIND 9.x server all authoritative name servers for a zone must have the same version of zone information.

**Automation Status:** Automatable

**Automation Method:** Bash (file/directory checks)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**Check Content:**
```
Verify that the SOA record is at the same version for all authoritative servers for a specific zone.

With the assistance of the DNS administrator, identify each name server that is authoritative for each zone.

Inspect each zone file that the server is authoritative for and identify the following:

example.com. 86400 IN SOA ns1.example.com. root.example.com. (17760704;serial) 

If the SOA "serial" numbers are not identical on each authoritative name server, this is a finding.
```
**NIST SP 800-53 Rev 4:** CM-6 b
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-207597 - BIND-9X-001620
**Severity:** LOW

**Rule Title:** On a BIND 9.x server all root name servers listed in the local root zone file hosted on a BIND 9.x authoritative name server must be valid for that zone.

**Automation Status:** Automatable

**Automation Method:** Bash (grep/awk for named.conf parsing)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**🔧 Configuration Dependencies:**
- ⚠️ **SYSTEM-SPECIFIC**: This check depends on deployment/installation-specific configuration

**Notes:**
- BIND configuration file parsing (named.conf)

**Check Content:**
```
If this is an authoritative name server, this is Not Applicable.

Identify the local root zone file in named.conf:

zone "." IN {
type hint;
file "<file_name>"
};

Examine the local root zone file.

If the local root zone file lists domains outside of the name serverâ€™s primary domain, this is a finding.
```
**NIST SP 800-53 Rev 4:** CM-6 b
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-207598 - BIND-9X-001621
**Severity:** LOW

**Rule Title:** On a BIND 9.x server all root name servers listed in the local root zone file hosted on a BIND 9.x authoritative name server must be empty or removed.

**Automation Status:** Automatable

**Automation Method:** Bash (grep/awk for named.conf parsing)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**🔧 Configuration Dependencies:**
- ⚠️ **SYSTEM-SPECIFIC**: This check depends on deployment/installation-specific configuration

**Notes:**
- BIND configuration file parsing (named.conf)

**Check Content:**
```
If this server is a caching name server, this is Not Applicable.

Ensure there is not a local root zone on the name server.

Inspect the "named.conf" file for the following:

zone "." IN {
type hint;
file "<file_name>"
};

If the file name identified is not empty or does exist, this is a finding.
```
**NIST SP 800-53 Rev 4:** CM-6 b
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-207601 - BIND-9X-001702
**Severity:** MEDIUM

**Rule Title:** The BIND 9.x server implementation must prohibit the forwarding of queries to servers controlled by organizations outside of the U.S. Government.

**Automation Status:** Automatable

**Automation Method:** Bash (grep/awk for named.conf parsing)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**Notes:**
- BIND configuration file parsing (named.conf)

**Check Content:**
```
If the server is not a caching server, this is Not Applicable.
This is Not Applicable to SIPR. 

Note: The use of the DREN Enterprise Recursive DNS (Domain Name System) servers, as mandated by the DoDIN service provider Defense Research and Engineering Network (DREN), meets the intent of this requirement. 

Verify that the server is configured to forward all DNS traffic to the DISA Enterprise Recursive Service (ERS) anycast IP addresses ( <IP_ADDRESS_LIST>; ):

Inspect the "named.conf" file for ...
```
**NIST SP 800-53 Rev 4:** CM-6 b
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

### Partially Automatable (17 checks)

#### V-207533 - BIND-9X-001000
**Severity:** HIGH

**Rule Title:** A BIND 9.x server implementation must be operating on a Current-Stable version as defined by ISC.

**Automation Status:** Partially Automatable

**Automation Method:** Bash/Python (needs validation)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**Notes:**
- Automation possible but may require manual validation

**Check Content:**
```
Verify that the BIND 9.x server is at a version that is considered "Current-Stable" by ISC or latest supported version of BIND when BIND is installed as part of a specific vendor implementation where the vendor maintains the BIND patches.

# named -v

The above command should produce a version number similar to the following:

BIND 9.9.4-RedHat-9.9.4-29.el7_2.3

If the server is running a version that is not listed as "Current-Stable" by ISC, this is a finding.

```
**NIST SP 800-53 Rev 4:** CM-6 b
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-207534 - BIND-9X-001002
**Severity:** MEDIUM

**Rule Title:** The platform on which the name server software is hosted must only run processes and services needed to support the BIND 9.x implementation.

**Automation Status:** Partially Automatable

**Automation Method:** Bash/Python (needs validation)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**Notes:**
- Automation possible but may require manual validation

**Check Content:**
```
Verify that the BIND 9.x server is dedicated for DNS traffic:

With the assistance of the DNS administrator, identify all of the processes running on the BIND 9.x server:

# ps -ef | less

If any of the identified processes are not in support of normal OS functionality or in support of the BIND 9.x process, this is a finding.
```
**NIST SP 800-53 Rev 4:** CM-6 b
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-207536 - BIND-9X-001004
**Severity:** MEDIUM

**Rule Title:** The host running a BIND 9.X implementation must implement a set of firewall rules that restrict traffic on the DNS interface.

**Automation Status:** Partially Automatable

**Automation Method:** Bash/Python (needs validation)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**Notes:**
- Automation possible but may require manual validation

**Check Content:**
```
With the assistance of the DNS administrator, verify that the OS firewall is configured to only allow incoming messages on ports 53/tcp and 53/udp.

Note: The following rules are for the IPTables firewall. If the system is utilizing a different firewall, the rules may be different.

Inspect the hosts firewall rules for the following rules:

-A INPUT -i [DNS Interface] -p tcp --dport 53 -j ACCEPT
-A INPUT -i [DNS Interface] -p udp --dport 53 -j ACCEPT
-A INPUT -i [DNS Interface] -j DROP

If any o...
```
**NIST SP 800-53 Rev 4:** CM-6 b
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-207537 - BIND-9X-001005
**Severity:** MEDIUM

**Rule Title:** The host running a BIND 9.x implementation must use a dedicated management interface in order to separate management traffic from DNS specific traffic.

**Automation Status:** Partially Automatable

**Automation Method:** Bash/Python (needs validation)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**Notes:**
- Automation possible but may require manual validation

**Check Content:**
```
Verify that the BIND 9.x server is configured to use a dedicated management interface:

# ifconfig -a
eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST> mtu 1500
inet 10.0.1.252 netmask 255.255.255.0 broadcast 10.0.1.255
inet6 fd80::21c:d8ff:fab7:1dba prefixlen 64 scopeid 0x20<link>
ether 00:1a:b8:d7:1a:bf txqueuelen 1000 (Ethernet)
RX packets 2295379 bytes 220126493 (209.9 MiB)
RX errors 0 dropped 31 overruns 0 frame 0
TX packets 70507 bytes 12284940 (11.7 MiB)
TX errors 0 dropped 0 overruns 0 ca...
```
**NIST SP 800-53 Rev 4:** CM-6 b
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-207538 - BIND-9X-001006
**Severity:** MEDIUM

**Rule Title:** The host running a BIND 9.x implementation must use an interface that is configured to process only DNS traffic.

**Automation Status:** Partially Automatable

**Automation Method:** Bash/Python (needs validation)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**Notes:**
- Automation possible but may require manual validation

**Check Content:**
```
Verify that the BIND 9.x server is configured to use an interface that is configured to process only DNS traffic.

# ifconfig -a
eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST> mtu 1500
inet 10.0.1.252 netmask 255.255.255.0 broadcast 10.0.1.255
inet6 fd80::21c:d8ff:fab7:1dba prefixlen 64 scopeid 0x20<link>
ether 00:1a:b8:d7:1a:bf txqueuelen 1000 (Ethernet)
RX packets 2295379 bytes 220126493 (209.9 MiB)
RX errors 0 dropped 31 overruns 0 frame 0
TX packets 70507 bytes 12284940 (11.7 MiB)
TX error...
```
**NIST SP 800-53 Rev 4:** CM-6 b
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-207552 - BIND-9X-001053
**Severity:** MEDIUM

**Rule Title:** The BIND 9.x server implementation must be configured to use only approved ports and protocols.

**Automation Status:** Partially Automatable

**Automation Method:** Bash (grep/awk for named.conf parsing)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**🔧 Configuration Dependencies:**
- ⚠️ **ENVIRONMENT-SPECIFIC**: This check requires site-specific or organizational values

**Notes:**
- BIND configuration file parsing (named.conf)

**Check Content:**
```
Verify the BIND 9.x server is configured to listen on UDP/TCP port 53.

Inspect the "named.conf" file for the following:

options {
listen-on port 53 { <ip_address>; };
};

If the "port" variable is missing, this is a finding.

If the "port" variable is not set to "53", this is a finding.

Note: "<ip_address>" should be replaced with the DNS server IP address.
```
**NIST SP 800-53 Rev 4:** CM-7 b
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-207553 - BIND-9X-001054
**Severity:** MEDIUM

**Rule Title:** A BIND 9.x server implementation must manage excess capacity, bandwidth, or other redundancy to limit the effects of information flooding types of Denial of Service (DoS) attacks.

**Automation Status:** Partially Automatable

**Automation Method:** Bash (grep/awk for named.conf parsing)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**🔧 Configuration Dependencies:**
- ⚠️ **ENVIRONMENT-SPECIFIC**: This check requires site-specific or organizational values

**Notes:**
- BIND configuration file parsing (named.conf)

**Check Content:**
```
If this is a recursive name server, this is not applicable.

Note: A recursive name server should NOT be configured as an authoritative name server for any zone.

Verify that the BIND 9.x server is configured to prohibit recursion on authoritative name servers.

Inspect the "named.conf" file for the following:

options {
recursion no;
allow-query {none;};
};

If the "recursion" sub statement is missing, or set to "yes", this is a finding.

If the "allow-query" sub statement under the "options st...
```
**NIST SP 800-53 Rev 4:** SC-5 (2)
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-207554 - BIND-9X-001055
**Severity:** MEDIUM

**Rule Title:** A BIND 9.x server implementation must prohibit recursion on authoritative name servers.

**Automation Status:** Partially Automatable

**Automation Method:** Bash (grep/awk for named.conf parsing)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**🔧 Configuration Dependencies:**
- ⚠️ **ENVIRONMENT-SPECIFIC**: This check requires site-specific or organizational values

**Notes:**
- BIND configuration file parsing (named.conf)

**Check Content:**
```
If this is a recursive name server, this is not applicable.

Note: A recursive name server should NOT be configured as an authoritative name server for any zone.

Verify that the BIND 9.x server is configured to prohibit recursion on authoritative name servers.

Inspect the "named.conf" file for the following:

options {
recursion no;
allow-recursion {none;};
allow-query {none;};
};

If the "recursion" sub statement is missing, or set to "yes", this is a finding.

If the â€œallow-recursionâ€ su...
```
**NIST SP 800-53 Rev 4:** CM-6 b
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-207555 - BIND-9X-001057
**Severity:** LOW

**Rule Title:** The master servers in a BIND 9.x implementation must notify authorized secondary name servers when zone files are updated.

**Automation Status:** Partially Automatable

**Automation Method:** Bash (grep/awk for named.conf parsing)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**🔧 Configuration Dependencies:**
- ⚠️ **ENVIRONMENT-SPECIFIC**: This check requires site-specific or organizational values

**Notes:**
- BIND configuration file parsing (named.conf)

**Check Content:**
```
If this is a secondary name server, this is Not Applicable.

On a master name server, verify that the global notify is disabled. The global entry for the name server is under the â€œOptionsâ€ section and notify should be disabled at this section.

Inspect the "named.conf" file for the following:

options {
notify no;
};

If the "notify" statement is missing, this is a finding.
If the "notify" statement is set to "yes", this is a finding.

Verify that each zone is configured to notify authorized...
```
**NIST SP 800-53 Rev 4:** CM-6 b
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-207556 - BIND-9X-001058
**Severity:** LOW

**Rule Title:** The secondary name servers in a BIND 9.x implementation must be configured to initiate zone update notifications to other authoritative zone name servers.

**Automation Status:** Partially Automatable

**Automation Method:** Bash (grep/awk for named.conf parsing)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**🔧 Configuration Dependencies:**
- ⚠️ **ENVIRONMENT-SPECIFIC**: This check requires site-specific or organizational values

**Notes:**
- BIND configuration file parsing (named.conf)

**Check Content:**
```
If this is a master name server, this is Not Applicable.

On a secondary name server, verify that the global notify is disabled. The global entry for the name server is under the â€œOptionsâ€ section and notify should be disabled at this section.

Inspect the "named.conf" file for the following:

options {
notify no;
};

If the "notify" statement is missing, this is a finding.
If the "notify" statement is set to "yes", this is a finding.

Verify that zones for which the secondary server is auth...
```
**NIST SP 800-53 Rev 4:** CM-6 b
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-207559 - BIND-9X-001070
**Severity:** MEDIUM

**Rule Title:** A BIND 9.x master name server must limit the number of concurrent zone transfers between authorized secondary name servers.

**Automation Status:** Partially Automatable

**Automation Method:** Bash (grep/awk for named.conf parsing)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**🔧 Configuration Dependencies:**
- ⚠️ **ENVIRONMENT-SPECIFIC**: This check requires site-specific or organizational values

**Notes:**
- BIND configuration file parsing (named.conf)

**Check Content:**
```
If this is not a master name server, this requirement is Not Applicable

Verify that the name server is configured to limit the number of zone transfers from authorized secondary name servers.

Inspect the "named.conf" file for the following:

server <ip_address> {
transfers 2;
};

If each "server" statement does not contain a "transfers" sub statement, this is a finding.
```
**NIST SP 800-53 Rev 4:** AC-10
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-207567 - BIND-9X-001120
**Severity:** HIGH

**Rule Title:** A BIND 9.x server must implement NIST FIPS-validated cryptography for provisioning digital signatures and generating cryptographic hashes.

**Automation Status:** Partially Automatable

**Automation Method:** Bash (grep/awk for named.conf parsing)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**🔧 Configuration Dependencies:**
- ⚠️ **ENVIRONMENT-SPECIFIC**: This check requires site-specific or organizational values

**Notes:**
- BIND configuration file parsing (named.conf)

**Check Content:**
```
Verify that the DNSSEC and TSIG keys used by the BIND 9.x implementation are FIPS 180-3 compliant.

If the server is in a classified network, the DNSSEC portion of the requirement is Not Applicable.
DNSSEC KEYS:

Inspect the "named.conf" file and identify all of the DNSSEC signed zone files:

zone "example.com" {
file "signed_zone_file";
};

For each signed zone file identified, inspect the file for the "DNSKEY" records: 

86400 DNSKEY 257 3 8 (
<KEY HASH>
) ; KSK; 
86400 DNSKEY 256 3 8 (
<KEY H...
```
**NIST SP 800-53 Rev 4:** SC-13
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-207579 - BIND-9X-001311
**Severity:** MEDIUM

**Rule Title:** The BIND 9.x server validity period for the RRSIGs covering the DS RR for zones delegated children must be no less than two days and no more than one week.

**Automation Status:** Partially Automatable

**Automation Method:** Bash/Python (needs validation)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**Notes:**
- Automation possible but may require manual validation

**Check Content:**
```
If the server is in a classified network, this is Not Applicable.
Note: This requirement does not validate the sig-validity-interval. This requirement ensures the signature validity period (i.e., the time from the signatureâ€™s inception until the signatureâ€™s expiration). It is recommended to ensure the Start of Authority (SOA) expire period (how long a secondary will still treat its copy of the zone data as valid if it cannot contact the primary.) is configured to ensure the SOA does not expi...
```
**NIST SP 800-53 Rev 4:** SC-20 b
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-207585 - BIND-9X-001402
**Severity:** MEDIUM

**Rule Title:** On a BIND 9.x server in a split DNS configuration, where separate name servers are used between the external and internal networks, the internal name server must be configured to not be reachable from outside resolvers.

**Automation Status:** Partially Automatable

**Automation Method:** Bash (grep/awk for named.conf parsing)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**🔧 Configuration Dependencies:**
- ⚠️ **ENVIRONMENT-SPECIFIC**: This check requires site-specific or organizational values

**Notes:**
- BIND configuration file parsing (named.conf)

**Check Content:**
```
If the BIND 9.x name server is not configured for split DNS, this is Not Applicable.

Verify that the BIND 9.x server is configured to use the "match-clients" sub statement to limit the reach of the internal view from the external view.

Inspect the "named.conf" file for the following:

view "internal" {
match-clients { <ip_address> | <address_match_list>; };
};

If the "match-clients" sub statement is missing for the internal view, this is a finding.

If the "match-clients" sub statement for th...
```
**NIST SP 800-53 Rev 4:** CM-6 b
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-207588 - BIND-9X-001405
**Severity:** HIGH

**Rule Title:** A BIND 9.x implementation operating in a split DNS configuration must be approved by the organizations Authorizing Official.

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
If the BIND 9.x name server is not configured for split DNS, this is Not Applicable.

Verify that the split DNS implementation has been approved by the organizations Authorizing Official.

With the assistance of the DNS administrator, obtain the Authorizing Officialâ€™s letter of approval for the split DNS implementation.

If the split DNS implementation has not been approved by the organizations Authorizing Official, this is a finding.
```
**NIST SP 800-53 Rev 4:** CM-6 b
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-207591 - BIND-9X-001510
**Severity:** MEDIUM

**Rule Title:** A BIND 9.x server implementation must enforce approved authorizations for controlling the flow of information between authoritative name servers and specified secondary name servers based on DNSSEC policies.

**Automation Status:** Partially Automatable

**Automation Method:** Bash (grep/awk for named.conf parsing)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**🔧 Configuration Dependencies:**
- ⚠️ **ENVIRONMENT-SPECIFIC**: This check requires site-specific or organizational values

**Notes:**
- BIND configuration file parsing (named.conf)

**Check Content:**
```
On an authoritative name sever, verify that each zone statement defined in the "named.conf" file contains an "allow-transfer" statement.

Inspect the "named.conf" file for the following:

zone example.com {
allow-transfer { <ip_address_list>; };
};

If there is not an "allow-transfer" statement for each zone defined, or the list contains IP addresses that are not authorized for that zone, this is a finding.

On a slave name server, verify that each zone statement defined in the "named.conf" file...
```
**NIST SP 800-53 Rev 4:** CM-6 b
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-207592 - BIND-9X-001600
**Severity:** MEDIUM

**Rule Title:** A BIND 9.x server validity period for the RRSIGs covering a zones DNSKEY RRSet must be no less than two days and no more than one week.

**Automation Status:** Partially Automatable

**Automation Method:** Bash/Python (needs validation)

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

**Notes:**
- Automation possible but may require manual validation

**Check Content:**
```
If the server is in a classified network, this is Not Applicable.

With the assistance of the DNS Administrator, identify the RRSIGs that cover the DNSKEY resource record set for each zone.

Each record will list an expiration and inception date, the difference of which will provide the validity period.

The dates are listed in the following format:

YYYYMMDDHHMMSS

For each RRSIG identified, verify that the validity period is no less than two days and is no longer than seven days.

If the valid...
```
**NIST SP 800-53 Rev 4:** CM-6 b
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

### Manual Review Required (2 checks)

#### V-207599 - BIND-9X-001700
**Severity:** MEDIUM

**Rule Title:** On the BIND 9.x server a zone file must not include resource records that resolve to a fully qualified domain name residing in another zone.

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
Verify that the zone files used by the BIND 9.x server do not contain resource records for a domain in which the server is not authoritative.

The exceptions are glue records supporting zone delegations, CNAME records supporting a system migration, or CNAME records that point to third-party Content Delivery Networks (CDN) or cloud computing platforms. In the case of third-party CDNs or cloud offerings, an approved mission need must be demonstrated.

Inspect the "named.conf" file to identify the ...
```
**NIST SP 800-53 Rev 4:** CM-6 b
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

#### V-207600 - BIND-9X-001701
**Severity:** LOW

**Rule Title:** On the BIND 9.x server CNAME records must not point to a zone with lesser security for more than six months.

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
Verify that the zone files used by the BIND 9.x server do not contain resource records for a domain in which the server is not authoritative.

Inspect the "named.conf" file for the following:

zone example.com {
file "db.example.com.signed";
};

Inspect each zone file for "CNAME" records and verify with the DNS administrator that these records are less than 6 months old.

The exceptions are glue records supporting zone delegations, CNAME records supporting a system migration, or CNAME records th...
```
**NIST SP 800-53 Rev 4:** CM-6 b
NIST SP 800-53 Revisio

--------------------------------------------------------------------------------

