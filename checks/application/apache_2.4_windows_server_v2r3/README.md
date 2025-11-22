# Apache 2.4 Windows Server v2r3 - STIG Automation Framework

## Overview

Automated STIG compliance checks for **Apache 2.4 Windows Server Version 2 Release 3**.

- **Total Checks**: 54
- **Platform**: Windows
- **STIG Version**: v2r3
- **Generated**: 2025-11-22

## Tool Priority

For Apache on Windows systems:

1. **PowerShell** (.ps1) - Primary automation tool
2. **Python** (.py) - Fallback/cross-platform option

## Quick Start

### Running Individual Checks

#### PowerShell (Primary)
```powershell
# Run a single check
.\V-214306.ps1

# Run with JSON output
.\V-214306.ps1 -OutputJson results.json

# Run with configuration file
.\V-214306.ps1 -ConfigFile apache-config.json

# Show help
.\V-214306.ps1 -Help
```

#### Python (Fallback)
```bash
# Run a single check
python V-214306.py

# Run with JSON output
python V-214306.py --output-json results.json

# Run with configuration file
python V-214306.py --config apache-config.json
```

### Running All Checks

#### PowerShell
```powershell
# Run all checks and save results
$results = @()
Get-ChildItem -Filter "V-*.ps1" | ForEach-Object {
    $jsonFile = "results\$($_.BaseName).json"
    & $_.FullName -OutputJson $jsonFile
    $results += Get-Content $jsonFile | ConvertFrom-Json
}
$results | ConvertTo-Json -Depth 10 | Out-File all-results.json
```

#### Python
```bash
# Create results directory
mkdir results

# Run all checks
for %f in (V-*.py) do python %f --output-json results\%~nf.json
```

## Exit Codes

- **0** = PASS (Compliant)
- **1** = FAIL (Finding)
- **2** = N/A (Not Applicable)
- **3** = ERROR (Check execution error)

## Tool Requirements

### PowerShell Checks (Primary)
- Windows PowerShell 5.1+ or PowerShell Core 7+
- Apache for Windows installed
- Administrative privileges (for some checks)

### Python Checks (Fallback)
- Python 3.6+
- Standard library only
- Apache for Windows installed

## Configuration File Support

Checks support an `apache-config.json` file for environment-specific values.

Example:
```json
{
  "apache": {
    "httpd_exe": "C:\\Apache24\\bin\\httpd.exe",
    "config_file": "C:\\Apache24\\conf\\httpd.conf",
    "install_root": "C:\\Apache24"
  },
  "organization": {
    "name": "Your Organization",
    "contact": "security@example.com"
  }
}
```

## Apache Detection

The scripts automatically detect Apache installation in common locations:
- `C:\Apache24\bin\httpd.exe`
- `C:\Apache22\bin\httpd.exe`
- `C:\Program Files\Apache Software Foundation\Apache2.4\bin\httpd.exe`
- `C:\xampp\apache\bin\httpd.exe`

## Check Structure

Each check script includes:
- STIG metadata (Vuln ID, STIG ID, Severity)
- Apache configuration detection helpers
- Configuration file support
- JSON output support
- Help text
- Standardized exit codes

## Implementation Status

**Status**: Framework generated - implementation required

All checks are currently stubs with TODO comments. Full implementation requires:
1. Apache domain expertise
2. Access to Windows Apache systems for testing
3. Organization-specific configuration
4. Understanding of Apache directives and modules on Windows

## Common Apache STIG Checks

These checks typically cover:
- Session management (KeepAlive, MaxKeepAliveRequests)
- TLS/SSL configuration
- Directory permissions and access controls
- Logging and auditing
- Module security
- Error handling and disclosure
- CGI/Script execution controls
- Windows-specific file permissions

## Contributing

To implement a check:
1. Open the check script (V-214306.ps1 or V-214306.py)
2. Review STIG requirements in header
3. Implement check logic in TODO section
4. Test on actual Windows Apache systems
5. Update documentation

## References

- [Official STIG Documentation](https://public.cyber.mil/stigs/)
- [Apache HTTP Server Documentation](https://httpd.apache.org/docs/)
- [STIG Viewer](https://www.stigviewer.com/)

## Directory Structure

```
apache_2.4_windows_server_v2r3/
├── README.md (this file)
├── V-214306.ps1 (PowerShell check - primary)
├── V-214306.py (Python check - fallback)
└── ... (54 checks total)
```

---

**Generated**: 2025-11-22
**STIG Version**: v2r3
**Total Checks**: 54
**Platform**: Windows
**Tool Priority**: PowerShell (primary) > Python (fallback)
