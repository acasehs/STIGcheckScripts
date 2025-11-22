# Microsoft Word 2016 STIG Automation Framework

## Overview

This directory contains automated compliance check scripts for the Microsoft Word 2016 Security Technical Implementation Guide (STIG).

**Total Checks:** 34

## Platform Requirements

- **Operating System:** Windows
- **Office Version:** Word 2016
- **PowerShell:** 5.1 or higher (for .ps1 scripts)
- **Python:** 3.6 or higher (for .py fallback scripts)

## Office Installation Detection

Before running checks, ensure that Word 2016 is installed on the system. Checks primarily validate:
- Registry settings in HKCU and HKLM hives
- Office installation paths
- Trust Center configurations
- Security policy settings

## Directory Structure

```
.
├── README.md           # This file
├── DTOO*.ps1          # PowerShell check scripts
└── DTOO*.py           # Python fallback scripts
```

## Quick Start

### Run Individual Check (PowerShell)

```powershell
# Basic check
.\DTOO182.ps1

# Check with custom configuration
.\DTOO182.ps1 -Config custom_config.json

# Output in JSON format
.\DTOO182.ps1 -OutputJson

# Display help
.\DTOO182.ps1 -Help
```

### Run Individual Check (Python)

```bash
# Basic check
python DTOO182.py

# Check with custom configuration
python DTOO182.py --config custom_config.json

# Output in JSON format
python DTOO182.py --output-json

# Display help
python DTOO182.py --help
```

### Run All Checks

```powershell
# PowerShell: Run all checks and save results
Get-ChildItem -Filter "DTOO*.ps1" | ForEach-Object {
    $result = & $_.FullName -OutputJson | ConvertFrom-Json
    [PSCustomObject]@{
        Check = $_.BaseName
        Status = $result.Status
        Details = $result.Finding_Details
    }
} | Export-Csv -Path "office_stig_results.csv" -NoTypeInformation
```

## Registry Key Reference

Most Word 2016 STIG checks validate Windows Registry settings. Common registry locations include:

### User Configuration Settings
- `HKCU\Software\Policies\Microsoft\Office\16.0\common\`
- `HKCU\Software\Policies\Microsoft\Office\16.0\common\security\`
- `HKCU\Software\Policies\Microsoft\Office\16.0\common\trustcenter\`

### Application-Specific Settings
- Excel: `HKCU\Software\Policies\Microsoft\Office\16.0\excel\`
- Word: `HKCU\Software\Policies\Microsoft\Office\16.0\word\`
- PowerPoint: `HKCU\Software\Policies\Microsoft\Office\16.0\powerpoint\`
- Outlook: `HKCU\Software\Policies\Microsoft\Office\16.0\outlook\`

### Machine-Level Settings
- `HKLM\Software\Policies\Microsoft\Office\16.0\`

## Common Registry Value Types

- **REG_DWORD**: 32-bit integer (e.g., 0, 1, 2)
- **REG_SZ**: String value (e.g., "Microsoft Enhanced RSA and AES Cryptographic Provider,AES 256,256")
- **REG_BINARY**: Binary data

## Exit Codes

All check scripts use standardized exit codes:

| Exit Code | Status | Description |
|-----------|--------|-------------|
| 0 | PASS | System is compliant with STIG requirement |
| 1 | FAIL | System is not compliant with STIG requirement |
| 2 | N/A | Check is not applicable to this system |
| 3 | ERROR | Script encountered an error during execution |

## Configuration File Format

Custom configuration files use JSON format:

```json
{
  "registry_overrides": {
    "custom_key": "HKCU\\Software\\Custom\\Path",
    "custom_value": "CustomValue"
  },
  "thresholds": {
    "custom_threshold": 100
  },
  "exceptions": [
    "system1.example.com",
    "system2.example.com"
  ]
}
```

## Common Office STIG Categories

### Trust Center Settings
Controls for macros, add-ins, ActiveX controls, and external content.

### Encryption Settings
Requirements for document encryption, metadata protection, and cryptographic providers.

### Privacy Settings
Controls for telemetry, feedback tools, and personal information sharing.

### Security Zones
Trusted locations, trusted publishers, and content source restrictions.

## Implementation Notes

### Current Status
- All scripts are **FRAMEWORK IMPLEMENTATIONS** with TODO placeholders
- Actual check logic requires Microsoft Office domain expertise
- Registry reading functions are implemented but validation logic is stubbed

### Automation Feasibility
Most Word 2016 STIG checks are **highly automatable** because they primarily involve:
- Registry key existence checks
- Registry value validation
- File version detection
- Installation path verification

### Prerequisites
1. Administrative privileges (for some registry reads)
2. Office installation on target system
3. Appropriate Group Policy configurations

## Security Considerations

### Execution Policy
PowerShell scripts may require execution policy adjustment:

```powershell
# View current execution policy
Get-ExecutionPolicy

# Set execution policy for current user (if needed)
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### Permissions
- Some checks require administrative privileges to read HKLM registry keys
- User-level checks (HKCU) can run with standard user permissions
- Consider running as part of system inventory or compliance scan

### Group Policy
Many Office STIG requirements are enforced via Group Policy. These checks validate that:
- Group Policy settings are correctly applied
- Local policy overrides are not present
- Security configurations match STIG requirements

## Troubleshooting

### Registry Access Errors
```
Error: Access to registry key denied
```
**Solution:** Run PowerShell as Administrator or check user permissions

### Office Not Detected
```
Error: Office installation not found
```
**Solution:** Verify Office is installed and registry keys exist

### Python winreg Module Errors
```
ModuleNotFoundError: No module named 'winreg'
```
**Solution:** This is a Windows-only module. Ensure you're running on Windows

## Additional Resources

- [Microsoft Office 2016 STIG Documentation](https://public.cyber.mil/stigs/)
- [Group Policy Administrative Templates](https://www.microsoft.com/en-us/download/details.aspx?id=49030)
- [Office Trust Center Overview](https://support.microsoft.com/office)

## Contributing

These scripts are framework implementations requiring Office security expertise to complete. When implementing check logic:

1. Review the STIG requirement carefully
2. Test registry key access permissions
3. Handle edge cases (key not found, value type mismatch)
4. Document any deviations from STIG guidance
5. Update this README with implementation notes

## License

These scripts are provided as-is for STIG compliance automation purposes.
