#!/usr/bin/env python3
"""
Microsoft Office STIG Automation Framework Generator
Generates PowerShell and Python check scripts for Microsoft Office STIGs
"""

import json
import os
import sys
import re
from pathlib import Path

# Office product configurations
OFFICE_PRODUCTS = {
    'microsoft_office_system_2016': {
        'json_file': 'microsoft_office_system_2016_checks.json',
        'dir_name': 'ms_office_system_2016',
        'display_name': 'Microsoft Office System 2016',
        'short_name': 'Office 2016'
    },
    'microsoft_office_365_proplus': {
        'json_file': 'microsoft_office_365_proplus_checks.json',
        'dir_name': 'ms_office_365_proplus',
        'display_name': 'Microsoft Office 365 ProPlus',
        'short_name': 'Office 365 ProPlus'
    },
    'microsoft_excel_2016': {
        'json_file': 'microsoft_excel_2016_checks.json',
        'dir_name': 'ms_excel_2016',
        'display_name': 'Microsoft Excel 2016',
        'short_name': 'Excel 2016'
    },
    'microsoft_word_2016': {
        'json_file': 'microsoft_word_2016_checks.json',
        'dir_name': 'ms_word_2016',
        'display_name': 'Microsoft Word 2016',
        'short_name': 'Word 2016'
    },
    'microsoft_powerpoint_2016': {
        'json_file': 'microsoft_powerpoint_2016_checks.json',
        'dir_name': 'ms_powerpoint_2016',
        'display_name': 'Microsoft PowerPoint 2016',
        'short_name': 'PowerPoint 2016'
    },
    'microsoft_outlook_2016': {
        'json_file': 'microsoft_outlook_2016_checks.json',
        'dir_name': 'ms_outlook_2016',
        'display_name': 'Microsoft Outlook 2016',
        'short_name': 'Outlook 2016'
    }
}

def sanitize_filename(name):
    """Sanitize STIG ID for use as filename"""
    return re.sub(r'[^\w\-]', '_', name)

def extract_registry_info(check_content):
    """Extract registry key and value info from check content"""
    reg_key_match = re.search(r'(HKCU|HKLM|HKEY_CURRENT_USER|HKEY_LOCAL_MACHINE)\\([^\n]+)', check_content)
    reg_value_match = re.search(r'value\s+(\w+)\s+is\s+REG_(\w+)\s*=\s*(.+?)[,\.]', check_content, re.IGNORECASE)

    reg_key = reg_key_match.group(0) if reg_key_match else None
    reg_value_name = reg_value_match.group(1) if reg_value_match else None
    reg_value_type = reg_value_match.group(2) if reg_value_match else None
    expected_value = reg_value_match.group(3).strip() if reg_value_match else None

    return reg_key, reg_value_name, reg_value_type, expected_value

def generate_powershell_script(check, product_name):
    """Generate PowerShell check script"""
    stig_id = check.get('STIG ID', 'UNKNOWN')
    rule_title = check.get('Rule Title', '').strip()
    severity = check.get('Severity', 'medium')
    vuln_id = check.get('Group ID', '')
    rule_id = check.get('Rule ID', '')
    check_content = check.get('Check Content', '')

    # Extract registry information
    reg_key, reg_value_name, reg_value_type, expected_value = extract_registry_info(check_content)

    script = f'''<#
.SYNOPSIS
    {stig_id} - {rule_title}

.DESCRIPTION
    STIG ID: {stig_id}
    Rule Title: {rule_title}
    Severity: {severity}
    Vuln ID: {vuln_id}
    Rule ID: {rule_id}

    This script checks {product_name} configuration compliance.

.PARAMETER Config
    Path to JSON configuration file for customized check parameters.

.PARAMETER OutputJson
    Output results in JSON format.

.PARAMETER Help
    Display this help message.

.EXAMPLE
    .\\{stig_id}.ps1
    Run the check with default parameters

.EXAMPLE
    .\\{stig_id}.ps1 -Config custom_config.json
    Run the check with custom configuration

.EXAMPLE
    .\\{stig_id}.ps1 -OutputJson
    Run the check and output results in JSON format

.NOTES
    Exit Codes:
    0 = PASS (Compliant)
    1 = FAIL (Non-Compliant)
    2 = N/A (Not Applicable)
    3 = ERROR (Script execution error)

    Registry Check:
'''

    if reg_key:
        script += f'''    Key: {reg_key}
'''
    if reg_value_name:
        script += f'''    Value: {reg_value_name}
'''
    if reg_value_type:
        script += f'''    Type: REG_{reg_value_type}
'''
    if expected_value:
        script += f'''    Expected: {expected_value}
'''

    script += '''#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$Config,

    [Parameter(Mandatory=$false)]
    [switch]$OutputJson,

    [Parameter(Mandatory=$false)]
    [switch]$Help
)

# Display help if requested
if ($Help) {
    Get-Help $MyInvocation.MyCommand.Path -Detailed
    exit 0
}

# Initialize result object
$result = @{
    STIG_ID = "''' + stig_id + '''"
    Rule_Title = "''' + rule_title.replace('"', '`"') + '''"
    Severity = "''' + severity + '''"
    Status = "Not_Reviewed"
    Finding_Details = ""
    Comments = ""
}

try {
    # Load custom configuration if provided
    $customConfig = $null
    if ($Config -and (Test-Path $Config)) {
        try {
            $customConfig = Get-Content $Config -Raw | ConvertFrom-Json
            Write-Verbose "Loaded custom configuration from $Config"
        }
        catch {
            Write-Warning "Failed to load configuration file: $_"
        }
    }

'''

    if reg_key:
        # Convert HKCU to full path
        reg_path = reg_key.replace('HKCU\\', 'HKCU:\\').replace('HKLM\\', 'HKLM:\\')
        script += f'''    # Check registry setting
    $regPath = "{reg_path}"
'''
        if reg_value_name:
            script += f'''    $regValueName = "{reg_value_name}"
'''
        if expected_value:
            script += f'''    $expectedValue = {expected_value}
'''

        script += '''
    # TODO: Implement registry check logic
    # Example implementation:
    # if (Test-Path $regPath) {
    #     $regValue = Get-ItemProperty -Path $regPath -Name $regValueName -ErrorAction SilentlyContinue
    #     if ($regValue -and $regValue.$regValueName -eq $expectedValue) {
    #         $result.Status = "PASS"
    #         $result.Finding_Details = "Registry setting is compliant."
    #     }
    #     else {
    #         $result.Status = "FAIL"
    #         $result.Finding_Details = "Registry setting is not compliant."
    #     }
    # }
    # else {
    #     $result.Status = "FAIL"
    #     $result.Finding_Details = "Registry key not found."
    # }

    # Placeholder - Mark as Not Reviewed until implementation is complete
    $result.Status = "Not_Reviewed"
    $result.Comments = "Automated check not yet implemented - requires Office domain expertise"
    $result.Finding_Details = "This check requires registry validation"
'''
    else:
        script += '''    # TODO: Implement check logic
    # This check requires manual implementation based on STIG requirements

    $result.Status = "Not_Reviewed"
    $result.Comments = "Automated check not yet implemented - requires Office domain expertise"
'''

    script += '''
}
catch {
    $result.Status = "ERROR"
    $result.Finding_Details = "Error: $($_.Exception.Message)"
    $result.Comments = "Script execution failed"
}

# Output results
if ($OutputJson) {
    $result | ConvertTo-Json
}
else {
    Write-Host "STIG ID: $($result.STIG_ID)"
    Write-Host "Status: $($result.Status)"
    Write-Host "Finding Details: $($result.Finding_Details)"
    if ($result.Comments) {
        Write-Host "Comments: $($result.Comments)"
    }
}

# Exit with appropriate code
switch ($result.Status) {
    "PASS" { exit 0 }
    "FAIL" { exit 1 }
    "Not_Reviewed" { exit 2 }
    "N/A" { exit 2 }
    "ERROR" { exit 3 }
    default { exit 3 }
}
'''

    return script

def generate_python_script(check, product_name):
    """Generate Python check script"""
    stig_id = check.get('STIG ID', 'UNKNOWN')
    rule_title = check.get('Rule Title', '').strip()
    severity = check.get('Severity', 'medium')
    vuln_id = check.get('Group ID', '')
    rule_id = check.get('Rule ID', '')
    check_content = check.get('Check Content', '')

    # Extract registry information
    reg_key, reg_value_name, reg_value_type, expected_value = extract_registry_info(check_content)

    script = f'''#!/usr/bin/env python3
"""
{stig_id} - {rule_title}

STIG ID: {stig_id}
Rule Title: {rule_title}
Severity: {severity}
Vuln ID: {vuln_id}
Rule ID: {rule_id}

This script checks {product_name} configuration compliance.

Exit Codes:
    0 = PASS (Compliant)
    1 = FAIL (Non-Compliant)
    2 = N/A (Not Applicable)
    3 = ERROR (Script execution error)
'''

    if reg_key:
        script += f'''
Registry Check:
    Key: {reg_key}
'''
    if reg_value_name:
        script += f'''    Value: {reg_value_name}
'''
    if reg_value_type:
        script += f'''    Type: REG_{reg_value_type}
'''
    if expected_value:
        script += f'''    Expected: {expected_value}
'''

    script += '''"""

import argparse
import json
import sys
import winreg
from typing import Dict, Any

def check_registry_value(hive, key_path, value_name, expected_value, value_type):
    """
    Check a registry value against expected value.

    Args:
        hive: Registry hive (e.g., winreg.HKEY_CURRENT_USER)
        key_path: Registry key path
        value_name: Registry value name
        expected_value: Expected value
        value_type: Registry value type

    Returns:
        Tuple of (status, details)
    """
    try:
        key = winreg.OpenKey(hive, key_path, 0, winreg.KEY_READ)
        value, reg_type = winreg.QueryValueEx(key, value_name)
        winreg.CloseKey(key)

        # TODO: Implement proper value comparison based on type
        # This is a placeholder implementation

        return "Not_Reviewed", "Automated check not yet implemented"
    except FileNotFoundError:
        return "FAIL", f"Registry key or value not found: {key_path}\\\\{value_name}"
    except Exception as e:
        return "ERROR", f"Error reading registry: {str(e)}"

def perform_check(config: Dict[str, Any] = None) -> Dict[str, Any]:
    """
    Perform the STIG check.

    Args:
        config: Optional configuration dictionary

    Returns:
        Dictionary containing check results
    """
    result = {
        "STIG_ID": "''' + stig_id + '''",
        "Rule_Title": "''' + rule_title.replace('"', '\\"') + '''",
        "Severity": "''' + severity + '''",
        "Status": "Not_Reviewed",
        "Finding_Details": "",
        "Comments": ""
    }

    try:
'''

    if reg_key and reg_value_name:
        # Determine hive
        hive = 'winreg.HKEY_CURRENT_USER' if reg_key.startswith('HKCU') else 'winreg.HKEY_LOCAL_MACHINE'
        key_path = reg_key.split('\\\\', 1)[1] if '\\\\' in reg_key else reg_key

        script += f'''        # Registry check configuration
        hive = {hive}
        key_path = r"{key_path}"
        value_name = "{reg_value_name}"
'''
        if expected_value:
            script += f'''        expected_value = {expected_value}
'''
        if reg_value_type:
            script += f'''        value_type = "{reg_value_type}"
'''

        script += '''
        # TODO: Implement registry check
        # status, details = check_registry_value(hive, key_path, value_name, expected_value, value_type)
        # result["Status"] = status
        # result["Finding_Details"] = details

        # Placeholder
        result["Status"] = "Not_Reviewed"
        result["Comments"] = "Automated check not yet implemented - requires Office domain expertise"
        result["Finding_Details"] = "This check requires registry validation"
'''
    else:
        script += '''        # TODO: Implement check logic
        # This check requires manual implementation based on STIG requirements

        result["Status"] = "Not_Reviewed"
        result["Comments"] = "Automated check not yet implemented - requires Office domain expertise"
'''

    script += '''
    except Exception as e:
        result["Status"] = "ERROR"
        result["Finding_Details"] = f"Error: {str(e)}"
        result["Comments"] = "Script execution failed"

    return result

def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description="''' + f'{stig_id} - {rule_title}' + '''",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        '--config',
        help='Path to JSON configuration file',
        type=str
    )
    parser.add_argument(
        '--output-json',
        help='Output results in JSON format',
        action='store_true'
    )

    args = parser.parse_args()

    # Load custom configuration if provided
    config = None
    if args.config:
        try:
            with open(args.config, 'r') as f:
                config = json.load(f)
        except Exception as e:
            print(f"Warning: Failed to load configuration file: {e}", file=sys.stderr)

    # Perform the check
    result = perform_check(config)

    # Output results
    if args.output_json:
        print(json.dumps(result, indent=2))
    else:
        print(f"STIG ID: {result['STIG_ID']}")
        print(f"Status: {result['Status']}")
        print(f"Finding Details: {result['Finding_Details']}")
        if result['Comments']:
            print(f"Comments: {result['Comments']}")

    # Exit with appropriate code
    exit_codes = {
        "PASS": 0,
        "FAIL": 1,
        "Not_Reviewed": 2,
        "N/A": 2,
        "ERROR": 3
    }
    sys.exit(exit_codes.get(result['Status'], 3))

if __name__ == "__main__":
    main()
'''

    return script

def generate_readme(product_config, check_count):
    """Generate README.md for Office STIG framework"""
    display_name = product_config['display_name']
    short_name = product_config['short_name']

    readme = f'''# {display_name} STIG Automation Framework

## Overview

This directory contains automated compliance check scripts for the {display_name} Security Technical Implementation Guide (STIG).

**Total Checks:** {check_count}

## Platform Requirements

- **Operating System:** Windows
- **Office Version:** {short_name}
- **PowerShell:** 5.1 or higher (for .ps1 scripts)
- **Python:** 3.6 or higher (for .py fallback scripts)

## Office Installation Detection

Before running checks, ensure that {short_name} is installed on the system. Checks primarily validate:
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
.\\DTOO182.ps1

# Check with custom configuration
.\\DTOO182.ps1 -Config custom_config.json

# Output in JSON format
.\\DTOO182.ps1 -OutputJson

# Display help
.\\DTOO182.ps1 -Help
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
Get-ChildItem -Filter "DTOO*.ps1" | ForEach-Object {{
    $result = & $_.FullName -OutputJson | ConvertFrom-Json
    [PSCustomObject]@{{
        Check = $_.BaseName
        Status = $result.Status
        Details = $result.Finding_Details
    }}
}} | Export-Csv -Path "office_stig_results.csv" -NoTypeInformation
```

## Registry Key Reference

Most {short_name} STIG checks validate Windows Registry settings. Common registry locations include:

### User Configuration Settings
- `HKCU\\Software\\Policies\\Microsoft\\Office\\16.0\\common\\`
- `HKCU\\Software\\Policies\\Microsoft\\Office\\16.0\\common\\security\\`
- `HKCU\\Software\\Policies\\Microsoft\\Office\\16.0\\common\\trustcenter\\`

### Application-Specific Settings
- Excel: `HKCU\\Software\\Policies\\Microsoft\\Office\\16.0\\excel\\`
- Word: `HKCU\\Software\\Policies\\Microsoft\\Office\\16.0\\word\\`
- PowerPoint: `HKCU\\Software\\Policies\\Microsoft\\Office\\16.0\\powerpoint\\`
- Outlook: `HKCU\\Software\\Policies\\Microsoft\\Office\\16.0\\outlook\\`

### Machine-Level Settings
- `HKLM\\Software\\Policies\\Microsoft\\Office\\16.0\\`

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
{{
  "registry_overrides": {{
    "custom_key": "HKCU\\\\Software\\\\Custom\\\\Path",
    "custom_value": "CustomValue"
  }},
  "thresholds": {{
    "custom_threshold": 100
  }},
  "exceptions": [
    "system1.example.com",
    "system2.example.com"
  ]
}}
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
Most {short_name} STIG checks are **highly automatable** because they primarily involve:
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
'''

    return readme

def process_office_product(base_dir, product_key, product_config):
    """Process a single Office product"""
    json_file = os.path.join(base_dir, product_config['json_file'])
    output_dir = os.path.join(base_dir, 'checks', 'application', product_config['dir_name'])

    print(f"\n{'='*80}")
    print(f"Processing: {product_config['display_name']}")
    print(f"{'='*80}")

    # Create output directory
    os.makedirs(output_dir, exist_ok=True)
    print(f"Created directory: {output_dir}")

    # Load checks from JSON
    with open(json_file, 'r', encoding='utf-8') as f:
        checks = json.load(f)

    print(f"Loaded {len(checks)} checks from {json_file}")

    # Generate scripts for each check
    script_count = 0
    for check in checks:
        stig_id = check.get('STIG ID', 'UNKNOWN')
        safe_stig_id = sanitize_filename(stig_id)

        # Generate PowerShell script
        ps_script = generate_powershell_script(check, product_config['display_name'])
        ps_file = os.path.join(output_dir, f"{safe_stig_id}.ps1")
        with open(ps_file, 'w', encoding='utf-8') as f:
            f.write(ps_script)

        # Generate Python script
        py_script = generate_python_script(check, product_config['display_name'])
        py_file = os.path.join(output_dir, f"{safe_stig_id}.py")
        with open(py_file, 'w', encoding='utf-8') as f:
            f.write(py_script)

        script_count += 2

    print(f"Generated {script_count} scripts ({len(checks)} PowerShell + {len(checks)} Python)")

    # Generate README
    readme = generate_readme(product_config, len(checks))
    readme_file = os.path.join(output_dir, 'README.md')
    with open(readme_file, 'w', encoding='utf-8') as f:
        f.write(readme)
    print(f"Generated README: {readme_file}")

    return len(checks), script_count

def generate_automation_report(base_dir, product_key, product_config, check_count):
    """Generate automation analysis report"""
    json_file = os.path.join(base_dir, product_config['json_file'])

    # Load checks
    with open(json_file, 'r', encoding='utf-8') as f:
        checks = json.load(f)

    # Analyze automation feasibility
    registry_checks = 0
    file_checks = 0
    config_checks = 0
    manual_checks = 0

    for check in checks:
        check_content = check.get('Check Content', '')
        if 'registry' in check_content.lower() or 'HKCU' in check_content or 'HKLM' in check_content:
            registry_checks += 1
        elif 'file' in check_content.lower():
            file_checks += 1
        elif 'policy' in check_content.lower() or 'group policy' in check_content.lower():
            config_checks += 1
        else:
            manual_checks += 1

    # Calculate automation percentages
    automatable = registry_checks + file_checks + config_checks
    automation_percentage = (automatable / check_count * 100) if check_count > 0 else 0

    report = f'''# {product_config['display_name']} STIG Automation Analysis

**Report Generated:** 2025-11-22
**STIG Framework Version:** 3.0
**Total Checks:** {check_count}

## Executive Summary

This report analyzes the automation feasibility for {product_config['display_name']} STIG compliance checks. The analysis examines each check requirement to determine the level of automation possible using PowerShell and Python scripts.

## Automation Statistics

| Metric | Count | Percentage |
|--------|-------|------------|
| Total Checks | {check_count} | 100% |
| Registry-Based Checks | {registry_checks} | {registry_checks/check_count*100:.1f}% |
| File-Based Checks | {file_checks} | {file_checks/check_count*100:.1f}% |
| Configuration Checks | {config_checks} | {config_checks/check_count*100:.1f}% |
| Manual Validation Required | {manual_checks} | {manual_checks/check_count*100:.1f}% |
| **Automatable Checks** | **{automatable}** | **{automation_percentage:.1f}%** |

## Check Category Breakdown

### Registry-Based Checks ({registry_checks})
These checks validate Windows Registry settings for Office applications. They are highly automatable using PowerShell's `Get-ItemProperty` cmdlet or Python's `winreg` module.

**Common Registry Locations:**
- `HKCU\\Software\\Policies\\Microsoft\\Office\\16.0\\`
- `HKLM\\Software\\Policies\\Microsoft\\Office\\16.0\\`
- Application-specific paths (Excel, Word, PowerPoint, Outlook)

**Automation Level:** 95-100% (Full automation possible)

### File-Based Checks ({file_checks})
These checks verify file existence, versions, or permissions related to Office installations.

**Automation Level:** 90-95% (High automation possible)

### Configuration Checks ({config_checks})
These checks validate Group Policy settings and Trust Center configurations.

**Automation Level:** 85-90% (Good automation possible)

### Manual Checks ({manual_checks})
These checks may require user interaction, visual inspection, or complex validation logic.

**Automation Level:** 40-60% (Partial automation possible)

## Severity Distribution
'''

    # Count by severity
    severity_counts = {'high': 0, 'medium': 0, 'low': 0}
    for check in checks:
        severity = check.get('Severity', 'medium').lower()
        severity_counts[severity] = severity_counts.get(severity, 0) + 1

    report += f'''
| Severity | Count | Percentage |
|----------|-------|------------|
| High | {severity_counts.get('high', 0)} | {severity_counts.get('high', 0)/check_count*100:.1f}% |
| Medium | {severity_counts.get('medium', 0)} | {severity_counts.get('medium', 0)/check_count*100:.1f}% |
| Low | {severity_counts.get('low', 0)} | {severity_counts.get('low', 0)/check_count*100:.1f}% |

## Implementation Approach

### Phase 1: Registry Validation (High Priority)
Implement automated checks for all registry-based requirements:
- Read registry keys using PowerShell or Python
- Compare actual values against expected STIG values
- Report compliance status

### Phase 2: File and Installation Checks (Medium Priority)
Implement automated checks for:
- Office installation detection
- File version verification
- Installation path validation

### Phase 3: Complex Configuration Checks (Lower Priority)
Implement checks requiring:
- Group Policy parsing
- Trust Center setting validation
- Multi-step verification processes

## Tool Priority

1. **PowerShell** (Primary)
   - Native Windows integration
   - Excellent registry access
   - Strong COM object support for Office automation
   - Built-in cmdlets for Windows management

2. **Python** (Fallback)
   - Cross-platform compatibility
   - Robust error handling
   - Extensive library support
   - Suitable for systems without PowerShell

## Sample Check Implementation

### High-Automation Check Example: DTOO182
**Title:** Help Improve Proofing Tools feature must be configured
**Type:** Registry Check
**Automation:** 100%

```powershell
$regPath = "HKCU:\\Software\\Policies\\Microsoft\\Office\\16.0\\common\\ptwatson"
$value = Get-ItemProperty -Path $regPath -Name "PTWOptIn" -ErrorAction SilentlyContinue
if ($value.PTWOptIn -eq 0) {{ "PASS" }} else {{ "FAIL" }}
```

## Recommendations

1. **Prioritize Registry Checks:** Focus on the {registry_checks} registry-based checks first, as they offer the highest automation ROI.

2. **Leverage Group Policy:** Many Office STIG requirements are enforced via GPO. Consider using GPO compliance reports in conjunction with these scripts.

3. **Test in Controlled Environment:** Validate all automated checks in a test environment before production deployment.

4. **Handle Edge Cases:** Implement robust error handling for missing registry keys, Office not installed, or permission issues.

5. **Document Deviations:** Any check that cannot be fully automated should document the manual steps required.

## Office-Specific Considerations

### Trust Center Settings
Many checks validate Trust Center configurations, which are stored in registry but may require Office to be running to fully validate.

### Version Detection
Some checks are version-specific. Ensure scripts detect Office version before applying checks.

### User vs. Machine Policies
Distinguish between HKCU (user-level) and HKLM (machine-level) policies. Some checks require both.

### ActiveX and Add-ins
Checks involving ActiveX controls and add-ins may require COM automation.

## Conclusion

The {product_config['display_name']} STIG framework shows **{automation_percentage:.1f}% automation feasibility**, with {registry_checks} checks being primarily registry-based. This high automation potential makes it an excellent candidate for automated compliance scanning.

### Implementation Status
- **Framework:** Complete (PowerShell and Python scripts generated)
- **Check Logic:** Stub implementations with TODO placeholders
- **Domain Expertise Required:** Yes (Office security configurations)
- **Testing Required:** Yes (Validate against actual Office installations)

### Next Steps
1. Review STIG requirements for each check
2. Implement registry validation logic
3. Test against compliant and non-compliant systems
4. Document findings and edge cases
5. Integrate into compliance scanning workflow

---
*Report generated by Microsoft Office STIG Automation Framework Generator v3.0*
'''

    return report

def main():
    """Main execution function"""
    base_dir = '/home/user/STIGcheckScripts'
    reports_dir = os.path.join(base_dir, 'reports')
    os.makedirs(reports_dir, exist_ok=True)

    print("="*80)
    print("Microsoft Office STIG Automation Framework Generator")
    print("="*80)

    total_checks = 0
    total_scripts = 0

    # Process each Office product
    for product_key, product_config in OFFICE_PRODUCTS.items():
        check_count, script_count = process_office_product(base_dir, product_key, product_config)
        total_checks += check_count
        total_scripts += script_count

        # Generate automation analysis report
        report = generate_automation_report(base_dir, product_key, product_config, check_count)
        report_file = os.path.join(reports_dir, f"{product_config['dir_name']}_stig_automation_analysis.md")
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write(report)
        print(f"Generated report: {report_file}")

    print(f"\n{'='*80}")
    print("Summary")
    print(f"{'='*80}")
    print(f"Total Office Products: {len(OFFICE_PRODUCTS)}")
    print(f"Total Checks: {total_checks}")
    print(f"Total Scripts Generated: {total_scripts}")
    print(f"Total Files Created: {total_scripts + len(OFFICE_PRODUCTS) + len(OFFICE_PRODUCTS)}")  # scripts + READMEs + reports
    print(f"{'='*80}")

if __name__ == '__main__':
    main()
