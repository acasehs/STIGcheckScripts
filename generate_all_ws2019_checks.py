#!/usr/bin/env python3
"""
Generate all Windows Server 2019 v2r7 STIG check scripts

This script automatically generates PowerShell and Python check scripts for all
Windows Server 2022 STIG checks based on the analyzed check data.

Usage:
    python3 generate_all_ws2019_checks.py
    python3 generate_all_ws2019_checks.py --dry-run
    python3 generate_all_ws2019_checks.py --limit 10  # Generate only first 10
"""

import json
import os
import argparse
from pathlib import Path
from datetime import datetime
import re


def categorize_check(check):
    """Determine the type of Windows check based on content"""
    check_content = check.get('Check Content', '').lower()
    rule_title = check.get('Rule Title', '').lower()

    # Registry checks
    if any(term in check_content for term in ['registry', 'hkey', 'hklm', 'hkcu', 'reg query']):
        return 'registry', 'value'

    # Group Policy checks
    if any(term in check_content for term in ['group policy', 'gpo', 'gpedit']):
        return 'group_policy', 'setting'

    # Service checks
    if any(term in check_content for term in ['get-service', 'sc query', 'service']) and 'service' in rule_title:
        return 'service', 'status'

    # User/Group checks
    if any(term in check_content for term in ['get-localuser', 'get-localgroup', 'net user', 'net localgroup']):
        return 'user_group', 'membership'

    # Audit Policy checks
    if any(term in check_content for term in ['auditpol', 'audit policy']):
        return 'audit_policy', 'setting'

    # Security Option checks
    if 'secedit' in check_content or 'security option' in check_content:
        return 'security_option', 'setting'

    # PowerShell command checks
    if 'get-' in check_content or 'powershell' in check_content:
        return 'powershell_command', 'output'

    # Default to generic command
    return 'command', 'generic'


def generate_powershell_registry_check(check, action='value'):
    """Generate PowerShell script for registry check"""
    vuln_id = check['Vuln ID']
    stig_id = check['STIG ID']
    severity = check['Severity']
    rule_title = check['Rule Title']

    # Try to extract registry path and value name
    check_content = check.get('Check Content', '')

    # Common registry paths
    registry_path = 'HKLM:\\SOFTWARE\\Policies'  # Default placeholder
    value_name = 'ValueName'
    expected_value = 1  # Default numeric value

    # Try to extract registry path
    path_match = re.search(r'(HKLM|HKCU|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER)[:\\\\]+([^\\s]+)', check_content, re.IGNORECASE)
    if path_match:
        hive = path_match.group(1).upper()
        path = path_match.group(2)
        # Convert to PowerShell format
        if hive.startswith('HKEY_LOCAL_MACHINE'):
            registry_path = f"HKLM:\\{path}"
        elif hive.startswith('HKEY_CURRENT_USER'):
            registry_path = f"HKCU:\\{path}"
        else:
            registry_path = f"{hive}:\\{path}"

    script = f'''<#
.SYNOPSIS
    STIG Check: {vuln_id}

.DESCRIPTION
    Severity: {severity}
    Rule Title: {rule_title}
    STIG ID: {stig_id}
    STIG Version: Windows Server 2019 v2r7
    Requires Elevation: Yes (registry read may require admin)
    Third-Party Tools: None (uses PowerShell Get-ItemProperty)

.NOTES
    AUTO-GENERATED: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
    Based on template: registry check

.PARAMETER ConfigFile
    Path to JSON configuration file

.PARAMETER OutputJson
    Path to output JSON results file

.EXAMPLE
    .\\{vuln_id}.ps1
    .\\{vuln_id}.ps1 -ConfigFile stig-config.json
    .\\{vuln_id}.ps1 -ConfigFile stig-config.json -OutputJson results.json
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$ConfigFile,

    [Parameter(Mandatory=$false)]
    [string]$OutputJson,

    [Parameter(Mandatory=$false)]
    [switch]$Force
)

# Global variables
$VulnID = "{vuln_id}"
$Severity = "{severity}"
$StigID = "{stig_id}"
$RuleTitle = "{rule_title[:200]}"
$StigVersion = "Windows Server 2019 v2r7"

# TODO: Extract actual registry path and value from check content
$RegistryPath = "{registry_path}"
$ValueName = "{value_name}"
$ExpectedValue = {expected_value}

$Status = "Not Checked"
$FindingDetails = @()
$Timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")

# Load configuration if provided
if ($ConfigFile -and (Test-Path $ConfigFile)) {{
    try {{
        $Config = Get-Content $ConfigFile | ConvertFrom-Json
        Write-Host "INFO: Loaded configuration from $ConfigFile"
    }} catch {{
        Write-Warning "Failed to load configuration file: $_"
    }}
}}

# Function to check registry value
function Test-RegistryValue {{
    param(
        [string]$Path,
        [string]$Name
    )

    try {{
        $value = Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop
        return @{{
            Exists = $true
            Value = $value.$Name
        }}
    }} catch {{
        return @{{
            Exists = $false
            Value = $null
        }}
    }}
}}

# Main check logic
try {{
    $regCheck = Test-RegistryValue -Path $RegistryPath -Name $ValueName

    if ($regCheck.Exists) {{
        if ($regCheck.Value -eq $ExpectedValue) {{
            $Status = "NotAFinding"
            $FindingDetails += @{{
                registry_path = $RegistryPath
                value_name = $ValueName
                actual_value = $regCheck.Value
                expected_value = $ExpectedValue
                status = "PASS"
                reason = "Registry value matches expected configuration"
            }}
            $exitCode = 0
        }} else {{
            $Status = "Open"
            $FindingDetails += @{{
                registry_path = $RegistryPath
                value_name = $ValueName
                actual_value = $regCheck.Value
                expected_value = $ExpectedValue
                status = "FAIL"
                reason = "Registry value does not match expected configuration"
            }}
            $exitCode = 1
        }}
    }} else {{
        $Status = "Open"
        $FindingDetails += @{{
            registry_path = $RegistryPath
            value_name = $ValueName
            status = "FAIL"
            reason = "Registry value does not exist"
        }}
        $exitCode = 1
    }}
}} catch {{
    $Status = "Error"
    $FindingDetails += @{{
        error = $_.Exception.Message
    }}
    $exitCode = 3
}}

# Output results
$result = @{{
    vuln_id = $VulnID
    severity = $Severity
    stig_id = $StigID
    stig_version = $StigVersion
    rule_title = $RuleTitle
    status = $Status
    finding_details = $FindingDetails
    timestamp = $Timestamp
    requires_elevation = $true
    third_party_tools = "None (uses PowerShell)"
    check_method = "PowerShell - Get-ItemProperty"
    config_file = if ($ConfigFile) {{ $ConfigFile }} else {{ "None (using defaults)" }}
    exit_code = $exitCode
}}

if ($OutputJson) {{
    $result | ConvertTo-Json -Depth 10 | Out-File -FilePath $OutputJson -Encoding UTF8
    Write-Host "Results written to: $OutputJson"
}}

# Print human-readable results
Write-Host ""
Write-Host "=" * 80
Write-Host "STIG Check: $VulnID - $StigID"
Write-Host "STIG Version: $StigVersion"
Write-Host "Severity: $($Severity.ToUpper())"
Write-Host "=" * 80
Write-Host "Rule: $RuleTitle"
Write-Host "Status: $Status"
Write-Host "Timestamp: $Timestamp"
Write-Host ""

exit $exitCode
'''

    return script


def generate_python_registry_check(check, action='value'):
    """Generate Python script for registry check (Windows)"""
    vuln_id = check['Vuln ID']
    stig_id = check['STIG ID']
    severity = check['Severity']
    rule_title = check['Rule Title']

    script = f'''#!/usr/bin/env python3
"""
STIG Check: {vuln_id}
Severity: {severity}
Rule Title: {rule_title}
STIG ID: {stig_id}
STIG Version: Windows Server 2019 v2r7

AUTO-GENERATED: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
Based on template: registry check

NOTE: This script requires the winreg module (Windows only)
"""

import sys
import argparse

try:
    import winreg
except ImportError:
    print("ERROR: This script requires Windows (winreg module)")
    sys.exit(3)


def check_registry_value(hive, key_path, value_name):
    """Check if a registry value exists and return its value"""
    try:
        key = winreg.OpenKey(hive, key_path, 0, winreg.KEY_READ)
        value, value_type = winreg.QueryValueEx(key, value_name)
        winreg.CloseKey(key)
        return {{'exists': True, 'value': value, 'type': value_type}}
    except FileNotFoundError:
        return {{'exists': False, 'value': None, 'type': None}}
    except Exception as e:
        return {{'exists': False, 'value': None, 'type': None, 'error': str(e)}}


def main():
    parser = argparse.ArgumentParser(description='STIG Check {vuln_id}')
    parser.add_argument('--config', help='Configuration file (JSON)')
    parser.add_argument('--output-json', help='Output results to JSON file')
    args = parser.parse_args()

    # TODO: Extract actual registry path and value
    hive = winreg.HKEY_LOCAL_MACHINE
    key_path = r"SOFTWARE\\Policies"
    value_name = "ValueName"
    expected_value = 1

    result = check_registry_value(hive, key_path, value_name)

    if result['exists']:
        if result['value'] == expected_value:
            print(f"PASS: Registry value matches expected ({{expected_value}})")
            return 0
        else:
            print(f"FAIL: Registry value is {{{{result['value']}}}}, expected {{expected_value}}")
            return 1
    else:
        print(f"FAIL: Registry value does not exist")
        return 1


if __name__ == '__main__':
    sys.exit(main())
'''

    return script


def generate_powershell_service_check(check, action='status'):
    """Generate PowerShell script for service check"""
    vuln_id = check['Vuln ID']
    stig_id = check['STIG ID']
    severity = check['Severity']
    rule_title = check['Rule Title']

    script = f'''<#
.SYNOPSIS
    STIG Check: {vuln_id}

.DESCRIPTION
    Severity: {severity}
    Rule Title: {rule_title}
    STIG ID: {stig_id}
    STIG Version: Windows Server 2019 v2r7

.NOTES
    AUTO-GENERATED: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
    Based on template: service check
#>

[CmdletBinding()]
param(
    [string]$ConfigFile,
    [string]$OutputJson
)

$VulnID = "{vuln_id}"
$Severity = "{severity}"
$StigID = "{stig_id}"
$Status = "Not Checked"

# TODO: Extract actual service name
$ServiceName = "SERVICE_NAME"

try {{
    $service = Get-Service -Name $ServiceName -ErrorAction Stop

    if ($service.Status -eq 'Running') {{
        $Status = "NotAFinding"
        Write-Host "PASS: Service $ServiceName is running"
        exit 0
    }} else {{
        $Status = "Open"
        Write-Host "FAIL: Service $ServiceName is not running (Status: $($service.Status))"
        exit 1
    }}
}} catch {{
    Write-Host "ERROR: Could not check service $ServiceName : $_"
    exit 3
}}
'''

    return script


def generate_powershell_generic_check(check):
    """Generate generic PowerShell check template"""
    vuln_id = check['Vuln ID']
    stig_id = check['STIG ID']
    severity = check['Severity']
    rule_title = check['Rule Title']

    script = f'''<#
.SYNOPSIS
    STIG Check: {vuln_id}

.DESCRIPTION
    Severity: {severity}
    Rule Title: {rule_title}
    STIG ID: {stig_id}
    STIG Version: Windows Server 2019 v2r7

.NOTES
    AUTO-GENERATED: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
    This is a generic template - implementation required
#>

[CmdletBinding()]
param(
    [string]$ConfigFile,
    [string]$OutputJson
)

# TODO: Implement check logic for {vuln_id}
Write-Host "TODO: Implement check for {vuln_id}"
Write-Host "Rule: {rule_title[:100]}"
exit 3
'''

    return script


def main():
    parser = argparse.ArgumentParser(
        description='Generate all Windows Server 2019 v2r7 STIG checks',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    parser.add_argument('--dry-run', action='store_true',
                       help='Preview what would be generated without creating files')
    parser.add_argument('--limit', type=int,
                       help='Only generate first N checks (for testing)')
    parser.add_argument('--output-dir', default='checks/os/windows_server_2019_v2r7',
                       help='Output directory for checks')
    parser.add_argument('--skip-existing', action='store_true',
                       help='Skip checks that already exist')

    args = parser.parse_args()

    # Load analyzed checks
    analyzed_file = Path(args.output_dir) / 'analyzed_checks.json'

    if not analyzed_file.exists():
        print(f"Error: {analyzed_file} not found")
        print("Run generate_stig_analysis.py first to analyze the STIG")
        return 1

    with open(analyzed_file, 'r') as f:
        checks = json.load(f)

    print(f"Loaded {len(checks)} checks from {analyzed_file}")

    # Apply limit if specified
    if args.limit:
        checks = checks[:args.limit]
        print(f"Limiting to first {args.limit} checks")

    # Create output directory
    output_dir = Path(args.output_dir)
    if not args.dry_run:
        output_dir.mkdir(parents=True, exist_ok=True)

    # Statistics
    stats = {
        'total': len(checks),
        'generated': 0,
        'skipped': 0,
        'failed': 0,
        'by_type': {}
    }

    # Generate checks
    for check in checks:
        vuln_id = check.get('Vuln ID')
        if not vuln_id:
            stats['failed'] += 1
            continue

        # Skip if already exists
        ps1_file = output_dir / f"{vuln_id}.ps1"
        python_file = output_dir / f"{vuln_id}.py"

        if args.skip_existing and (ps1_file.exists() or python_file.exists()):
            stats['skipped'] += 1
            if not args.dry_run:
                print(f"  Skipping {vuln_id} (already exists)")
            continue

        # Determine check type
        check_type, action = categorize_check(check)
        stats['by_type'][check_type] = stats['by_type'].get(check_type, 0) + 1

        if args.dry_run:
            print(f"Would generate: {vuln_id} ({check_type}/{action})")
            stats['generated'] += 1
            continue

        # Generate scripts based on type
        try:
            if check_type == 'registry':
                powershell_script = generate_powershell_registry_check(check, action)
                python_script = generate_python_registry_check(check, action)
            elif check_type == 'service':
                powershell_script = generate_powershell_service_check(check, action)
                python_script = "# TODO: Python service check for Windows\n"
            else:
                # Generic placeholder
                powershell_script = generate_powershell_generic_check(check)
                python_script = f"#!/usr/bin/env python3\n# TODO: Implement {vuln_id}\n"

            # Write PowerShell script
            with open(ps1_file, 'w', encoding='utf-8') as f:
                f.write(powershell_script)
            # Note: PowerShell scripts don't need chmod on Windows

            # Write Python script
            with open(python_file, 'w', encoding='utf-8') as f:
                f.write(python_script)
            if os.name != 'nt':  # Only chmod on Unix-like systems
                os.chmod(python_file, 0o755)

            stats['generated'] += 1
            print(f"  Generated: {vuln_id} ({check_type})")

        except Exception as e:
            print(f"  ERROR generating {vuln_id}: {e}")
            stats['failed'] += 1

    # Print summary
    print(f"\n{'='*80}")
    print(f"Generation Summary")
    print(f"{'='*80}")
    print(f"Total checks:     {stats['total']}")
    print(f"Generated:        {stats['generated']}")
    print(f"Skipped:          {stats['skipped']}")
    print(f"Failed:           {stats['failed']}")
    print(f"\nBy Check Type:")
    for check_type, count in sorted(stats['by_type'].items()):
        print(f"  {check_type}: {count}")

    if args.dry_run:
        print(f"\n(DRY RUN - No files were created)")

    return 0


if __name__ == '__main__':
    exit(main())
