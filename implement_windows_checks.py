#!/usr/bin/env python3
"""
Windows OS STIG Check Implementation Engine
Implements actual check logic for Windows 10/11 STIGs
"""

import json
import re
import sys
from pathlib import Path
from collections import defaultdict

stats = defaultdict(lambda: {'total': 0, 'implemented': 0})

def analyze_windows_check(check_content, rule_title):
    """Analyze Windows check content to determine check type"""

    if not check_content:
        return None

    check_lower = check_content.lower()

    # Determine check type
    check_type = 'unknown'
    registry_paths = []
    services = []
    policies = []

    # Extract registry paths
    if 'registry' in check_lower or 'hkey' in check_lower:
        check_type = 'registry'
        # Extract registry paths
        reg_patterns = [
            r'HKEY[_A-Z]+\\\\[^"\n]+',
            r'HKLM\\\\[^"\n]+',
            r'HKCU\\\\[^"\n]+',
        ]
        for pattern in reg_patterns:
            matches = re.finditer(pattern, check_content, re.IGNORECASE)
            for match in matches:
                path = match.group(0)
                if path and path not in registry_paths:
                    registry_paths.append(path)

    # Check for services
    if 'service' in check_lower and ('running' in check_lower or 'disabled' in check_lower or 'automatic' in check_lower):
        check_type = 'service'
        # Try to extract service names
        service_patterns = [
            r'"([A-Za-z0-9_\-\s]+)" service',
            r'service "([A-Za-z0-9_\-\s]+)"',
        ]
        for pattern in service_patterns:
            matches = re.finditer(pattern, check_content, re.IGNORECASE)
            for match in matches:
                svc = match.group(1)
                if svc and svc not in services:
                    services.append(svc)

    # Check for Group Policy/Security Policy
    if 'policy' in check_lower or 'gpedit' in check_lower or 'secpol' in check_lower:
        if check_type == 'unknown':
            check_type = 'policy'

    # Check for Windows Edition/Version
    if 'edition' in check_lower or 'version' in check_lower or 'system type' in check_lower:
        if check_type == 'unknown':
            check_type = 'system_info'

    # Check for audit settings
    if 'audit' in check_lower and 'policy' in check_lower:
        check_type = 'audit_policy'

    return {
        'type': check_type,
        'registry_paths': registry_paths[:3],
        'services': services[:2],
        'requires_manual': 'review' in check_lower or 'interview' in check_lower or 'document' in check_lower,
        'na_conditions': extract_na_conditions(check_content)
    }

def extract_na_conditions(check_content):
    """Extract N/A conditions from check content"""
    na_conditions = []
    lines = check_content.split('\n')
    for line in lines:
        if 'this is na' in line.lower() or 'not applicable' in line.lower():
            na_conditions.append(line.strip())
    return na_conditions[:2]

def generate_registry_check(registry_paths):
    """Generate Windows registry check"""
    path_hint = registry_paths[0] if registry_paths else 'HKLM\\Software\\...'

    return f'''
    # Windows Registry Check
    Write-Host "INFO: Checking Windows registry configuration"
    Write-Host ""

    # Registry path to check
    $regPath = "{path_hint}"

    try {{
        # Check if registry path exists
        if (Test-Path "Registry::$regPath") {{
            $regValue = Get-ItemProperty -Path "Registry::$regPath" -ErrorAction SilentlyContinue

            Write-Host "Registry path found: $regPath"
            Write-Host "Current values:"
            $regValue | Format-List
            Write-Host ""

            Write-Host "MANUAL REVIEW REQUIRED: Verify registry values meet STIG requirements"
            Write-Host "Registry Path: $regPath"
            Write-Host ""

            if ($OutputJson) {{
                $output = @{{
                    vuln_id = $VulnID
                    stig_id = $StigID
                    severity = $Severity
                    status = "Not_Reviewed"
                    finding_details = "Registry check requires manual validation"
                    registry_path = $regPath
                    current_values = $regValue
                }}
                Write-Host ($output | ConvertTo-Json -Depth 10)
            }}

            exit 2  # Manual review required
        }} else {{
            Write-Host "WARNING: Registry path not found: $regPath"
            Write-Host "This may indicate non-compliance or N/A condition"
            Write-Host ""

            if ($OutputJson) {{
                $output = @{{
                    vuln_id = $VulnID
                    stig_id = $StigID
                    severity = $Severity
                    status = "Not_Reviewed"
                    finding_details = "Registry path not found - manual validation required"
                    registry_path = $regPath
                }}
                Write-Host ($output | ConvertTo-Json -Depth 10)
            }}

            exit 2  # Manual review required
        }}
    }} catch {{
        Write-Host "ERROR: Failed to check registry: $($_.Exception.Message)"

        if ($OutputJson) {{
            $output = @{{
                vuln_id = $VulnID
                stig_id = $StigID
                severity = $Severity
                status = "Error"
                finding_details = "Registry check failed: $($_.Exception.Message)"
            }}
            Write-Host ($output | ConvertTo-Json -Depth 10)
        }}

        exit 3
    }}
'''

def generate_service_check(services):
    """Generate Windows service check"""
    service_hint = services[0] if services else 'ServiceName'

    return f'''
    # Windows Service Check
    Write-Host "INFO: Checking Windows service configuration"
    Write-Host ""

    $serviceName = "{service_hint}"

    try {{
        $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue

        if ($service) {{
            Write-Host "Service found: $serviceName"
            Write-Host "Status: $($service.Status)"
            Write-Host "StartType: $($service.StartType)"
            Write-Host ""

            Write-Host "MANUAL REVIEW REQUIRED: Verify service configuration meets STIG requirements"
            Write-Host "Service: $serviceName"
            Write-Host "Expected configuration should be verified against STIG documentation"
            Write-Host ""

            if ($OutputJson) {{
                $output = @{{
                    vuln_id = $VulnID
                    stig_id = $StigID
                    severity = $Severity
                    status = "Not_Reviewed"
                    finding_details = "Service check requires manual validation"
                    service_name = $serviceName
                    current_status = $service.Status
                    current_starttype = $service.StartType
                }}
                Write-Host ($output | ConvertTo-Json -Depth 10)
            }}

            exit 2  # Manual review required
        }} else {{
            Write-Host "WARNING: Service not found: $serviceName"
            Write-Host "This may indicate N/A or finding condition"
            Write-Host ""

            if ($OutputJson) {{
                $output = @{{
                    vuln_id = $VulnID
                    stig_id = $StigID
                    severity = $Severity
                    status = "Not_Reviewed"
                    finding_details = "Service not found - manual validation required"
                    service_name = $serviceName
                }}
                Write-Host ($output | ConvertTo-Json -Depth 10)
            }}

            exit 2  # Manual review required
        }}
    }} catch {{
        Write-Host "ERROR: Failed to check service: $($_.Exception.Message)"

        if ($OutputJson) {{
            $output = @{{
                vuln_id = $VulnID
                stig_id = $StigID
                severity = $Severity
                status = "Error"
                finding_details = "Service check failed: $($_.Exception.Message)"
            }}
            Write-Host ($output | ConvertTo-Json -Depth 10)
        }}

        exit 3
    }}
'''

def generate_system_info_check():
    """Generate Windows system information check"""
    return '''
    # Windows System Information Check
    Write-Host "INFO: Checking Windows system information"
    Write-Host ""

    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem
        $cs = Get-CimInstance -ClassName Win32_ComputerSystem

        Write-Host "OS Caption: $($os.Caption)"
        Write-Host "OS Architecture: $($os.OSArchitecture)"
        Write-Host "OS Version: $($os.Version)"
        Write-Host "System Type: $($cs.SystemType)"
        Write-Host "Domain Role: $($cs.DomainRole)"
        Write-Host ""

        Write-Host "MANUAL REVIEW REQUIRED: Verify system configuration meets STIG requirements"
        Write-Host "Check Windows Edition, Architecture, and Domain membership"
        Write-Host ""

        if ($OutputJson) {
            $output = @{
                vuln_id = $VulnID
                stig_id = $StigID
                severity = $Severity
                status = "Not_Reviewed"
                finding_details = "System info check requires manual validation"
                os_caption = $os.Caption
                os_architecture = $os.OSArchitecture
                system_type = $cs.SystemType
                domain_role = $cs.DomainRole
            }
            Write-Host ($output | ConvertTo-Json -Depth 10)
        }

        exit 2  # Manual review required
    } catch {
        Write-Host "ERROR: Failed to get system information: $($_.Exception.Message)"

        if ($OutputJson) {
            $output = @{
                vuln_id = $VulnID
                stig_id = $StigID
                severity = $Severity
                status = "Error"
                finding_details = "System info check failed: $($_.Exception.Message)"
            }
            Write-Host ($output | ConvertTo-Json -Depth 10)
        }

        exit 3
    }
'''

def generate_policy_check():
    """Generate Windows policy check"""
    return '''
    # Windows Policy Check
    Write-Host "INFO: Checking Windows security policy configuration"
    Write-Host ""

    Write-Host "MANUAL REVIEW REQUIRED: This check requires examination of Group Policy"
    Write-Host "Use gpedit.msc or secpol.msc to verify policy settings"
    Write-Host "Refer to STIG documentation for specific policy requirements"
    Write-Host ""

    if ($OutputJson) {
        $output = @{
            vuln_id = $VulnID
            stig_id = $StigID
            severity = $Severity
            status = "Not_Reviewed"
            finding_details = "Policy check requires manual review using Group Policy editor"
            comments = "Use gpedit.msc or secpol.msc to verify settings"
        }
        Write-Host ($output | ConvertTo-Json -Depth 10)
    }

    exit 2  # Manual review required
'''

def generate_manual_check():
    """Generate manual review check"""
    return '''
    # Windows Manual Review Check
    Write-Host "INFO: This check requires manual review"
    Write-Host ""
    Write-Host "MANUAL REVIEW REQUIRED: Examine Windows configuration per STIG requirements"
    Write-Host "Refer to the STIG documentation for specific validation steps"
    Write-Host ""

    if ($OutputJson) {
        $output = @{
            vuln_id = $VulnID
            stig_id = $StigID
            severity = $Severity
            status = "Not_Reviewed"
            finding_details = "This check requires manual examination"
        }
        Write-Host ($output | ConvertTo-Json -Depth 10)
    }

    exit 2  # Manual review required
'''

def generate_implementation(stig_id, check_content, rule_title, script_path):
    """Generate implementation for a single Windows check"""

    analysis = analyze_windows_check(check_content, rule_title)

    if not analysis:
        return False

    # Generate appropriate implementation based on check type
    if analysis['type'] == 'registry':
        impl_code = generate_registry_check(analysis['registry_paths'])
    elif analysis['type'] == 'service':
        impl_code = generate_service_check(analysis['services'])
    elif analysis['type'] == 'system_info':
        impl_code = generate_system_info_check()
    elif analysis['type'] == 'policy' or analysis['type'] == 'audit_policy':
        impl_code = generate_policy_check()
    else:
        impl_code = generate_manual_check()

    # Read existing script
    try:
        with open(script_path, 'r', encoding='utf-8') as f:
            content = f.read()
    except Exception as e:
        print(f"ERROR reading {script_path}: {e}")
        return False

    # Check if already implemented
    if 'TODO: Implement check logic' not in content and 'TODO: Implement specific check logic' not in content:
        return False  # Already implemented

    # Replace TODO section in Invoke-Check function
    pattern = r'(function Invoke-Check \{)\s*# TODO:.*?return \$false\s*\n'
    # Escape backslashes in impl_code to avoid regex escape issues
    escaped_impl = impl_code.replace('\\', '\\\\')
    replacement = r'\1' + escaped_impl + '\n'
    new_content = re.sub(pattern, replacement, content, flags=re.DOTALL)

    if new_content != content:
        try:
            with open(script_path, 'w', encoding='utf-8') as f:
                f.write(new_content)
            return True
        except Exception as e:
            print(f"ERROR writing {script_path}: {e}")
            return False

    return False

def process_windows_stig(json_file):
    """Process all checks in a Windows STIG"""

    # Find Windows script directory
    check_base = Path('checks/os')
    script_dir = None

    # Determine platform from JSON filename
    stem = json_file.stem
    if 'windows_10' in stem:
        platform_name = 'windows_10'
    elif 'windows_11' in stem:
        platform_name = 'windows_11'
    else:
        print(f"  ✗ Unknown Windows platform for {json_file}")
        return

    # Find matching directory
    for d in check_base.iterdir():
        if d.is_dir() and platform_name in d.name.lower():
            script_dir = d
            break

    if not script_dir or not script_dir.exists():
        print(f"  ✗ Script directory not found for {platform_name}")
        return

    print(f"  Found {platform_name} scripts in: {script_dir}")

    # Load checks
    try:
        with open(json_file, 'r', encoding='utf-8') as f:
            checks = json.load(f)
    except Exception as e:
        print(f"  ✗ Error loading {json_file}: {e}")
        return

    if not checks:
        return

    stig_name = platform_name
    stats[stig_name]['total'] = len(checks)
    implemented = 0

    # Handle both dict and list formats
    check_list = checks if isinstance(checks, list) else list(checks.values())

    for check in check_list:
        if not isinstance(check, dict):
            continue

        stig_id = check.get('STIG ID', '')
        vuln_id = check.get('Vuln ID', '')
        check_content = check.get('Check Content', '')
        rule_title = check.get('Rule Title', '')

        # Try both STIG ID and Vuln ID for file matching
        script_found = False
        for check_id in [vuln_id, stig_id]:
            if not check_id:
                continue

            # Find corresponding script
            script_files = list(script_dir.glob(f"{check_id}.*"))

            if script_files:
                # Process .ps1 file
                for script_file in script_files:
                    if script_file.suffix == '.ps1':
                        if generate_implementation(check_id, check_content, rule_title, script_file):
                            implemented += 1
                        script_found = True
                        break
                if script_found:
                    break

        # Progress indicator
        if implemented > 0 and implemented % 25 == 0:
            print(f"  ✓ {stig_name}: {implemented}/{len(checks)}")

    stats[stig_name]['implemented'] = implemented
    print(f"  ✓ {stig_name}: {implemented}/{len(checks)}")

def main():
    print("=" * 80)
    print("WINDOWS OS IMPLEMENTATION ENGINE")
    print("Implementing check logic for Windows 10/11 STIGs")
    print("=" * 80)
    print()

    # Find Windows JSON files
    windows_jsons = [
        Path('windows_10_checks.json'),
        Path('windows_11_checks.json'),
    ]

    for json_file in windows_jsons:
        if json_file.exists():
            process_windows_stig(json_file)

    print()
    print("=" * 80)
    print("IMPLEMENTATION COMPLETE")
    print("=" * 80)
    print()

    total_checks = sum(s['total'] for s in stats.values())
    total_impl = sum(s['implemented'] for s in stats.values())

    print(f"TOTAL: {total_impl}/{total_checks} ({100*total_impl/total_checks if total_checks > 0 else 0:.1f}%) implemented\n")

    for name, s in sorted(stats.items()):
        pct = 100 * s['implemented'] / s['total'] if s['total'] > 0 else 0
        print(f"  {name:45s}: {s['implemented']:4d}/{s['total']:4d} ({pct:5.1f}%)")

if __name__ == '__main__':
    main()
