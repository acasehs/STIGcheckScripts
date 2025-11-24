#!/usr/bin/env python3
"""
Automated STIG Check Implementation Engine for Oracle 2025 STIGs.
Analyzes check content and generates fully automated check logic.
"""

import json
import re
from pathlib import Path
from typing import Dict, List, Tuple

def extract_check_commands(check_content: str) -> List[str]:
    """Extract actual commands from check content"""
    if not check_content:
        return []

    commands = []

    # Pattern 1: Commands in code blocks with $ or #
    cmd_patterns = [
        r'\$\s*(?:sudo\s+)?([^\n]+)',
        r'#\s*([a-z]+\s+[^\n]+)',
    ]

    for pattern in cmd_patterns:
        matches = re.findall(pattern, check_content)
        commands.extend(matches)

    return [cmd.strip() for cmd in commands if len(cmd.strip()) > 5]

def categorize_check_type(check_content: str, commands: List[str]) -> str:
    """Determine the type of check"""
    content_lower = check_content.lower() if check_content else ''

    # File permission checks
    if re.search(r'permission|chmod|stat.*-c|ls -l', content_lower):
        return 'file_permission'

    # File ownership checks
    if re.search(r'owner|group|stat.*%U|stat.*%G', content_lower):
        return 'file_ownership'

    # Package checks
    if re.search(r'rpm -q|yum list|dnf list|dpkg', content_lower):
        return 'package_check'

    # Config file grep
    if re.search(r'grep.*config|grep.*conf|cat.*\.conf.*grep', content_lower):
        return 'config_grep'

    # Sysctl/kernel parameter
    if re.search(r'sysctl|/proc/sys/', content_lower):
        return 'sysctl_check'

    # Service status
    if re.search(r'systemctl.*status|systemctl.*is-enabled|service.*status', content_lower):
        return 'service_check'

    # File existence
    if re.search(r'test -f|test -d|\[ -f \]|\[ -d \]|if.*exist', content_lower):
        return 'file_existence'

    # Database query
    if re.search(r'select.*from|sql.*query', content_lower):
        return 'database_query'

    # Registry check (Windows - but shouldn't be in Oracle Linux)
    if re.search(r'registry|reg query|get-itemproperty', content_lower):
        return 'registry_check'

    return 'complex'

def generate_file_permission_check(check_content: str, commands: List[str]) -> str:
    """Generate code for file permission checks"""

    # Try to extract the file path and expected permissions
    file_match = re.search(r'check.*file[:\s]+([/\w\.\-]+)', check_content, re.IGNORECASE)
    perm_match = re.search(r'permission.*[:\s]+"?(\d{4})"?|mode.*[:\s]+"?(\d{4})"?', check_content, re.IGNORECASE)

    file_path = file_match.group(1) if file_match else '/etc/example/file'
    expected_perm = (perm_match.group(1) or perm_match.group(2)) if perm_match else '0644'

    return f'''    # Automated file permission check

    local file_path="{file_path}"  # Extract from STIG check content
    local expected_perm="{expected_perm}"

    if [[ ! -e "$file_path" ]]; then
        output_json "Not_Applicable" "File does not exist: $file_path" "File not found"
        echo "[$VULN_ID] N/A - File does not exist: $file_path"
        exit 2
    fi

    # Get actual permissions
    actual_perm=$(stat -c "%a" "$file_path" 2>/dev/null)

    if [[ "$actual_perm" == "$expected_perm" || "$actual_perm" -le "$expected_perm" ]]; then
        output_json "NotAFinding" "File permissions are compliant" "Permissions: $actual_perm (expected: $expected_perm or more restrictive)"
        echo "[$VULN_ID] PASS - File permissions are compliant: $actual_perm"
        exit 0
    else
        output_json "Open" "File permissions are not compliant" "Found: $actual_perm, Expected: $expected_perm or more restrictive"
        echo "[$VULN_ID] FAIL - File permissions are not compliant: $actual_perm (expected: $expected_perm)"
        exit 1
    fi
'''

def generate_package_check(check_content: str, commands: List[str]) -> str:
    """Generate code for package installation checks"""

    # Try to extract package name
    pkg_match = re.search(r'(?:rpm -q|yum list|dnf list)\s+(\S+)', check_content)
    package_name = pkg_match.group(1) if pkg_match else 'example-package'

    # Determine if package should be installed or not installed
    should_not_be_installed = 'must not' in check_content.lower() or 'should not be installed' in check_content.lower()

    if should_not_be_installed:
        return f'''    # Automated package check - verify NOT installed

    local package="{package_name}"

    if rpm -q "$package" &>/dev/null; then
        output_json "Open" "Package should not be installed" "Package $package is installed"
        echo "[$VULN_ID] FAIL - Package $package should not be installed"
        exit 1
    else
        output_json "NotAFinding" "Package is not installed (compliant)" "Package $package is not installed"
        echo "[$VULN_ID] PASS - Package $package is not installed"
        exit 0
    fi
'''
    else:
        return f'''    # Automated package check - verify installed

    local package="{package_name}"

    if rpm -q "$package" &>/dev/null; then
        output_json "NotAFinding" "Package is installed (compliant)" "Package $package is installed"
        echo "[$VULN_ID] PASS - Package $package is installed"
        exit 0
    else
        output_json "Open" "Required package is not installed" "Package $package is not installed"
        echo "[$VULN_ID] FAIL - Package $package is not installed"
        exit 1
    fi
'''

def generate_config_grep_check(check_content: str, commands: List[str]) -> str:
    """Generate code for config file grep checks"""

    # Extract config file and search pattern
    file_match = re.search(r'grep.*?([/\w\.\-]+\.conf)', check_content)
    pattern_match = re.search(r'grep.*?"([^"]+)"', check_content)

    config_file = file_match.group(1) if file_match else '/etc/example.conf'
    search_pattern = pattern_match.group(1) if pattern_match else 'ParameterName'

    return f'''    # Automated config file grep check

    local config_file="{config_file}"
    local search_pattern="{search_pattern}"

    if [[ ! -f "$config_file" ]]; then
        output_json "Not_Applicable" "Config file does not exist" "File not found: $config_file"
        echo "[$VULN_ID] N/A - Config file not found: $config_file"
        exit 2
    fi

    if grep -q "$search_pattern" "$config_file" 2>/dev/null; then
        output_json "NotAFinding" "Configuration is compliant" "Found required setting: $search_pattern"
        echo "[$VULN_ID] PASS - Found required configuration"
        exit 0
    else
        output_json "Open" "Required configuration not found" "Missing: $search_pattern in $config_file"
        echo "[$VULN_ID] FAIL - Required configuration not found"
        exit 1
    fi
'''

def generate_sysctl_check(check_content: str, commands: List[str]) -> str:
    """Generate code for sysctl parameter checks"""

    # Extract sysctl parameter and expected value
    param_match = re.search(r'sysctl\s+([\w\.]+)', check_content)
    value_match = re.search(r'=\s*(\d+)', check_content)

    param_name = param_match.group(1) if param_match else 'kernel.parameter'
    expected_value = value_match.group(1) if value_match else '1'

    return f'''    # Automated sysctl parameter check

    local param="{param_name}"
    local expected="{expected_value}"

    actual=$(sysctl -n "$param" 2>/dev/null)

    if [[ -z "$actual" ]]; then
        output_json "Open" "Sysctl parameter not found" "Parameter $param is not set"
        echo "[$VULN_ID] FAIL - Sysctl parameter not found: $param"
        exit 1
    fi

    if [[ "$actual" == "$expected" ]]; then
        output_json "NotAFinding" "Sysctl parameter is compliant" "Parameter: $param=$actual"
        echo "[$VULN_ID] PASS - Sysctl parameter $param=$actual"
        exit 0
    else
        output_json "Open" "Sysctl parameter not compliant" "Found: $param=$actual, Expected: $expected"
        echo "[$VULN_ID] FAIL - Sysctl parameter $param=$actual (expected: $expected)"
        exit 1
    fi
'''

def generate_service_check(check_content: str, commands: List[str]) -> str:
    """Generate code for service status checks"""

    # Extract service name
    svc_match = re.search(r'(?:systemctl|service)\s+(?:status|is-enabled|is-active)\s+(\S+)', check_content)
    service_name = svc_match.group(1) if svc_match else 'example.service'

    # Determine if service should be enabled/disabled
    should_be_enabled = 'enabled' in check_content.lower() and 'disabled' not in check_content.lower()

    if should_be_enabled:
        return f'''    # Automated service check - verify enabled

    local service="{service_name}"

    if systemctl is-enabled "$service" &>/dev/null; then
        output_json "NotAFinding" "Service is enabled (compliant)" "Service $service is enabled"
        echo "[$VULN_ID] PASS - Service $service is enabled"
        exit 0
    else
        output_json "Open" "Service should be enabled" "Service $service is not enabled"
        echo "[$VULN_ID] FAIL - Service $service is not enabled"
        exit 1
    fi
'''
    else:
        return f'''    # Automated service check - verify disabled

    local service="{service_name}"

    if systemctl is-enabled "$service" &>/dev/null; then
        output_json "Open" "Service should be disabled" "Service $service is enabled"
        echo "[$VULN_ID] FAIL - Service $service should be disabled"
        exit 1
    else
        output_json "NotAFinding" "Service is disabled (compliant)" "Service $service is disabled"
        echo "[$VULN_ID] PASS - Service $service is disabled"
        exit 0
    fi
'''

def generate_automated_check(stig_data: Dict) -> str:
    """Generate fully automated check code based on STIG data"""

    check_content = stig_data.get('check_content', '')
    commands = extract_check_commands(check_content)
    check_type = categorize_check_type(check_content, commands)

    if check_type == 'file_permission':
        return generate_file_permission_check(check_content, commands)
    elif check_type == 'package_check':
        return generate_package_check(check_content, commands)
    elif check_type == 'config_grep':
        return generate_config_grep_check(check_content, commands)
    elif check_type == 'sysctl_check':
        return generate_sysctl_check(check_content, commands)
    elif check_type == 'service_check':
        return generate_service_check(check_content, commands)
    else:
        # For complex checks, keep manual review
        return '''    # Complex check - requires manual review

    echo "[$VULN_ID] MANUAL REVIEW REQUIRED"
    echo "This check requires manual verification per STIG documentation"

    output_json "Not_Reviewed" "Manual review required" "Complex check - consult STIG documentation"
    exit 2
'''

def main():
    print("=" * 80)
    print("AUTOMATED CHECK IMPLEMENTATION GENERATOR")
    print("=" * 80)

    # Load Oracle 2025 STIGs
    with open('oracle_2025_stigs.json', 'r') as f:
        stigs = json.load(f)

    print(f"\nAnalyzing {len(stigs)} Oracle 2025 STIGs...")

    # Categorize by check type
    by_type = {}
    for stig in stigs:
        check_content = stig.get('check_content', '')
        commands = extract_check_commands(check_content)
        check_type = categorize_check_type(check_content, commands)

        by_type[check_type] = by_type.get(check_type, 0) + 1

    print("\nCheck Type Distribution:")
    for check_type, count in sorted(by_type.items(), key=lambda x: x[1], reverse=True):
        print(f"  {check_type}: {count}")

    print("\n" + "=" * 80)
    print("Ready to implement automation")
    print("=" * 80)

if __name__ == '__main__':
    main()
