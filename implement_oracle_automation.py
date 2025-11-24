#!/usr/bin/env python3
"""
Implement full automation for Oracle 2025 STIGs.
Replaces manual review placeholders with actual check logic.
"""

import json
import re
from pathlib import Path
from typing import Dict, Optional

# Load STIG data
def load_stig_data():
    with open('AllSTIGS2.json', 'r') as f:
        data = json.load(f)

    # Index by Group ID (VULN ID)
    stig_map = {}
    for entry in data:
        vuln_id = entry.get('Group ID')
        release_info = entry.get('Release Info', '')
        benchmark = entry.get('Benchmark Name', '')

        # Only Oracle 2025 STIGs
        if vuln_id and 'Oracle' in benchmark and '2025' in release_info:
            stig_map[vuln_id] = entry

    return stig_map

def extract_file_path_from_check(check_content: str) -> Optional[str]:
    """Extract file path from check content"""
    patterns = [
        r'check.*file.*[:\s]+([/\w\.\-]+)',
        r'verify.*([/\w]+/[\w\.\-]+)',
        r'cat\s+([/\w\.\-]+)',
        r'ls.*\s+([/\w\.\-]+)',
        r'stat.*\s+([/\w\.\-]+)',
    ]

    for pattern in patterns:
        match = re.search(pattern, check_content, re.IGNORECASE)
        if match:
            path = match.group(1)
            if path.startswith('/') and len(path) > 3:
                return path
    return None

def extract_expected_permission(check_content: str) -> Optional[str]:
    """Extract expected file permission from check content"""
    patterns = [
        r'permission.*[:\s]+"?(\d{4})"?',
        r'mode.*[:\s]+"?(\d{4})"?',
        r'chmod\s+(\d{4})',
    ]

    for pattern in patterns:
        match = re.search(pattern, check_content, re.IGNORECASE)
        if match:
            return match.group(1)
    return None

def extract_package_name(check_content: str) -> Optional[str]:
    """Extract package name from check content"""
    patterns = [
        r'(?:rpm -q|yum list|dnf list)\s+(\S+)',
        r'package.*[:\s]+(\S+)',
    ]

    for pattern in patterns:
        match = re.search(pattern, check_content)
        if match:
            pkg = match.group(1)
            if pkg and not pkg.startswith('-'):
                return pkg
    return None

def extract_config_pattern(check_content: str) -> tuple:
    """Extract config file and search pattern"""
    file_match = re.search(r'(?:grep|cat).*?([/\w\.\-]+\.conf[^\s]*)', check_content)
    pattern_match = re.search(r'grep.*?["\']([^"\']+)["\']', check_content)

    config_file = file_match.group(1) if file_match else None
    search_pattern = pattern_match.group(1) if pattern_match else None

    return config_file, search_pattern

def extract_sysctl_param(check_content: str) -> tuple:
    """Extract sysctl parameter and expected value"""
    param_match = re.search(r'sysctl.*?([\w\.]+)', check_content)
    value_match = re.search(r'=\s*(\d+)', check_content)

    param = param_match.group(1) if param_match else None
    value = value_match.group(1) if value_match else None

    return param, value

def generate_check_implementation(stig_data: Dict) -> str:
    """Generate bash implementation based on check content"""

    check_content = stig_data.get('Check Content', '')
    vuln_id = stig_data.get('Group ID', '')
    stig_id = stig_data.get('STIG ID', '')
    rule_title = stig_data.get('Rule Title', '')
    severity = stig_data.get('Severity', 'medium')

    if not check_content:
        return None

    content_lower = check_content.lower()

    # File permission check
    if 'permission' in content_lower and ('ls -l' in content_lower or 'stat' in content_lower):
        file_path = extract_file_path_from_check(check_content)
        expected_perm = extract_expected_permission(check_content)

        if file_path and expected_perm:
            return f'''#!/usr/bin/env bash
################################################################################
# STIG Check: {vuln_id}
# STIG ID: {stig_id}
# Severity: {severity}
# Rule Title: {rule_title[:70]}...
#
# Automated Check: File Permission Validation
################################################################################

set -euo pipefail

# Configuration
VULN_ID="{vuln_id}"
STIG_ID="{stig_id}"
SEVERITY="{severity}"
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
OUTPUT_JSON=""

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --output-json)
            OUTPUT_JSON="$2"
            shift 2
            ;;
        *)
            shift
            ;;
    esac
done

# Output function
output_json() {{
    local status="$1"
    local finding="$2"
    [[ -n "$OUTPUT_JSON" ]] && cat > "$OUTPUT_JSON" << EOF
{{"vuln_id":"$VULN_ID","stig_id":"$STIG_ID","severity":"$SEVERITY","status":"$status","finding_details":"$finding","timestamp":"$TIMESTAMP"}}
EOF
}}

# Automated file permission check
FILE_PATH="{file_path}"
EXPECTED_PERM="{expected_perm}"

if [[ ! -e "$FILE_PATH" ]]; then
    output_json "Not_Applicable" "File does not exist: $FILE_PATH"
    echo "[$VULN_ID] N/A - File not found"
    exit 2
fi

ACTUAL_PERM=$(stat -c "%a" "$FILE_PATH" 2>/dev/null || stat -f "%Mp%Lp" "$FILE_PATH" 2>/dev/null)

if [[ "$ACTUAL_PERM" -le "$EXPECTED_PERM" ]]; then
    output_json "NotAFinding" "Permissions compliant: $ACTUAL_PERM"
    echo "[$VULN_ID] PASS - Permissions: $ACTUAL_PERM"
    exit 0
else
    output_json "Open" "Permissions too permissive: $ACTUAL_PERM (expected: $EXPECTED_PERM)"
    echo "[$VULN_ID] FAIL - Permissions: $ACTUAL_PERM (expected: $EXPECTED_PERM)"
    exit 1
fi
'''

    # Package check
    if 'rpm -q' in content_lower or 'yum list' in content_lower or 'dnf list' in content_lower:
        package = extract_package_name(check_content)
        should_not_exist = 'must not' in content_lower or 'should not be installed' in content_lower

        if package:
            check_cmd = 'rpm -q' if 'rpm' in content_lower else 'yum list installed'

            return f'''#!/usr/bin/env bash
################################################################################
# STIG Check: {vuln_id}
# STIG ID: {stig_id}
# Severity: {severity}
# Rule Title: {rule_title[:70]}...
#
# Automated Check: Package Installation Validation
################################################################################

set -euo pipefail

VULN_ID="{vuln_id}"
STIG_ID="{stig_id}"
SEVERITY="{severity}"
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
OUTPUT_JSON=""

while [[ $# -gt 0 ]]; do
    case $1 in --output-json) OUTPUT_JSON="$2"; shift 2;; *) shift;; esac
done

output_json() {{
    [[ -n "$OUTPUT_JSON" ]] && cat > "$OUTPUT_JSON" << EOF
{{"vuln_id":"$VULN_ID","stig_id":"$STIG_ID","severity":"$SEVERITY","status":"$1","finding_details":"$2","timestamp":"$TIMESTAMP"}}
EOF
}}

PACKAGE="{package}"

if {check_cmd} "$PACKAGE" &>/dev/null; then
    {"if [[ true ]]; then" if not should_not_exist else "if [[ false ]]; then"}
        output_json "NotAFinding" "Package is installed (compliant)"
        echo "[$VULN_ID] PASS - Package $PACKAGE is installed"
        exit 0
    else
        output_json "Open" "Package should {'not ' if should_not_exist else ''}be installed"
        echo "[$VULN_ID] FAIL - Package $PACKAGE should {'not ' if should_not_exist else ''}be installed"
        exit 1
    fi
else
    {"if [[ false ]]; then" if not should_not_exist else "if [[ true ]]; then"}
        output_json "NotAFinding" "Package not installed (compliant)"
        echo "[$VULN_ID] PASS - Package $PACKAGE is not installed"
        exit 0
    else
        output_json "Open" "Required package not installed"
        echo "[$VULN_ID] FAIL - Package $PACKAGE should be installed"
        exit 1
    fi
fi
'''

    # Config grep check
    if 'grep' in content_lower and '.conf' in content_lower:
        config_file, pattern = extract_config_pattern(check_content)

        if config_file and pattern:
            return f'''#!/usr/bin/env bash
################################################################################
# STIG Check: {vuln_id}
# STIG ID: {stig_id}
# Severity: {severity}
# Rule Title: {rule_title[:70]}...
#
# Automated Check: Configuration Parameter Validation
################################################################################

set -euo pipefail

VULN_ID="{vuln_id}"
STIG_ID="{stig_id}"
SEVERITY="{severity}"
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
OUTPUT_JSON=""

while [[ $# -gt 0 ]]; do
    case $1 in --output-json) OUTPUT_JSON="$2"; shift 2;; *) shift;; esac
done

output_json() {{
    [[ -n "$OUTPUT_JSON" ]] && cat > "$OUTPUT_JSON" << EOF
{{"vuln_id":"$VULN_ID","stig_id":"$STIG_ID","severity":"$SEVERITY","status":"$1","finding_details":"$2","timestamp":"$TIMESTAMP"}}
EOF
}}

CONFIG_FILE="{config_file}"
PATTERN="{pattern}"

if [[ ! -f "$CONFIG_FILE" ]]; then
    output_json "Not_Applicable" "Config file not found: $CONFIG_FILE"
    echo "[$VULN_ID] N/A - Config file not found"
    exit 2
fi

if grep -q "$PATTERN" "$CONFIG_FILE" 2>/dev/null; then
    output_json "NotAFinding" "Required configuration found"
    echo "[$VULN_ID] PASS - Configuration found: $PATTERN"
    exit 0
else
    output_json "Open" "Required configuration not found: $PATTERN"
    echo "[$VULN_ID] FAIL - Configuration not found: $PATTERN"
    exit 1
fi
'''

    # Sysctl check
    if 'sysctl' in content_lower:
        param, value = extract_sysctl_param(check_content)

        if param and value:
            return f'''#!/usr/bin/env bash
################################################################################
# STIG Check: {vuln_id}
# STIG ID: {stig_id}
# Severity: {severity}
# Rule Title: {rule_title[:70]}...
#
# Automated Check: Kernel Parameter Validation
################################################################################

set -euo pipefail

VULN_ID="{vuln_id}"
STIG_ID="{stig_id}"
SEVERITY="{severity}"
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
OUTPUT_JSON=""

while [[ $# -gt 0 ]]; do
    case $1 in --output-json) OUTPUT_JSON="$2"; shift 2;; *) shift;; esac
done

output_json() {{
    [[ -n "$OUTPUT_JSON" ]] && cat > "$OUTPUT_JSON" << EOF
{{"vuln_id":"$VULN_ID","stig_id":"$STIG_ID","severity":"$SEVERITY","status":"$1","finding_details":"$2","timestamp":"$TIMESTAMP"}}
EOF
}}

PARAM="{param}"
EXPECTED="{value}"

ACTUAL=$(sysctl -n "$PARAM" 2>/dev/null || echo "NOT_SET")

if [[ "$ACTUAL" == "$EXPECTED" ]]; then
    output_json "NotAFinding" "Kernel parameter compliant: $PARAM=$ACTUAL"
    echo "[$VULN_ID] PASS - $PARAM=$ACTUAL"
    exit 0
else
    output_json "Open" "Kernel parameter not compliant: $PARAM=$ACTUAL (expected: $EXPECTED)"
    echo "[$VULN_ID] FAIL - $PARAM=$ACTUAL (expected: $EXPECTED)"
    exit 1
fi
'''

    return None  # Can't automate this check

def process_oracle_linux_checks():
    """Process Oracle Linux checks and implement automation"""

    print("="*80)
    print("IMPLEMENTING ORACLE LINUX AUTOMATION")
    print("="*80)

    stig_map = load_stig_data()

    base_dir = Path('/home/user/STIGcheckScripts/checks/os')
    oracle_linux_dirs = [
        'oracle_linux_7_v2r12',
        'oracle_linux_8_v1r7',
        'oracle_linux_8_v2r2',
        'oracle_linux_8_v2r5',
        'oracle_linux_9_v1r2',
    ]

    implemented = 0
    skipped = 0

    for dir_name in oracle_linux_dirs:
        platform_dir = base_dir / dir_name
        if not platform_dir.exists():
            continue

        print(f"\nProcessing {dir_name}...")
        platform_impl = 0

        for check_file in sorted(platform_dir.glob('*.sh')):
            # Extract VULN ID from filename or content
            vuln_id = None
            if check_file.stem.startswith('V-'):
                vuln_id = check_file.stem
            else:
                content = check_file.read_text(errors='ignore')
                match = re.search(r'VULN_ID="([VH]-\d+)"', content)
                if match:
                    vuln_id = match.group(1)

            if not vuln_id or vuln_id not in stig_map:
                skipped += 1
                continue

            # Generate automated check
            new_content = generate_check_implementation(stig_map[vuln_id])

            if new_content:
                check_file.write_text(new_content)
                implemented += 1
                platform_impl += 1
                if platform_impl <= 3:
                    print(f"  ✓ {check_file.name}")
            else:
                skipped += 1

        print(f"  Implemented: {platform_impl}")

    print(f"\n{'='*80}")
    print(f"Total Implemented: {implemented}")
    print(f"Total Skipped: {skipped}")
    print(f"{'='*80}")

if __name__ == '__main__':
    process_oracle_linux_checks()
