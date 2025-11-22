#!/usr/bin/env python3
"""
Generate all Oracle Linux 8 v1r7 STIG check scripts

This script automatically generates bash and python check scripts for all
Oracle Linux 8 STIG checks based on the analyzed check data.

Usage:
    python3 generate_all_ol8_checks.py
    python3 generate_all_ol8_checks.py --dry-run
    python3 generate_all_ol8_checks.py --limit 10  # Generate only first 10
"""

import json
import os
import argparse
from pathlib import Path
from datetime import datetime


# Template selection based on check type
CHECK_TEMPLATES = {
    'package': 'V-248519',  # Package installation check
    'service': 'V-248520',  # Service status check
    'config_file': 'generic_config',  # Configuration file parsing
    'command': 'generic_command',  # Command output validation
}


def categorize_check(check):
    """Determine the type of check based on content"""
    check_content = check.get('Check Content', '').lower()
    automation_method = check.get('automation_method', '').lower()

    # Package checks
    if any(cmd in check_content for cmd in ['rpm -q', 'yum list installed', 'dnf list']):
        return 'package', 'install' if 'must be installed' in check.get('Rule Title', '').lower() else 'remove'

    # Service checks
    if any(cmd in check_content for cmd in ['systemctl status', 'systemctl is-active', 'systemctl is-enabled']):
        return 'service', 'enabled' if 'must be' in check.get('Rule Title', '').lower() and 'running' in check_content else 'disabled'

    # Configuration file checks
    if '/etc/' in check_content or 'configuration' in check_content:
        return 'config_file', 'setting'

    # Command-based checks
    if 'command:' in check_content or '$ ' in check_content:
        return 'command', 'output'

    # Default to command-based
    return 'command', 'generic'


def generate_bash_package_check(check, action='install'):
    """Generate bash script for package check"""
    vuln_id = check['Vuln ID']
    stig_id = check['STIG ID']
    severity = check['Severity']
    rule_title = check['Rule Title']

    # Extract package name from check content
    check_content = check.get('Check Content', '')
    package_name = 'PACKAGE_NAME'  # Default, should be extracted

    # Try to extract package name
    import re
    match = re.search(r'(?:rpm -q|yum list installed|package)\s+(\S+)', check_content)
    if match:
        package_name = match.group(1)

    if action == 'install':
        check_logic = f'''
    # Check if {package_name} package is installed
    if check_package_installed "{package_name}"; then
        package_version=$(get_package_version "{package_name}")
        STATUS="NotAFinding"
        # Package is installed - PASS
        # (Add audit evidence here)
        return 0
    else
        STATUS="Open"
        # Package not installed - FAIL
        # (Add compliance issues here)
        return 1
    fi
'''
    else:  # remove
        check_logic = f'''
    # Check if {package_name} package is NOT installed
    if ! check_package_installed "{package_name}"; then
        STATUS="NotAFinding"
        # Package not installed (as required) - PASS
        return 0
    else
        package_version=$(get_package_version "{package_name}")
        STATUS="Open"
        # Package installed (should not be) - FAIL
        return 1
    fi
'''

    script = f'''#!/usr/bin/env bash
#
# STIG Check: {vuln_id}
# Severity: {severity}
# Rule Title: {rule_title}
# STIG ID: {stig_id}
# STIG Version: Oracle Linux 8 v1r7
# Requires Elevation: No
# Third-Party Tools: None (uses yum/rpm)
#
# AUTO-GENERATED: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
# Based on template: V-248519 (package check)

set -eo pipefail

VULN_ID="{vuln_id}"
SEVERITY="{severity}"
STIG_ID="{stig_id}"
RULE_TITLE="{rule_title[:200]}"
STIG_VERSION="Oracle Linux 8 v1r7"

# TODO: Extract actual package name from check content
PACKAGE_NAME="{package_name}"

# Check implementation
run_check() {{
{check_logic}
}}

# Main execution
run_check
exit $?
'''

    return script


def generate_python_package_check(check, action='install'):
    """Generate python script for package check"""
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
STIG Version: Oracle Linux 8 v1r7

AUTO-GENERATED: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
Based on template: V-248519 (package check)
"""

import sys
import subprocess

def check_package_installed(package):
    """Check if package is installed"""
    try:
        result = subprocess.run(
            ['rpm', '-q', package],
            capture_output=True,
            text=True,
            timeout=30
        )
        return result.returncode == 0
    except:
        return False

def main():
    # TODO: Extract actual package name
    package = "PACKAGE_NAME"

    if check_package_installed(package):
        print(f"PASS: Package {{package}} is installed")
        return 0
    else:
        print(f"FAIL: Package {{package}} is not installed")
        return 1

if __name__ == '__main__':
    sys.exit(main())
'''

    return script


def generate_bash_service_check(check, action='enabled'):
    """Generate bash script for service check"""
    vuln_id = check['Vuln ID']
    stig_id = check['STIG ID']
    severity = check['Severity']
    rule_title = check['Rule Title']

    # Extract service name
    check_content = check.get('Check Content', '')
    service_name = 'SERVICE_NAME'

    import re
    match = re.search(r'systemctl.*?\s+(\S+\.service|\S+)\s*$', check_content, re.MULTILINE)
    if match:
        service_name = match.group(1).replace('.service', '')

    script = f'''#!/usr/bin/env bash
#
# STIG Check: {vuln_id}
# Severity: {severity}
# Rule Title: {rule_title}
# STIG ID: {stig_id}
# STIG Version: Oracle Linux 8 v1r7
#
# AUTO-GENERATED: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
# Based on template: V-248520 (service check)

set -eo pipefail

VULN_ID="{vuln_id}"
SEVERITY="{severity}"
STIG_ID="{stig_id}"
STIG_VERSION="Oracle Linux 8 v1r7"

SERVICE_NAME="{service_name}"

# Check service status
is_active=$(systemctl is-active "$SERVICE_NAME" 2>/dev/null || echo "inactive")

if [[ "$is_active" == "active" ]]; then
    echo "PASS: Service $SERVICE_NAME is active"
    exit 0
else
    echo "FAIL: Service $SERVICE_NAME is not active (current: $is_active)"
    exit 1
fi
'''

    return script


def main():
    parser = argparse.ArgumentParser(
        description='Generate all Oracle Linux 8 v1r7 STIG checks',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    parser.add_argument('--dry-run', action='store_true',
                       help='Preview what would be generated without creating files')
    parser.add_argument('--limit', type=int,
                       help='Only generate first N checks (for testing)')
    parser.add_argument('--output-dir', default='checks/os/oracle_linux_8_v1r7',
                       help='Output directory for checks')
    parser.add_argument('--skip-existing', action='store_true',
                       help='Skip checks that already exist')

    args = parser.parse_args()

    # Load analyzed checks
    analyzed_file = Path(args.output_dir) / 'analyzed_checks.json'

    if not analyzed_file.exists():
        print(f"Error: {analyzed_file} not found")
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
        bash_file = output_dir / f"{vuln_id}.sh"
        python_file = output_dir / f"{vuln_id}.py"

        if args.skip_existing and (bash_file.exists() or python_file.exists()):
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
            if check_type == 'package':
                bash_script = generate_bash_package_check(check, action)
                python_script = generate_python_package_check(check, action)
            elif check_type == 'service':
                bash_script = generate_bash_service_check(check, action)
                python_script = "# Python service check template\n"  # TODO
            else:
                # Generic placeholder
                bash_script = f"#!/usr/bin/env bash\n# TODO: Implement {vuln_id}\n"
                python_script = f"#!/usr/bin/env python3\n# TODO: Implement {vuln_id}\n"

            # Write bash script
            with open(bash_file, 'w') as f:
                f.write(bash_script)
            os.chmod(bash_file, 0o755)

            # Write python script
            with open(python_file, 'w') as f:
                f.write(python_script)
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
