#!/usr/bin/env python3
"""
Update STIG_COMMANDS_REFERENCE.csv with check commands

This script scans the checks/ directory for implemented STIG checks and
updates the command reference CSV file with execution commands.

Usage:
    python3 update_command_reference.py
    python3 update_command_reference.py --dry-run  # Preview changes without updating
"""

import os
import re
import csv
import argparse
from pathlib import Path
from collections import defaultdict


def extract_metadata_from_check(file_path):
    """Extract STIG metadata from check script header"""
    metadata = {
        'vuln_id': None,
        'severity': None,
        'stig_id': None,
        'rule_title': None,
        'stig_version': None,
        'requires_elevation': None,
        'third_party_tools': None
    }

    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read(500)  # Read first 500 chars for metadata

        # Extract Vuln ID
        match = re.search(r'STIG Check:\s*(V-\d+)|Vuln ID:\s*(V-\d+)', content, re.IGNORECASE)
        if match:
            metadata['vuln_id'] = match.group(1) or match.group(2)

        # Extract Severity
        match = re.search(r'Severity:\s*(\w+)', content, re.IGNORECASE)
        if match:
            metadata['severity'] = match.group(1).lower()

        # Extract STIG ID
        match = re.search(r'STIG ID:\s*([\w-]+)', content, re.IGNORECASE)
        if match:
            metadata['stig_id'] = match.group(1)

        # Extract Rule Title
        match = re.search(r'Rule Title:\s*(.+?)(?:\n|$)', content, re.IGNORECASE)
        if match:
            metadata['rule_title'] = match.group(1).strip()

        # Extract STIG Version
        match = re.search(r'STIG Version:\s*(.+?)(?:\n|$)', content, re.IGNORECASE)
        if match:
            metadata['stig_version'] = match.group(1).strip()

        # Extract Requires Elevation
        match = re.search(r'Requires Elevation:\s*(Yes|No)', content, re.IGNORECASE)
        if match:
            metadata['requires_elevation'] = match.group(1)

        # Extract Third-Party Tools
        match = re.search(r'Third-Party Tools:\s*(.+?)(?:\n|$)', content, re.IGNORECASE)
        if match:
            metadata['third_party_tools'] = match.group(1).strip()

    except Exception as e:
        print(f"Warning: Could not read {file_path}: {e}")

    return metadata


def parse_stig_version(stig_version_str):
    """Parse STIG version string to extract version and release"""
    # Examples:
    # "Oracle Linux 8 v1r7" -> version=1, release=7
    # "Oracle WebLogic Server 12c v2r1" -> version=2, release=1
    # "Windows Server 2022 v1r4" -> version=1, release=4

    version, release = None, None

    if stig_version_str:
        # Try to extract v#r# pattern
        match = re.search(r'v(\d+)r(\d+)', stig_version_str, re.IGNORECASE)
        if match:
            version = match.group(1)
            release = match.group(2)

    return version, release


def get_checklist_name(path):
    """Extract checklist name from directory path"""
    # Extract from path like: checks/os/oracle_linux_8_v1r7/samples/V-248519.sh
    # Should return: Oracle Linux 8

    parts = Path(path).parts

    # Find the STIG directory (contains version info)
    for part in parts:
        if '_v' in part and 'r' in part:
            # Remove version/release suffix
            name = re.sub(r'_v\d+r\d+.*$', '', part)
            # Convert underscores to spaces and title case
            name = name.replace('_', ' ').title()
            return name

    return None


def scan_checks_directory(base_path):
    """Scan checks/ directory for all implemented checks"""
    checks = []

    checks_dir = Path(base_path) / 'checks'

    if not checks_dir.exists():
        print(f"Error: checks/ directory not found at {checks_dir}")
        return checks

    # Find all check scripts (.sh and .py files)
    for check_file in checks_dir.rglob('*'):
        if check_file.is_file() and check_file.suffix in ['.sh', '.py']:
            # Skip config files and other non-check files
            if 'config' in check_file.name.lower():
                continue

            # Extract metadata
            metadata = extract_metadata_from_check(check_file)

            if not metadata['vuln_id']:
                # Skip files without Vuln ID (not actual checks)
                continue

            # Determine tool
            tool = 'Bash' if check_file.suffix == '.sh' else 'Python'

            # Get checklist name
            checklist_name = get_checklist_name(check_file)

            # Parse STIG version
            version, release = parse_stig_version(metadata['stig_version'])

            # Generate commands
            rel_path = check_file.relative_to(base_path)
            cmd_without_config = f"{tool.lower()} {rel_path}" if tool == 'Python' else f"bash {rel_path}"
            cmd_with_config = f"{cmd_without_config} --config stig-config.json"

            check_entry = {
                'checklist_name': checklist_name or 'Unknown',
                'version': f"v{version}" if version else 'Unknown',
                'release': f"r{release}" if release else 'Unknown',
                'stig_id': metadata['stig_id'] or 'Unknown',
                'vuln_id': metadata['vuln_id'] or 'Unknown',
                'severity': metadata['severity'] or 'unknown',
                'rule_title': metadata['rule_title'] or 'Unknown',
                'tool': tool,
                'command_with_config': cmd_with_config,
                'command_without_config': cmd_without_config,
                'requires_elevation': metadata['requires_elevation'] or 'Unknown',
                'third_party_tools': metadata['third_party_tools'] or 'Unknown',
                'notes': f"Path: {rel_path}"
            }

            checks.append(check_entry)

    return checks


def update_csv(checks, csv_path, dry_run=False):
    """Update the CSV file with check information"""
    # Sort checks by checklist name, then version, then vuln_id
    sorted_checks = sorted(checks, key=lambda x: (x['checklist_name'], x['version'], x['release'], x['vuln_id']))

    if dry_run:
        print("\n=== DRY RUN - Preview of CSV entries ===\n")
        for check in sorted_checks:
            print(f"{check['checklist_name']} {check['version']}{check['release']} - {check['vuln_id']} ({check['tool']})")
        print(f"\nTotal entries: {len(sorted_checks)}")
        print(f"\nWould write to: {csv_path}")
        return

    # Write to CSV
    fieldnames = [
        'Checklist_Name',
        'Version',
        'Release',
        'STIG_ID',
        'Vuln_ID',
        'Severity',
        'Rule_Title',
        'Tool',
        'Command_With_Config',
        'Command_Without_Config',
        'Requires_Elevation',
        'Third_Party_Tools',
        'Notes'
    ]

    try:
        with open(csv_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()

            for check in sorted_checks:
                writer.writerow({
                    'Checklist_Name': check['checklist_name'],
                    'Version': check['version'],
                    'Release': check['release'],
                    'STIG_ID': check['stig_id'],
                    'Vuln_ID': check['vuln_id'],
                    'Severity': check['severity'],
                    'Rule_Title': check['rule_title'],
                    'Tool': check['tool'],
                    'Command_With_Config': check['command_with_config'],
                    'Command_Without_Config': check['command_without_config'],
                    'Requires_Elevation': check['requires_elevation'],
                    'Third_Party_Tools': check['third_party_tools'],
                    'Notes': check['notes']
                })

        print(f"\n✅ Successfully updated {csv_path}")
        print(f"   Total entries: {len(sorted_checks)}")

        # Print summary by checklist
        summary = defaultdict(int)
        for check in sorted_checks:
            key = f"{check['checklist_name']} {check['version']}{check['release']}"
            summary[key] += 1

        print("\n=== Summary by STIG ===")
        for stig, count in sorted(summary.items()):
            print(f"   {stig}: {count} checks")

    except Exception as e:
        print(f"Error writing CSV: {e}")
        return False

    return True


def main():
    parser = argparse.ArgumentParser(
        description='Update STIG_COMMANDS_REFERENCE.csv with implemented checks',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    parser.add_argument('--dry-run', action='store_true',
                       help='Preview changes without updating CSV')
    parser.add_argument('--base-path', default='.',
                       help='Base path to STIGcheckScripts directory (default: current directory)')

    args = parser.parse_args()

    base_path = Path(args.base_path).resolve()
    csv_path = base_path / 'STIG_COMMANDS_REFERENCE.csv'

    print(f"Scanning for checks in: {base_path / 'checks'}")
    print(f"Output CSV: {csv_path}")
    print("")

    # Scan for checks
    checks = scan_checks_directory(base_path)

    if not checks:
        print("No checks found. Make sure you're in the STIGcheckScripts directory.")
        return 1

    print(f"Found {len(checks)} check script(s)")

    # Update CSV
    success = update_csv(checks, csv_path, args.dry_run)

    return 0 if success or args.dry_run else 1


if __name__ == '__main__':
    exit(main())
