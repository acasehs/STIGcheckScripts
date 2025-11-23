#!/usr/bin/env python3
"""
Find all STIG checks that are not yet implemented.
"""

import os
import re
from pathlib import Path
from collections import defaultdict

def is_not_implemented(file_path):
    """Check if a script is not implemented"""
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()

        # Check for various "not implemented" patterns
        not_impl_patterns = [
            r'STATUS="Not Implemented"',
            r'status="Not Implemented"',
            r'\$Status = "Not Implemented"',
            r'TODO: Implement',
            r'echo "TODO:',
            r'# TODO: Implement the actual check logic',
            r'Check logic not yet implemented',
        ]

        # Exclude manual review (those are intentionally not automated)
        if 'Manual review required' in content or 'Manual Review Required' in content:
            return False

        # Check if any not-implemented pattern exists
        for pattern in not_impl_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                return True

        return False
    except Exception as e:
        return False

def main():
    base_dir = Path('/home/user/STIGcheckScripts')

    # Categories to scan
    categories = [
        'OS_STIGs',
        'Application_STIGs',
        'Database_STIGs',
        'Network_Device_STIGs',
        'Container_Platform_STIGs'
    ]

    not_implemented = defaultdict(list)
    total_not_impl = 0

    print("=" * 80)
    print("FINDING NOT-IMPLEMENTED STIG CHECKS")
    print("=" * 80)
    print()

    for category in categories:
        cat_dir = base_dir / category
        if not cat_dir.exists():
            continue

        # Find all check directories
        for platform_dir in sorted(cat_dir.iterdir()):
            if not platform_dir.is_dir():
                continue

            platform_name = platform_dir.name
            checks_dir = platform_dir / 'checks'

            if not checks_dir.exists():
                continue

            # Find all script files
            for check_file in sorted(checks_dir.iterdir()):
                if check_file.is_file() and (check_file.suffix in ['.sh', '.ps1', '.bat']):
                    if is_not_implemented(check_file):
                        not_implemented[platform_name].append(str(check_file))
                        total_not_impl += 1

    # Display results
    print(f"Found {total_not_impl} not-implemented checks across {len(not_implemented)} platforms:\n")

    for platform in sorted(not_implemented.keys()):
        files = not_implemented[platform]
        print(f"{platform}: {len(files)} checks")
        for f in files[:3]:  # Show first 3 examples
            print(f"  - {Path(f).name}")
        if len(files) > 3:
            print(f"  ... and {len(files) - 3} more")
        print()

    # Save detailed list to file
    output_file = base_dir / 'not_implemented_list.txt'
    with open(output_file, 'w') as f:
        f.write("NOT-IMPLEMENTED STIG CHECKS\n")
        f.write("=" * 80 + "\n\n")
        f.write(f"Total: {total_not_impl} checks\n\n")

        for platform in sorted(not_implemented.keys()):
            f.write(f"\n{platform} ({len(not_implemented[platform])} checks):\n")
            f.write("-" * 80 + "\n")
            for file_path in sorted(not_implemented[platform]):
                f.write(f"{file_path}\n")

    print(f"✅ Detailed list saved to: {output_file}")
    print()
    print("=" * 80)

if __name__ == '__main__':
    main()
