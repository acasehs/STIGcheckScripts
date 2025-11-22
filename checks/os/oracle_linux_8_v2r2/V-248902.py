#!/usr/bin/env python3
"""
STIG Check: V-248902
Severity: medium
Rule Title: If the Trivial File Transfer Protocol (TFTP) server is required, the OL 8 TFTP daemon must be configured to operate in secure mode.
STIG ID: OL08-00-040350
STIG Version: Oracle Linux 8 v2r2

AUTO-GENERATED: 2025-11-22 04:51:30
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
        print(f"PASS: Package {package} is installed")
        return 0
    else:
        print(f"FAIL: Package {package} is not installed")
        return 1

if __name__ == '__main__':
    sys.exit(main())
