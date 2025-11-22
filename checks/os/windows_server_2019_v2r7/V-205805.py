#!/usr/bin/env python3
"""
STIG Check: V-205805
Severity: high
Rule Title: Windows Server 2019 default AutoRun behavior must be configured to prevent AutoRun commands.
STIG ID: WN19-CC-000220
STIG Version: Windows Server 2019 v2r7

AUTO-GENERATED: 2025-11-22 04:41:54
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
        return {'exists': True, 'value': value, 'type': value_type}
    except FileNotFoundError:
        return {'exists': False, 'value': None, 'type': None}
    except Exception as e:
        return {'exists': False, 'value': None, 'type': None, 'error': str(e)}


def main():
    parser = argparse.ArgumentParser(description='STIG Check V-205805')
    parser.add_argument('--config', help='Configuration file (JSON)')
    parser.add_argument('--output-json', help='Output results to JSON file')
    args = parser.parse_args()

    # TODO: Extract actual registry path and value
    hive = winreg.HKEY_LOCAL_MACHINE
    key_path = r"SOFTWARE\Policies"
    value_name = "ValueName"
    expected_value = 1

    result = check_registry_value(hive, key_path, value_name)

    if result['exists']:
        if result['value'] == expected_value:
            print(f"PASS: Registry value matches expected ({expected_value})")
            return 0
        else:
            print(f"FAIL: Registry value is {{result['value']}}, expected {expected_value}")
            return 1
    else:
        print(f"FAIL: Registry value does not exist")
        return 1


if __name__ == '__main__':
    sys.exit(main())
