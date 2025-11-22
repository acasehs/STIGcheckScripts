#!/usr/bin/env python3
"""
DTOO285 - Internet calendar integration in Outlook must be disabled.

STIG ID: DTOO285
Rule Title: Internet calendar integration in Outlook must be disabled.
Severity: medium
Vuln ID: V-228470
Rule ID: SV-228470r822351

This script checks Microsoft Outlook 2016 configuration compliance.

Exit Codes:
    0 = PASS (Compliant)
    1 = FAIL (Non-Compliant)
    2 = N/A (Not Applicable)
    3 = ERROR (Script execution error)

Registry Check:
    Key: HKCU\Software\Policies\Microsoft\Office\16.0\outlook\options\webcal
    Value: Disable
    Type: REG_DWORD
    Expected: 1
"""

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
        return "FAIL", f"Registry key or value not found: {key_path}\\{value_name}"
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
        "STIG_ID": "DTOO285",
        "Rule_Title": "Internet calendar integration in Outlook must be disabled.",
        "Severity": "medium",
        "Status": "Not_Reviewed",
        "Finding_Details": "",
        "Comments": ""
    }

    try:
        # Registry check configuration
        hive = winreg.HKEY_CURRENT_USER
        key_path = r"HKCU\Software\Policies\Microsoft\Office\16.0\outlook\options\webcal"
        value_name = "Disable"
        expected_value = 1
        value_type = "DWORD"

        # TODO: Implement registry check
        # status, details = check_registry_value(hive, key_path, value_name, expected_value, value_type)
        # result["Status"] = status
        # result["Finding_Details"] = details

        # Placeholder
        result["Status"] = "Not_Reviewed"
        result["Comments"] = "Automated check not yet implemented - requires Office domain expertise"
        result["Finding_Details"] = "This check requires registry validation"

    except Exception as e:
        result["Status"] = "ERROR"
        result["Finding_Details"] = f"Error: {str(e)}"
        result["Comments"] = "Script execution failed"

    return result

def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description="DTOO285 - Internet calendar integration in Outlook must be disabled.",
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
