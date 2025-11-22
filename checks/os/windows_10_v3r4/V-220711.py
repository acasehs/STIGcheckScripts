#!/usr/bin/env python3
"""
STIG Check: V-220711
STIG ID: WN10-00-000065
Severity: low
Rule Title: Unused accounts must be disabled or removed from the system after 35 days of inactivity.

Description:
Outdated or unused accounts provide penetration points that may go undetected. Inactive accounts must be deleted if no longer necessary or, if still required, disabled until needed.

Tool Priority: PowerShell (1st priority) > Python (2nd priority/fallback) > third-party (if required)
Exit Codes: 0=PASS, 1=FAIL, 2=N/A, 3=ERROR
"""

import json
import sys
import argparse
from pathlib import Path

# Configuration
VULN_ID = "V-220711"
STIG_ID = "WN10-00-000065"
SEVERITY = "low"

def load_config(config_file):
    """Load configuration from JSON file"""
    if not config_file or not Path(config_file).exists():
        return dict()
    with open(config_file, 'r') as f:
        return json.load(f)

def perform_check(config):
    """
    Perform the STIG check

    Returns:
        tuple: (passed: bool, evidence: dict, issues: list)
    """
    # TODO: Implement check logic based on:
    # Run "PowerShell".
    # Copy the lines below to the PowerShell window and enter.
    # 
    # "([ADSI]('WinNT://{0}' -f $env:COMPUTERNAME)).Children | Where { $_.SchemaClassName -eq 'user' } | ForEach {
    #    $user = ([ADSI]$_.Path)
    #    $lastLogin = $user.Properties.LastLogin.Value
    #    $enabled = ($user.Properties.UserFlags.Value -band 0x2) -ne 0x2
    #    if ($lastLogin -eq $null) {
    #       $lastLogin = 'Never'
    #    }
    #    Write-Host $user.Name $lastLogin $enabled 
    # }"
    # 
    # This will return a list of local accounts with the account name, last logon, and if the account is enabled (True/False).
    # For example: User1  10/31/2015  5:49:56  AM  True
    # 
    # Review the list to determine the finding validity for each account reported.
    # 
    # Exclude the following accounts:
    # Built-in administrator account (Disabled, SID ending in 500)

    # TODO: Implement specific check logic
    # This is a placeholder - customize based on check requirements
    return False, {}, ["Check not implemented"]

def main():
    parser = argparse.ArgumentParser(description='Unused accounts must be disabled or removed from the system after 35 days of inactivity.')
    parser.add_argument('--config', help='Configuration file path')
    parser.add_argument('--output-json', action='store_true', help='Output in JSON format')
    args = parser.parse_args()

    # Load configuration
    config = load_config(args.config)

    # Perform check
    try:
        passed, evidence, issues = perform_check(config)
    except Exception as e:
        if args.output_json:
            result = {
                "vuln_id": VULN_ID,
                "stig_id": STIG_ID,
                "severity": SEVERITY,
                "status": "Error",
                "finding_details": str(e),
                "comments": "Error during check execution",
                "compliance_issues": []
            }
            print(json.dumps(result, indent=2))
        else:
            print(f"[{VULN_ID}] ERROR - {str(e)}")
        return 3

    # Output results
    if args.output_json:
        result = dict()
        result["vuln_id"] = VULN_ID
        result["stig_id"] = STIG_ID
        result["severity"] = SEVERITY
        result["status"] = "NotAFinding" if passed else "Open"
        result["finding_details"] = "" if passed else "Check failed"
        result["comments"] = "Check passed" if passed else ""
        result["evidence"] = evidence if passed else dict()
        result["compliance_issues"] = [] if passed else issues
        print(json.dumps(result, indent=2))
    else:
        status = "PASS" if passed else "FAIL"
        finding_status = "NotAFinding" if passed else "Finding"
        print(f"[{VULN_ID}] {status} - {finding_status}")

    return 0 if passed else 1

if __name__ == '__main__':
    sys.exit(main())
