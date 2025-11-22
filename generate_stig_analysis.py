#!/usr/bin/env python3
"""
Universal STIG Analysis and Report Generator

Analyzes STIG checks from AllSTIGS2.json for any STIG type and generates
automation analysis reports.

Usage:
    python3 generate_stig_analysis.py --stig-filter "Oracle Linux 7" --output-dir checks/os/oracle_linux_7_v2r12
    python3 generate_stig_analysis.py --stig-filter "Oracle Linux 8" --output-dir checks/os/oracle_linux_8_v1r7
    python3 generate_stig_analysis.py --stig-filter "Windows Server 2022" --output-dir checks/os/windows_server_2022_v1r4
"""

import json
import argparse
from pathlib import Path
from collections import defaultdict
import re


def analyze_check_automation(check, platform='linux'):
    """Analyze if a check can be automated and how"""
    check_content = check.get('Check Content', '').lower()
    fix_text = check.get('Fix Text', '').lower()
    rule_title = check.get('Rule Title', '').lower()

    automation_status = 'Unknown'
    automation_method = ''
    requires_elevation = False
    notes = []
    is_environment_specific = False
    environment_notes = ''
    preferred_tool = 'Bash' if platform == 'linux' else 'PowerShell'
    third_party_required = False
    third_party_tools = []

    # Manual review keywords
    manual_keywords = [
        'manual review', 'manually review', 'site security plan',
        'organizational policy', 'documented', 'network diagram',
        'organizational requirement', 'organization-defined'
    ]
    if any(keyword in check_content for keyword in manual_keywords):
        automation_status = 'Manual Review Required'
        notes.append('Requires policy/documentation review')
        return (automation_status, automation_method, requires_elevation, '; '.join(notes),
                is_environment_specific, environment_notes, preferred_tool, third_party_required, third_party_tools)

    # Linux/UNIX checks
    if platform == 'linux':
        # Package checks
        if any(cmd in check_content for cmd in ['rpm -', 'yum ', 'dnf ', 'package']):
            automation_status = 'Fully Automated'
            automation_method = 'Bash (rpm, yum, dnf)'
            requires_elevation = False

        # Service checks
        elif any(cmd in check_content for cmd in ['systemctl', 'service ', 'systemd', 'chkconfig']):
            automation_status = 'Fully Automated'
            automation_method = 'Bash (systemctl/service)'
            requires_elevation = False

        # SELinux checks
        elif any(cmd in check_content for cmd in ['getenforce', 'selinux', 'sestatus', 'getsebool']):
            automation_status = 'Fully Automated'
            automation_method = 'Bash (SELinux commands)'
            requires_elevation = False

        # Configuration file checks
        elif '/etc/' in check_content or 'configuration' in check_content:
            automation_status = 'Fully Automated'
            automation_method = 'Bash (grep, awk, sed)'
            requires_elevation = True

            if any(term in check_content for term in ['approved', 'authorized', 'organization']):
                is_environment_specific = True
                environment_notes = 'Requires approved/authorized values in config file'

        # Firewall checks
        elif any(cmd in check_content for cmd in ['firewall', 'iptables', 'firewalld']):
            automation_status = 'Fully Automated'
            automation_method = 'Bash (firewall-cmd, iptables)'
            requires_elevation = True

        # Audit checks
        elif any(cmd in check_content for cmd in ['auditctl', 'aureport', 'ausearch', '/etc/audit']):
            automation_status = 'Fully Automated'
            automation_method = 'Bash (auditctl, aureport)'
            requires_elevation = True

        # User/account checks
        elif any(cmd in check_content for cmd in ['passwd', 'shadow', 'group', 'getent']):
            automation_status = 'Fully Automated'
            automation_method = 'Bash (getent, passwd)'
            requires_elevation = True

        # Kernel parameter checks
        elif any(cmd in check_content for cmd in ['sysctl', '/proc/sys']):
            automation_status = 'Fully Automated'
            automation_method = 'Bash (sysctl)'
            requires_elevation = False

        # File permission checks
        elif any(cmd in check_content for cmd in ['find /', 'ls -', 'stat ']):
            automation_status = 'Fully Automated'
            automation_method = 'Bash (find, ls, stat)'
            requires_elevation = 'sudo' in check_content or '/root' in check_content

        # Command-based checks
        elif '$ ' in check_content or 'command:' in check_content:
            automation_status = 'Fully Automated'
            automation_method = 'Bash (command output validation)'
            requires_elevation = 'sudo' in check_content

        else:
            automation_status = 'Potentially Automated'
            automation_method = 'Bash script required'

    # Windows checks
    elif platform == 'windows':
        # Registry checks
        if 'registry' in check_content or 'hkey' in check_content or 'hklm' in check_content:
            automation_status = 'Fully Automated'
            automation_method = 'PowerShell (Get-ItemProperty)'
            requires_elevation = True

        # Group Policy checks
        elif 'group policy' in check_content or 'gpo' in check_content:
            automation_status = 'Fully Automated'
            automation_method = 'PowerShell (Get-GPO, Get-GPRegistryValue)'
            requires_elevation = True

        # Service checks
        elif 'service' in check_content and 'get-service' in check_content:
            automation_status = 'Fully Automated'
            automation_method = 'PowerShell (Get-Service)'
            requires_elevation = False

        # User/Group checks
        elif any(term in check_content for term in ['get-localuser', 'get-localgroup', 'net user']):
            automation_status = 'Fully Automated'
            automation_method = 'PowerShell (Get-LocalUser, Get-LocalGroup)'
            requires_elevation = True

        else:
            automation_status = 'Potentially Automated'
            automation_method = 'PowerShell script required'

    # Check for third-party tools
    third_party_keywords = {
        'aide': 'AIDE',
        'tripwire': 'Tripwire',
        'nessus': 'Nessus',
        'McAfee': 'McAfee',
        'splunk': 'Splunk'
    }
    for keyword, tool_name in third_party_keywords.items():
        if keyword in check_content:
            third_party_required = True
            third_party_tools.append(tool_name)

    return (automation_status, automation_method, requires_elevation, '; '.join(notes),
            is_environment_specific, environment_notes, preferred_tool, third_party_required, third_party_tools)


def main():
    parser = argparse.ArgumentParser(description='Analyze STIG checks for automation feasibility')
    parser.add_argument('--stig-filter', required=True, help='Filter string for STIG (e.g., "Oracle Linux 7")')
    parser.add_argument('--output-dir', required=True, help='Output directory for analysis')
    parser.add_argument('--platform', default='linux', choices=['linux', 'windows'], help='Platform type')
    parser.add_argument('--source-json', default='AllSTIGS2.json', help='Source STIG JSON file')

    args = parser.parse_args()

    # Load source data
    print(f"Loading {args.source_json}...")
    with open(args.source_json, 'r') as f:
        all_checks = json.load(f)

    # Filter for specific STIG
    checks = [c for c in all_checks if args.stig_filter in c.get('STIG', '')]
    print(f"Found {len(checks)} checks for filter '{args.stig_filter}'")

    if not checks:
        print(f"ERROR: No checks found for filter '{args.stig_filter}'")
        return 1

    # Get STIG version info
    stig_full = checks[0].get('STIG', '')
    print(f"STIG: {stig_full}")

    # Analyze each check
    analyzed_checks = []
    stats = defaultdict(int)
    env_specific_count = 0
    third_party_count = 0

    for check in checks:
        (auto_status, auto_method, req_elevation, notes, is_env, env_notes,
         pref_tool, third_party, tp_tools) = analyze_check_automation(check, args.platform)

        check['automation_status'] = auto_status
        check['automation_method'] = auto_method
        check['requires_elevation'] = req_elevation
        check['automation_notes'] = notes
        check['is_environment_specific'] = is_env
        check['environment_notes'] = env_notes
        check['preferred_tool'] = pref_tool
        check['third_party_required'] = third_party
        check['third_party_tools'] = tp_tools

        analyzed_checks.append(check)
        stats[auto_status] += 1
        if is_env:
            env_specific_count += 1
        if third_party:
            third_party_count += 1

    # Create output directory
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    # Save analyzed checks
    analyzed_file = output_dir / 'analyzed_checks.json'
    with open(analyzed_file, 'w') as f:
        json.dump(analyzed_checks, f, indent=2)
    print(f"\nSaved analyzed checks to: {analyzed_file}")

    # Print summary
    print(f"\n{'='*80}")
    print(f"Analysis Summary")
    print(f"{'='*80}")
    print(f"Total checks: {len(checks)}")
    print(f"Fully Automated: {stats.get('Fully Automated', 0)} ({stats.get('Fully Automated', 0)/len(checks)*100:.1f}%)")
    print(f"Potentially Automated: {stats.get('Potentially Automated', 0)} ({stats.get('Potentially Automated', 0)/len(checks)*100:.1f}%)")
    print(f"Manual Review Required: {stats.get('Manual Review Required', 0)} ({stats.get('Manual Review Required', 0)/len(checks)*100:.1f}%)")
    print(f"Environment-Specific: {env_specific_count} ({env_specific_count/len(checks)*100:.1f}%)")
    print(f"Requires Third-Party: {third_party_count} ({third_party_count/len(checks)*100:.1f}%)")

    automatable = stats.get('Fully Automated', 0) + stats.get('Potentially Automated', 0)
    print(f"\n**Total Automatable**: {automatable} ({automatable/len(checks)*100:.1f}%)")

    return 0


if __name__ == '__main__':
    exit(main())
