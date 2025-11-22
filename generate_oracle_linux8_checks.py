#!/usr/bin/env python3
"""
Extract Oracle Linux 8 STIG checks and generate automated check framework
Following the pattern established in Test-Weblogic-3:
- Bash/Python priority (native tools first)
- Configuration file support
- Detailed audit evidence
"""

import json
import os
import re
from pathlib import Path
from collections import defaultdict

def analyze_check_automation(check):
    """Analyze if a check can be automated and how"""
    check_content = check.get('Check Content', '').lower()
    fix_text = check.get('Fix Text', '').lower()
    rule_title = check.get('Rule Title', '').lower()

    automation_status = 'Unknown'
    automation_method = ''
    requires_elevation = False
    notes = []
    is_environment_specific = False
    is_system_specific = False
    environment_notes = ''
    preferred_tool = 'Bash'
    third_party_required = False
    third_party_tools = []

    # Check for manual review requirements
    manual_keywords = [
        'manual review', 'manually review', 'site security plan',
        'organizational policy', 'documented', 'network diagram',
        'organizational requirement', 'organization-defined'
    ]
    if any(keyword in check_content for keyword in manual_keywords):
        automation_status = 'Manual Review Required'
        notes.append('Requires policy/documentation review')
        return automation_status, automation_method, requires_elevation, '; '.join(notes), \
               is_environment_specific, is_system_specific, environment_notes, \
               preferred_tool, third_party_required, third_party_tools

    # File system checks
    if any(cmd in check_content for cmd in ['find /', 'ls -', 'stat ', 'file permissions', 'ownership']):
        automation_status = 'Fully Automated'
        automation_method = 'Bash (find, ls, stat)'
        requires_elevation = 'sudo' in check_content or 'root' in check_content
        preferred_tool = 'Bash'

    # Configuration file checks
    elif any(cmd in check_content for cmd in ['grep', 'cat ', '/etc/', '/var/', 'configuration']):
        automation_status = 'Fully Automated'
        automation_method = 'Bash (grep, cat, awk)'
        requires_elevation = True
        preferred_tool = 'Bash'

        # Check if environment-specific
        if any(term in check_content for term in ['approved', 'authorized', 'organization', 'site-defined']):
            is_environment_specific = True
            environment_notes = 'Requires approved/authorized values in config file'

    # Package/RPM checks
    elif any(cmd in check_content for cmd in ['rpm -', 'yum ', 'dnf ', 'package']):
        automation_status = 'Fully Automated'
        automation_method = 'Bash (rpm, yum, dnf)'
        requires_elevation = False
        preferred_tool = 'Bash'

    # Service/systemd checks
    elif any(cmd in check_content for cmd in ['systemctl', 'service ', 'systemd']):
        automation_status = 'Fully Automated'
        automation_method = 'Bash (systemctl)'
        requires_elevation = False
        preferred_tool = 'Bash'

    # SELinux checks
    elif any(cmd in check_content for cmd in ['getenforce', 'selinux', 'sestatus', 'getsebool']):
        automation_status = 'Fully Automated'
        automation_method = 'Bash (SELinux commands)'
        requires_elevation = False
        preferred_tool = 'Bash'

    # Firewall checks
    elif any(cmd in check_content for cmd in ['firewall-cmd', 'iptables', 'firewalld']):
        automation_status = 'Fully Automated'
        automation_method = 'Bash (firewall-cmd, iptables)'
        requires_elevation = True
        preferred_tool = 'Bash'

        if 'approved' in check_content or 'authorized' in check_content:
            is_environment_specific = True
            environment_notes = 'Requires approved ports/services in config file'

    # Audit (auditd) checks
    elif any(cmd in check_content for cmd in ['auditctl', 'aureport', 'ausearch', '/etc/audit']):
        automation_status = 'Fully Automated'
        automation_method = 'Bash (auditctl, aureport)'
        requires_elevation = True
        preferred_tool = 'Bash'

    # User/account checks
    elif any(cmd in check_content for cmd in ['passwd', 'shadow', 'group', 'getent', '/etc/passwd']):
        automation_status = 'Fully Automated'
        automation_method = 'Bash (getent, passwd)'
        requires_elevation = True
        preferred_tool = 'Bash'

        if any(term in check_content for term in ['authorized', 'approved users', 'privileged']):
            is_environment_specific = True
            environment_notes = 'Requires authorized user list in config file'

    # Kernel parameter checks
    elif any(cmd in check_content for cmd in ['sysctl', '/proc/sys', 'kernel parameter']):
        automation_status = 'Fully Automated'
        automation_method = 'Bash (sysctl)'
        requires_elevation = False
        preferred_tool = 'Bash'

    # Crypto/FIPS checks
    elif any(term in check_content for term in ['fips', 'crypto', 'encryption', 'certificate']):
        automation_status = 'Fully Automated'
        automation_method = 'Bash (openssl, update-crypto-policies)'
        requires_elevation = False
        preferred_tool = 'Bash'

        if 'approved cipher' in check_content or 'approved algorithm' in check_content:
            is_environment_specific = True
            environment_notes = 'Requires approved cipher suites in config file'

    # Network checks
    elif any(cmd in check_content for cmd in ['ip addr', 'ifconfig', 'netstat', 'ss ']):
        automation_status = 'Fully Automated'
        automation_method = 'Bash (ip, ss, netstat)'
        requires_elevation = False
        preferred_tool = 'Bash'

    # SSH checks
    elif 'sshd_config' in check_content or 'ssh ' in check_content:
        automation_status = 'Fully Automated'
        automation_method = 'Bash (sshd -T, grep)'
        requires_elevation = True
        preferred_tool = 'Bash'

        if 'approved cipher' in check_content or 'approved mac' in check_content:
            is_environment_specific = True
            environment_notes = 'Requires approved SSH ciphers/MACs in config file'

    # Logging checks
    elif any(cmd in check_content for cmd in ['rsyslog', 'journalctl', '/var/log']):
        automation_status = 'Fully Automated'
        automation_method = 'Bash (journalctl, grep)'
        requires_elevation = True
        preferred_tool = 'Bash'

    else:
        automation_status = 'Potentially Automated'
        automation_method = 'Requires custom bash/python script'
        notes.append('Check content needs detailed analysis')

    # Check for third-party tools
    third_party_keywords = {
        'aide': 'AIDE (Advanced Intrusion Detection Environment)',
        'tripwire': 'Tripwire',
        'nessus': 'Nessus',
        'McAfee': 'McAfee',
        'splunk': 'Splunk'
    }

    for keyword, tool_name in third_party_keywords.items():
        if keyword in check_content:
            third_party_required = True
            third_party_tools.append(tool_name)
            notes.append(f'Requires {tool_name}')

    return automation_status, automation_method, requires_elevation, '; '.join(notes), \
           is_environment_specific, is_system_specific, environment_notes, \
           preferred_tool, third_party_required, third_party_tools


def main():
    # Read AllSTIGS2.json
    with open('/home/user/STIGcheckScripts/AllSTIGS2.json', 'r') as f:
        all_checks = json.load(f)

    # Filter Oracle Linux 8 checks
    ol8_checks = [
        check for check in all_checks
        if 'Oracle Linux 8' in check.get('STIG', '')
    ]

    print(f"Found {len(ol8_checks)} Oracle Linux 8 STIG checks")

    # Analyze automation feasibility
    automation_stats = defaultdict(int)
    severity_stats = defaultdict(int)
    environment_specific_count = 0
    third_party_count = 0

    analyzed_checks = []

    for check in ol8_checks:
        automation_status, automation_method, requires_elevation, notes, \
        is_env_specific, is_sys_specific, env_notes, preferred_tool, \
        third_party_req, third_party_tools = analyze_check_automation(check)

        check['automation_status'] = automation_status
        check['automation_method'] = automation_method
        check['requires_elevation'] = requires_elevation
        check['automation_notes'] = notes
        check['is_environment_specific'] = is_env_specific
        check['is_system_specific'] = is_sys_specific
        check['environment_notes'] = env_notes
        check['preferred_tool'] = preferred_tool
        check['third_party_required'] = third_party_req
        check['third_party_tools'] = third_party_tools

        analyzed_checks.append(check)

        automation_stats[automation_status] += 1
        severity_stats[check.get('Severity', 'unknown')] += 1

        if is_env_specific:
            environment_specific_count += 1
        if third_party_req:
            third_party_count += 1

    # Create output directory
    output_dir = Path('/home/user/STIGcheckScripts/checks/os/oracle_linux_8')
    output_dir.mkdir(parents=True, exist_ok=True)

    # Generate markdown report
    report_path = output_dir / 'Oracle_Linux_8_STIG_Analysis.md'

    with open(report_path, 'w') as f:
        f.write("# Oracle Linux 8 STIG Automation Analysis\n\n")
        f.write("## Overview\n\n")
        f.write(f"**Total Checks**: {len(ol8_checks)}\n\n")
        f.write(f"**STIG Version**: Oracle Linux 8 Security Technical Implementation Guide :: Version 1, Release: 7\n\n")
        f.write(f"**Benchmark Date**: 26 Jul 2023\n\n")

        # Summary table
        f.write("## Automation Summary\n\n")
        f.write("| Metric | Count | Percentage |\n")
        f.write("|--------|-------|------------|\n")

        fully_automated = automation_stats.get('Fully Automated', 0)
        potentially_automated = automation_stats.get('Potentially Automated', 0)
        manual_required = automation_stats.get('Manual Review Required', 0)

        f.write(f"| Fully Automated | {fully_automated} | {fully_automated/len(ol8_checks)*100:.1f}% |\n")
        f.write(f"| Potentially Automated | {potentially_automated} | {potentially_automated/len(ol8_checks)*100:.1f}% |\n")
        f.write(f"| Manual Review Required | {manual_required} | {manual_required/len(ol8_checks)*100:.1f}% |\n")
        f.write(f"| Environment-Specific | {environment_specific_count} | {environment_specific_count/len(ol8_checks)*100:.1f}% |\n")
        f.write(f"| Requires Third-Party Tools | {third_party_count} | {third_party_count/len(ol8_checks)*100:.1f}% |\n")
        f.write(f"| **Total Automatable** | **{fully_automated + potentially_automated}** | **{(fully_automated + potentially_automated)/len(ol8_checks)*100:.1f}%** |\n\n")

        # Severity distribution
        f.write("## Severity Distribution\n\n")
        f.write("| Severity | Count | Percentage |\n")
        f.write("|----------|-------|------------|\n")
        for severity in ['high', 'medium', 'low']:
            count = severity_stats.get(severity, 0)
            f.write(f"| {severity.upper()} | {count} | {count/len(ol8_checks)*100:.1f}% |\n")
        f.write("\n")

        # Tool requirements
        f.write("## Tool Requirements\n\n")
        f.write("### Native Tools (Bash)\n")
        f.write("- File system commands: `find`, `ls`, `stat`, `chmod`, `chown`\n")
        f.write("- Configuration: `grep`, `cat`, `awk`, `sed`\n")
        f.write("- Package management: `rpm`, `yum`, `dnf`\n")
        f.write("- Services: `systemctl`\n")
        f.write("- SELinux: `getenforce`, `sestatus`, `getsebool`\n")
        f.write("- Firewall: `firewall-cmd`, `iptables`\n")
        f.write("- Audit: `auditctl`, `aureport`, `ausearch`\n")
        f.write("- Users: `getent`, `passwd`, `lastlog`\n")
        f.write("- Kernel: `sysctl`, `uname`\n")
        f.write("- Crypto: `openssl`, `update-crypto-policies`\n")
        f.write("- Network: `ip`, `ss`, `netstat`\n")
        f.write("- SSH: `sshd`, `ssh-keygen`\n")
        f.write("- Logging: `journalctl`, `rsyslog`\n\n")

        f.write("### Fallback (Python 3.6+)\n")
        f.write("- Standard library modules: `os`, `subprocess`, `pathlib`, `re`\n\n")

        if third_party_count > 0:
            f.write("### Third-Party Tools (When Required)\n")
            all_third_party = set()
            for check in analyzed_checks:
                all_third_party.update(check['third_party_tools'])
            for tool in sorted(all_third_party):
                f.write(f"- {tool}\n")
            f.write("\n")

        # Configuration file requirements
        f.write("## Configuration File Requirements\n\n")
        f.write(f"**{environment_specific_count}** checks ({environment_specific_count/len(ol8_checks)*100:.1f}%) require environment-specific values:\n\n")

        env_categories = defaultdict(list)
        for check in analyzed_checks:
            if check['is_environment_specific']:
                env_categories[check['environment_notes']].append(check['Vuln ID'])

        for category, vuln_ids in env_categories.items():
            f.write(f"- **{category}**: {len(vuln_ids)} checks\n")
        f.write("\n")

        # Detailed check list
        f.write("## Detailed Check Analysis\n\n")
        f.write("| Vuln ID | Severity | Automation Status | Method | Elevation | Third-Party | Notes |\n")
        f.write("|---------|----------|-------------------|---------|-----------|-------------|-------|\n")

        for check in analyzed_checks:
            vuln_id = check.get('Vuln ID', 'N/A')
            severity = check.get('Severity', 'unknown').upper()
            auto_status = check['automation_status']
            method = check['automation_method'][:40] if check['automation_method'] else 'N/A'
            elevation = 'Yes' if check['requires_elevation'] else 'No'
            third_party = 'Yes' if check['third_party_required'] else 'No'
            notes = check['automation_notes'][:50] if check['automation_notes'] else ''

            f.write(f"| {vuln_id} | {severity} | {auto_status} | {method} | {elevation} | {third_party} | {notes} |\n")

        f.write("\n")

        # Sample checks section
        f.write("## Sample Check Implementation\n\n")
        f.write("See the following directories for sample implementations:\n\n")
        f.write("- `samples/` - Sample bash and python checks\n")
        f.write("- `stig-config.json` - Environment-specific configuration file\n")
        f.write("- `CONFIG-GUIDE.md` - Configuration customization guide\n")
        f.write("- `EXAMPLE-OUTPUT.md` - Example check outputs with audit evidence\n\n")

        # Usage section
        f.write("## Usage\n\n")
        f.write("### Basic Check (Default Values)\n")
        f.write("```bash\n")
        f.write("# Bash (preferred)\n")
        f.write("bash V-252518.sh\n\n")
        f.write("# Python (fallback)\n")
        f.write("python3 V-252518.py\n")
        f.write("```\n\n")

        f.write("### With Configuration File\n")
        f.write("```bash\n")
        f.write("# Bash with environment-specific values\n")
        f.write("bash V-252518.sh --config stig-config.json\n\n")
        f.write("# Python with environment-specific values\n")
        f.write("python3 V-252518.py --config stig-config.json\n")
        f.write("```\n\n")

        f.write("### With JSON Output\n")
        f.write("```bash\n")
        f.write("bash V-252518.sh --config stig-config.json --output-json results.json\n")
        f.write("```\n\n")

    print(f"Report generated: {report_path}")

    # Save analyzed data
    analyzed_data_path = output_dir / 'analyzed_checks.json'
    with open(analyzed_data_path, 'w') as f:
        json.dump(analyzed_checks, f, indent=2)

    print(f"Analyzed data saved: {analyzed_data_path}")

    # Print summary
    print("\n=== Summary ===")
    print(f"Total checks: {len(ol8_checks)}")
    print(f"Fully automated: {fully_automated} ({fully_automated/len(ol8_checks)*100:.1f}%)")
    print(f"Potentially automated: {potentially_automated} ({potentially_automated/len(ol8_checks)*100:.1f}%)")
    print(f"Manual review required: {manual_required} ({manual_required/len(ol8_checks)*100:.1f}%)")
    print(f"Environment-specific: {environment_specific_count} ({environment_specific_count/len(ol8_checks)*100:.1f}%)")
    print(f"Requires third-party: {third_party_count} ({third_party_count/len(ol8_checks)*100:.1f}%)")


if __name__ == '__main__':
    main()
