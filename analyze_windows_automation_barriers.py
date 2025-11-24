#!/usr/bin/env python3
"""
Analyze why Windows checks have lower automation rates compared to Oracle.
Identify specific barriers and categorize what prevents automation.
"""

import json
import re
from pathlib import Path
from collections import defaultdict

def load_windows_office_stigs():
    with open('windows_office_2025_stigs.json', 'r') as f:
        return json.load(f)

def detect_automation_barriers(check_content: str, discussion: str, rule_title: str) -> dict:
    """Identify specific barriers preventing automation"""

    barriers = {
        'is_automatable': True,
        'automation_method': [],
        'barriers': [],
        'complexity': 'simple',
        'requires_tools': [],
        'confidence': 'high'
    }

    combined = (check_content or '').lower() + ' ' + (discussion or '').lower()

    # Registry checks (highly automatable)
    if any(word in combined for word in ['registry', 'reg query', 'get-itemproperty', 'hklm:', 'hkcu:']):
        barriers['automation_method'].append('registry_query')
        barriers['requires_tools'].append('PowerShell Get-ItemProperty')

    # Audit policy checks (automatable with auditpol.exe)
    if 'audit' in combined and 'policy' in combined:
        barriers['automation_method'].append('audit_policy')
        barriers['requires_tools'].append('auditpol.exe')

    # User Rights Assignment (requires secedit or PowerShell)
    if 'user rights assignment' in combined or 'user right' in combined:
        barriers['automation_method'].append('user_rights')
        barriers['requires_tools'].append('secedit or Get-LocalUser')
        barriers['complexity'] = 'medium'

    # Group Policy verification
    if any(phrase in combined for phrase in ['group policy', 'gpo', 'gpresult', 'verify the policy']):
        barriers['automation_method'].append('group_policy')
        barriers['requires_tools'].append('gpresult or GPMC')

        # GPO checks can be complex
        if 'domain' in combined or 'active directory' in combined:
            barriers['complexity'] = 'complex'
            barriers['barriers'].append('Requires domain environment')

    # Service checks
    if any(word in combined for word in ['service', 'get-service', 'sc query']):
        barriers['automation_method'].append('service_status')
        barriers['requires_tools'].append('Get-Service or sc.exe')

    # File permission checks
    if any(word in combined for word in ['file permission', 'get-acl', 'icacls']):
        barriers['automation_method'].append('file_permissions')
        barriers['requires_tools'].append('Get-Acl or icacls.exe')

    # Firewall checks
    if 'firewall' in combined or 'windows defender firewall' in combined:
        barriers['automation_method'].append('firewall_rules')
        barriers['requires_tools'].append('Get-NetFirewallRule')

    # Event log checks
    if 'event log' in combined or 'get-winevent' in combined:
        barriers['automation_method'].append('event_log')
        barriers['requires_tools'].append('Get-WinEvent')

    # Active Directory checks
    if any(phrase in combined for phrase in ['active directory', 'domain controller', 'ad ds', 'ldap']):
        barriers['automation_method'].append('active_directory')
        barriers['requires_tools'].append('Active Directory PowerShell module')
        barriers['complexity'] = 'complex'
        barriers['barriers'].append('Requires Active Directory environment')

    # BitLocker checks
    if 'bitlocker' in combined or 'manage-bde' in combined:
        barriers['automation_method'].append('bitlocker')
        barriers['requires_tools'].append('manage-bde.exe or Get-BitLockerVolume')
        barriers['complexity'] = 'medium'

    # Certificate checks
    if any(word in combined for word in ['certificate', 'cert:', 'get-childitem cert:']):
        barriers['automation_method'].append('certificate_store')
        barriers['requires_tools'].append('Get-ChildItem Cert:')

    # Manual verification barriers
    if any(phrase in combined for phrase in [
        'interview the', 'review documentation', 'obtain a list', 'ask the',
        'consult with', 'review with', 'if there is a documented'
    ]):
        barriers['barriers'].append('Requires manual interview/documentation')
        barriers['is_automatable'] = False
        barriers['confidence'] = 'low'

    # Organization-defined parameters
    if any(phrase in combined for phrase in [
        'organization-defined', 'site-defined', 'organizationally defined',
        'as appropriate for the organization'
    ]):
        barriers['barriers'].append('Requires organization-defined parameters')
        barriers['complexity'] = 'medium'

    # Complex multi-step checks
    if combined.count('and') > 5 or combined.count('verify') > 3:
        barriers['complexity'] = 'complex'

    # Physical access required
    if any(phrase in combined for phrase in ['physical access', 'console access', 'local access']):
        barriers['barriers'].append('Requires physical/console access')
        barriers['complexity'] = 'complex'

    # GUI/Manual tools required
    if any(tool in combined for tool in ['gpedit.msc', 'mmc', 'secpol.msc', 'lusrmgr.msc', 'manually']):
        barriers['barriers'].append('Requires GUI tools or manual steps')
        barriers['complexity'] = 'medium'

    # Application-specific checks (Office, IE, Edge)
    if any(app in combined for app in ['microsoft office', 'excel', 'word', 'outlook', 'internet explorer', 'edge']):
        barriers['automation_method'].append('application_registry')
        barriers['requires_tools'].append('Application-specific registry keys')

    # Determine if truly automatable
    if not barriers['automation_method']:
        barriers['is_automatable'] = False
        barriers['barriers'].append('No clear automation method identified')
        barriers['confidence'] = 'unknown'

    return barriers

def analyze_windows_automation():
    """Comprehensive Windows automation barrier analysis"""

    stigs = load_windows_office_stigs()

    print("=" * 80)
    print("WINDOWS AUTOMATION BARRIER ANALYSIS")
    print("=" * 80)
    print(f"\nAnalyzing {len(stigs)} Windows/Office 2025 STIGs...\n")

    # Statistics
    by_complexity = defaultdict(list)
    by_automation_method = defaultdict(list)
    by_barrier = defaultdict(list)
    by_tool = defaultdict(int)

    automatable_count = 0
    not_automatable_count = 0

    for stig in stigs:
        check_content = stig.get('check_content', '')
        discussion = stig.get('discussion', '')
        rule_title = stig.get('rule_title', '')

        analysis = detect_automation_barriers(check_content, discussion, rule_title)

        if analysis['is_automatable']:
            automatable_count += 1
        else:
            not_automatable_count += 1

        # Categorize by complexity
        by_complexity[analysis['complexity']].append({
            'vuln_id': stig['vuln_id'],
            'benchmark': stig['benchmark'],
            'rule_title': rule_title[:60],
            'barriers': analysis['barriers'],
            'tools': analysis['requires_tools'],
            'methods': analysis['automation_method']
        })

        # Count automation methods
        for method in analysis['automation_method']:
            by_automation_method[method].append(stig['vuln_id'])

        # Count barriers
        for barrier in analysis['barriers']:
            by_barrier[barrier].append({
                'vuln_id': stig['vuln_id'],
                'benchmark': stig['benchmark'],
                'rule_title': rule_title[:60]
            })

        # Count tools
        for tool in analysis['requires_tools']:
            by_tool[tool] += 1

    # Display overall stats
    print("=" * 80)
    print("OVERALL AUTOMATION ANALYSIS")
    print("=" * 80)
    print(f"Total checks:                    {len(stigs)}")
    print(f"Automatable:                     {automatable_count:4d} ({automatable_count/len(stigs)*100:.1f}%)")
    print(f"Not automatable:                 {not_automatable_count:4d} ({not_automatable_count/len(stigs)*100:.1f}%)")
    print()

    # Display by complexity
    print("=" * 80)
    print("COMPLEXITY BREAKDOWN")
    print("=" * 80)
    for complexity in ['simple', 'medium', 'complex']:
        count = len(by_complexity[complexity])
        if count > 0:
            pct = count / len(stigs) * 100
            print(f"{complexity.title():15s} {count:4d} ({pct:5.1f}%)")
    print()

    # Display automation methods
    print("=" * 80)
    print("AUTOMATION METHODS AVAILABLE")
    print("=" * 80)
    sorted_methods = sorted(by_automation_method.items(), key=lambda x: len(x[1]), reverse=True)
    for method, vuln_ids in sorted_methods[:15]:
        count = len(vuln_ids)
        pct = count / len(stigs) * 100
        print(f"{method.replace('_', ' ').title():30s} {count:4d} ({pct:5.1f}%)")
    print()

    # Display barriers
    print("=" * 80)
    print("AUTOMATION BARRIERS IDENTIFIED")
    print("=" * 80)
    if by_barrier:
        sorted_barriers = sorted(by_barrier.items(), key=lambda x: len(x[1]), reverse=True)
        for barrier, checks in sorted_barriers:
            count = len(checks)
            pct = count / len(stigs) * 100
            print(f"{barrier:50s} {count:4d} ({pct:5.1f}%)")
    else:
        print("No significant barriers identified")
    print()

    # Display required tools
    print("=" * 80)
    print("TOOLS REQUIRED FOR AUTOMATION")
    print("=" * 80)
    sorted_tools = sorted(by_tool.items(), key=lambda x: x[1], reverse=True)
    for tool, count in sorted_tools[:15]:
        pct = count / len(stigs) * 100
        print(f"{tool:50s} {count:4d} ({pct:5.1f}%)")
    print()

    # Show examples of barriers
    print("=" * 80)
    print("EXAMPLES: CHECKS WITH AUTOMATION BARRIERS")
    print("=" * 80)

    # Show complex checks
    if by_complexity['complex']:
        print("\nCOMPLEX CHECKS (require multiple steps or special environment)")
        print("-" * 80)
        for i, check in enumerate(by_complexity['complex'][:5], 1):
            print(f"\n{i}. {check['vuln_id']} - {check['benchmark']}")
            print(f"   Title: {check['rule_title']}...")
            if check['barriers']:
                print(f"   Barriers: {', '.join(check['barriers'])}")
            if check['tools']:
                print(f"   Tools needed: {', '.join(check['tools'][:2])}")

    # Show checks requiring manual steps
    if 'Requires manual interview/documentation' in by_barrier:
        print("\n\nMANUAL VERIFICATION REQUIRED")
        print("-" * 80)
        for i, check in enumerate(by_barrier['Requires manual interview/documentation'][:5], 1):
            print(f"\n{i}. {check['vuln_id']} - {check['benchmark']}")
            print(f"   Title: {check['rule_title']}...")

    # Show checks requiring GUI tools
    if 'Requires GUI tools or manual steps' in by_barrier:
        print("\n\nGUI TOOLS REQUIRED")
        print("-" * 80)
        for i, check in enumerate(by_barrier['Requires GUI tools or manual steps'][:5], 1):
            print(f"\n{i}. {check['vuln_id']} - {check['benchmark']}")
            print(f"   Title: {check['rule_title']}...")

    # Comparison with Oracle
    print("\n" + "=" * 80)
    print("COMPARISON: WINDOWS vs ORACLE AUTOMATION")
    print("=" * 80)
    print(f"Windows Automatable:    {automatable_count:4d} / {len(stigs):4d} ({automatable_count/len(stigs)*100:.1f}%)")
    print(f"Oracle Automatable:     1519 / 1522 (99.8%)")
    print()
    print("Why is Oracle higher?")
    print("-" * 80)
    print("✓ Oracle checks are mostly Linux OS-level (file perms, config files, packages)")
    print("✓ Oracle uses standard bash commands (stat, grep, rpm, sysctl)")
    print("✓ Oracle config files are text-based and easily parseable")
    print("✓ Oracle SQL queries are explicit and self-contained")
    print()
    print("Windows challenges:")
    print("-" * 80)
    print("✗ Many checks require domain/Active Directory environment")
    print("✗ Group Policy verification is complex (multiple sources)")
    print("✗ Some checks require GUI tools (gpedit.msc, secpol.msc)")
    print("✗ Audit policies and user rights require elevated privileges")
    print("✗ Organization-defined parameters more common in Windows")
    print("✗ Application checks (Office) have version-specific registry paths")
    print()

    # Save detailed results
    output = {
        'summary': {
            'total': len(stigs),
            'automatable': automatable_count,
            'not_automatable': not_automatable_count,
            'automation_percentage': round(automatable_count / len(stigs) * 100, 1)
        },
        'by_complexity': {
            complexity: len(checks)
            for complexity, checks in by_complexity.items()
        },
        'automation_methods': {
            method: len(vuln_ids)
            for method, vuln_ids in by_automation_method.items()
        },
        'barriers': {
            barrier: len(checks)
            for barrier, checks in by_barrier.items()
        },
        'required_tools': dict(sorted_tools),
        'detailed_analysis': {
            'complex_checks': by_complexity['complex'][:20],
            'manual_checks': by_barrier.get('Requires manual interview/documentation', [])[:20]
        }
    }

    with open('windows_automation_barriers.json', 'w') as f:
        json.dump(output, f, indent=2)

    print("=" * 80)
    print("✅ Detailed analysis saved to: windows_automation_barriers.json")
    print("=" * 80)

if __name__ == '__main__':
    analyze_windows_automation()
