#!/usr/bin/env python3
"""
Deep analysis of Windows checks to map GPO paths to registry keys.
Windows Group Policy settings are stored in registry - we need to find those paths.
"""

import json
import re
from pathlib import Path
from collections import defaultdict

# Known GPO to Registry mappings for common Windows security settings
GPO_REGISTRY_MAP = {
    # Account Policies
    'account policies >> password policy': {
        'base_path': 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters',
        'common_keys': ['MaximumPasswordAge', 'MinimumPasswordAge', 'MinimumPasswordLength', 'PasswordComplexity']
    },
    'account policies >> account lockout': {
        'base_path': 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters',
        'common_keys': ['LockoutDuration', 'LockoutBadCount', 'ResetLockoutCount']
    },

    # Security Options
    'security options': {
        'base_path': 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa',
        'common_keys': ['LimitBlankPasswordUse', 'NoLMHash', 'restrictanonymous', 'restrictanonymoussam']
    },

    # Windows Components
    'windows components >> windows defender': {
        'base_path': 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows Defender',
        'common_keys': ['DisableAntiSpyware', 'DisableRoutinelyTakingAction']
    },
    'windows components >> windows update': {
        'base_path': 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate',
        'common_keys': ['AUOptions', 'NoAutoUpdate', 'ScheduledInstallDay']
    },
    'windows components >> remote desktop': {
        'base_path': 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services',
        'common_keys': ['fDenyTSConnections', 'fEncryptRPCTraffic', 'MinEncryptionLevel']
    },

    # Microsoft Office
    'microsoft office': {
        'base_path': 'HKCU:\\Software\\Policies\\Microsoft\\Office',
        'versions': ['16.0', '15.0'],  # Office 2016, 2013
        'apps': ['Word', 'Excel', 'PowerPoint', 'Outlook', 'Access']
    },
    'microsoft access': {
        'base_path': 'HKCU:\\Software\\Policies\\Microsoft\\Office\\16.0\\Access',
        'common_keys': ['Security']
    },
    'microsoft excel': {
        'base_path': 'HKCU:\\Software\\Policies\\Microsoft\\Office\\16.0\\Excel',
        'common_keys': ['Security', 'Options']
    },

    # System
    'system >> logon': {
        'base_path': 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System',
        'common_keys': ['LegalNoticeCaption', 'LegalNoticeText', 'DontDisplayLastUserName']
    },
    'system >> user profiles': {
        'base_path': 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList',
        'common_keys': []
    },
}

def extract_gpo_path(check_content: str) -> str:
    """Extract Group Policy path from check content"""

    patterns = [
        r'((?:Computer|User) Configuration\s*>>[^:]+)',
        r'Verify the policy value for\s+([^"]+)',
        r'Configure[:\s]+([^"]+?)\s+to',
    ]

    for pattern in patterns:
        match = re.search(pattern, check_content, re.IGNORECASE)
        if match:
            return match.group(1).strip()

    return None

def infer_registry_path(gpo_path: str, check_content: str) -> dict:
    """Infer registry path from GPO path and check content"""

    result = {
        'has_registry': False,
        'registry_path': None,
        'value_name': None,
        'expected_value': None,
        'confidence': 'unknown'
    }

    if not gpo_path:
        return result

    gpo_lower = gpo_path.lower()

    # Check against known mappings
    for key_phrase, mapping in GPO_REGISTRY_MAP.items():
        if key_phrase in gpo_lower:
            result['has_registry'] = True
            result['registry_path'] = mapping['base_path']
            result['confidence'] = 'high'

            # Try to extract specific value name from check content
            value_patterns = [
                r'"([^"]+)"\s+(?:value|setting)',
                r'Value:\s+([^\n]+)',
                r'Setting:\s+([^\n]+)',
            ]

            for pattern in value_patterns:
                match = re.search(pattern, check_content, re.IGNORECASE)
                if match:
                    result['value_name'] = match.group(1).strip()
                    break

            return result

    # Infer from GPO structure
    if 'administrative templates' in gpo_lower:
        if 'microsoft office' in gpo_lower or 'microsoft access' in gpo_lower:
            result['has_registry'] = True
            result['registry_path'] = 'HKCU:\\Software\\Policies\\Microsoft\\Office\\16.0'
            result['confidence'] = 'medium'

            # Extract specific Office app
            for app in ['Access', 'Excel', 'Word', 'PowerPoint', 'Outlook']:
                if app.lower() in gpo_lower:
                    result['registry_path'] += f'\\{app}'
                    break

        elif 'windows components' in gpo_lower:
            result['has_registry'] = True
            result['registry_path'] = 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows'
            result['confidence'] = 'medium'

        elif 'system' in gpo_lower:
            result['has_registry'] = True
            result['registry_path'] = 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System'
            result['confidence'] = 'medium'

    elif 'security settings' in gpo_lower:
        result['has_registry'] = True
        result['registry_path'] = 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa'
        result['confidence'] = 'medium'

    # Extract expected value
    value_patterns = [
        r'(?:must be|should be|set to)[:\s]+["\']?(\w+)["\']?',
        r'Enabled\s*\((\d+)\)',
        r'Disabled\s*\((\d+)\)',
    ]

    for pattern in value_patterns:
        match = re.search(pattern, check_content, re.IGNORECASE)
        if match:
            result['expected_value'] = match.group(1)
            break

    return result

def analyze_windows_checks():
    """Analyze all Windows checks for registry automation potential"""

    with open('windows_office_2025_stigs.json', 'r') as f:
        stigs = json.load(f)

    print("="*80)
    print("WINDOWS REGISTRY AUTOMATION ANALYSIS")
    print("="*80)
    print()

    # Filter to Windows/Office only
    windows_stigs = [s for s in stigs if any(x in s['benchmark'] for x in
                     ['Windows 10', 'Windows 11', 'Windows Server', 'Office', 'Excel', 'Word', 'PowerPoint', 'Outlook'])]

    print(f"Analyzing {len(windows_stigs)} Windows/Office STIGs...")
    print()

    by_confidence = defaultdict(list)
    stats = {
        'high': 0,
        'medium': 0,
        'low': 0,
        'unknown': 0,
        'total': len(windows_stigs)
    }

    for stig in windows_stigs:
        check_content = stig.get('check_content', '')
        gpo_path = extract_gpo_path(check_content)

        reg_info = infer_registry_path(gpo_path, check_content)

        if reg_info['has_registry']:
            stats[reg_info['confidence']] += 1
            by_confidence[reg_info['confidence']].append({
                'vuln_id': stig['vuln_id'],
                'benchmark': stig['benchmark'],
                'rule_title': stig['rule_title'][:60],
                'gpo_path': gpo_path,
                'registry_path': reg_info['registry_path'],
                'value_name': reg_info['value_name'],
                'expected_value': reg_info['expected_value']
            })
        else:
            stats['unknown'] += 1
            by_confidence['unknown'].append({
                'vuln_id': stig['vuln_id'],
                'benchmark': stig['benchmark'],
                'rule_title': stig['rule_title'][:60],
                'gpo_path': gpo_path,
                'check_preview': check_content[:200] if check_content else 'No content'
            })

    # Display statistics
    print("Registry Automation Potential:")
    print(f"  High Confidence:    {stats['high']:4d} ({stats['high']/stats['total']*100:.1f}%) - Known registry mappings")
    print(f"  Medium Confidence:  {stats['medium']:4d} ({stats['medium']/stats['total']*100:.1f}%) - Inferred from GPO structure")
    print(f"  Low Confidence:     {stats['low']:4d} ({stats['low']/stats['total']*100:.1f}%) - Needs research")
    print(f"  Unknown:            {stats['unknown']:4d} ({stats['unknown']/stats['total']*100:.1f}%) - No GPO path found")
    print("  " + "-" * 76)
    print(f"  Total:              {stats['total']:4d}")
    print()

    automatable = stats['high'] + stats['medium']
    print(f"🎯 AUTOMATABLE: {automatable} checks ({automatable/stats['total']*100:.1f}%)")
    print()

    # Show examples
    print("="*80)
    print("HIGH CONFIDENCE EXAMPLES (Known Registry Mappings)")
    print("="*80)

    for i, check in enumerate(by_confidence['high'][:10], 1):
        print(f"\n{i}. {check['vuln_id']} - {check['benchmark']}")
        print(f"   Title: {check['rule_title']}...")
        print(f"   GPO: {check['gpo_path']}")
        print(f"   Registry: {check['registry_path']}")
        if check['value_name']:
            print(f"   Value: {check['value_name']}")
        if check['expected_value']:
            print(f"   Expected: {check['expected_value']}")

    print("\n" + "="*80)
    print("MEDIUM CONFIDENCE EXAMPLES (Inferred Paths)")
    print("="*80)

    for i, check in enumerate(by_confidence['medium'][:10], 1):
        print(f"\n{i}. {check['vuln_id']} - {check['benchmark']}")
        print(f"   Title: {check['rule_title']}...")
        print(f"   GPO: {check['gpo_path']}")
        print(f"   Inferred Registry: {check['registry_path']}")

    print("\n" + "="*80)
    print("UNKNOWN EXAMPLES (Need Manual Research)")
    print("="*80)

    for i, check in enumerate(by_confidence['unknown'][:5], 1):
        print(f"\n{i}. {check['vuln_id']} - {check['benchmark']}")
        print(f"   Title: {check['rule_title']}...")
        print(f"   GPO: {check['gpo_path'] or 'Not found'}")
        print(f"   Check: {check['check_preview']}...")

    # Save results
    output = {
        'statistics': stats,
        'by_confidence': {k: v for k, v in by_confidence.items()}
    }

    with open('windows_registry_analysis.json', 'w') as f:
        json.dump(output, f, indent=2)

    print("\n" + "="*80)
    print("✅ Analysis saved to: windows_registry_analysis.json")
    print("="*80)

    return stats

if __name__ == '__main__':
    analyze_windows_checks()
