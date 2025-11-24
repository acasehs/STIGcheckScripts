#!/usr/bin/env python3
"""
Analyze all STIG checks and categorize by automation potential.
Uses AllSTIGS2.json to get actual check content and determine what can be automated.
"""

import json
import re
from pathlib import Path
from collections import defaultdict

def load_stig_data():
    """Load and index STIG data by VULN ID (Group ID)"""
    with open('/home/user/STIGcheckScripts/AllSTIGS2.json', 'r') as f:
        data = json.load(f)

    # Index by Group ID (VULN ID)
    stig_map = {}
    for entry in data:
        vuln_id = entry.get('Group ID')
        if vuln_id:
            stig_map[vuln_id] = entry

    return stig_map

def categorize_check_automation(check_content, discussion, fix_text, rule_title):
    """
    Analyze check content to determine if it can be automated.
    Returns: 'automated', 'semi-automated', or 'manual'
    """
    if not check_content:
        return 'manual', 'No check content available'

    content_lower = check_content.lower()

    # Automated checks - can be fully scripted
    automated_indicators = [
        # File and directory checks
        (r'check.*permission.*file|ls -l|stat.*file|find.*-perm', 'file permissions check'),
        (r'check.*owner.*group|ls -l.*owner|stat.*%U|stat.*%G', 'file ownership check'),
        (r'grep.*file|cat.*file|search.*file', 'file content search'),
        (r'test -f|test -d|\[ -f \]|\[ -d \]', 'file/directory existence'),

        # Configuration file checks
        (r'check.*parameter.*config|grep.*conf|cat.*\.conf', 'config parameter check'),
        (r'sysctl|/proc/sys|kernel parameter', 'kernel parameter check'),
        (r'systemctl.*status|service.*status|chkconfig', 'service status check'),

        # Registry checks (Windows)
        (r'registry.*key|reg query|get-itemproperty|hklm:|hkcu:', 'registry check'),

        # Database queries
        (r'select.*from|sql.*query|sqlplus', 'database query check'),

        # Package/version checks
        (r'rpm -q|dpkg -l|yum list|apt list', 'package installation check'),
    ]

    for pattern, reason in automated_indicators:
        if re.search(pattern, content_lower):
            return 'automated', reason

    # Semi-automated - can check some aspects
    semi_automated_indicators = [
        (r'verify.*with.*administrator|consult|coordinate|contact', 'requires admin consultation'),
        (r'interview|ask|question|determine if.*organization', 'requires interview'),
        (r'review.*policy|organizational policy|site policy', 'requires policy review'),
    ]

    for pattern, reason in semi_automated_indicators:
        if re.search(pattern, content_lower):
            # But if it also has automated aspects, it's semi-automated
            for auto_pattern, _ in automated_indicators:
                if re.search(auto_pattern, content_lower):
                    return 'semi-automated', f'{reason} but has automated components'
            return 'manual', reason

    # Manual only indicators
    manual_indicators = [
        (r'visual.*inspect|physically.*inspect|observe', 'requires visual inspection'),
        (r'not.*applicable|n/a if', 'conditional applicability'),
        (r'determine.*if.*appropriate|assess.*appropriateness', 'requires judgment'),
        (r'verify.*documentation|review.*documentation', 'requires documentation review'),
    ]

    for pattern, reason in manual_indicators:
        if re.search(pattern, content_lower):
            return 'manual', reason

    # Default: if has specific commands, likely automated
    if any(cmd in content_lower for cmd in ['grep', 'cat', 'ls', 'stat', 'find', 'sysctl', 'systemctl', 'reg query', 'get-itemproperty']):
        return 'automated', 'contains specific check commands'

    return 'manual', 'requires complex verification'

def analyze_all_checks():
    """Analyze all implemented checks and categorize them"""

    stig_map = load_stig_data()

    base_dir = Path('/home/user/STIGcheckScripts/checks')
    categories = ['os', 'application', 'database', 'network', 'container']

    results = {
        'automated': [],
        'semi-automated': [],
        'manual': [],
        'no-stig-data': []
    }

    stats_by_platform = defaultdict(lambda: {'automated': 0, 'semi': 0, 'manual': 0, 'no-data': 0, 'total': 0})

    total_analyzed = 0

    for category in categories:
        cat_dir = base_dir / category
        if not cat_dir.exists():
            continue

        for platform_dir in cat_dir.iterdir():
            if not platform_dir.is_dir():
                continue

            platform_name = f"{category}/{platform_dir.name}"

            for check_file in platform_dir.iterdir():
                if check_file.suffix not in ['.sh', '.ps1', '.bat']:
                    continue

                total_analyzed += 1
                stats_by_platform[platform_name]['total'] += 1

                # Try to extract VULN ID from filename or content
                vuln_id = None
                if check_file.stem.startswith('V-'):
                    vuln_id = check_file.stem
                else:
                    # Try to read from file content
                    try:
                        content = check_file.read_text(encoding='utf-8', errors='ignore')
                        vuln_match = re.search(r'VULN[_ ]?ID["\s=:]+([VH]-\d+)', content, re.IGNORECASE)
                        if vuln_match:
                            vuln_id = vuln_match.group(1)
                    except:
                        pass

                if not vuln_id or vuln_id not in stig_map:
                    results['no-stig-data'].append({
                        'file': str(check_file),
                        'platform': platform_name,
                        'vuln_id': vuln_id or 'unknown'
                    })
                    stats_by_platform[platform_name]['no-data'] += 1
                    continue

                # Get STIG data
                stig_entry = stig_map[vuln_id]
                check_content = stig_entry.get('Check Content', '')
                discussion = stig_entry.get('Discussion', '')
                fix_text = stig_entry.get('Fix Text', '')
                rule_title = stig_entry.get('Rule Title', '')

                # Categorize
                category_type, reason = categorize_check_automation(check_content, discussion, fix_text, rule_title)

                results[category_type].append({
                    'file': str(check_file),
                    'platform': platform_name,
                    'vuln_id': vuln_id,
                    'stig_id': stig_entry.get('STIG ID', ''),
                    'rule_title': rule_title,
                    'reason': reason,
                    'check_content': check_content[:200]
                })

                if category_type == 'automated':
                    stats_by_platform[platform_name]['automated'] += 1
                elif category_type == 'semi-automated':
                    stats_by_platform[platform_name]['semi'] += 1
                else:
                    stats_by_platform[platform_name]['manual'] += 1

    return results, stats_by_platform, total_analyzed

def main():
    print("=" * 80)
    print("STIG CHECK AUTOMATION ANALYSIS")
    print("=" * 80)
    print("\nAnalyzing all checks against STIG data...")

    results, stats_by_platform, total = analyze_all_checks()

    print(f"\nTotal checks analyzed: {total:,}")
    print(f"\nAutomation Categorization:")
    print(f"  Can be fully automated:     {len(results['automated']):,}")
    print(f"  Semi-automated (mixed):     {len(results['semi-automated']):,}")
    print(f"  Manual review required:     {len(results['manual']):,}")
    print(f"  No STIG data available:     {len(results['no-stig-data']):,}")

    print("\n" + "=" * 80)
    print("BREAKDOWN BY PLATFORM")
    print("=" * 80)

    for platform in sorted(stats_by_platform.keys()):
        stats = stats_by_platform[platform]
        auto_pct = (stats['automated'] / stats['total'] * 100) if stats['total'] > 0 else 0
        print(f"\n{platform}:")
        print(f"  Total: {stats['total']}")
        print(f"  Automated: {stats['automated']} ({auto_pct:.1f}%)")
        print(f"  Semi-Auto: {stats['semi']}")
        print(f"  Manual: {stats['manual']}")
        print(f"  No Data: {stats['no-data']}")

    print("\n" + "=" * 80)
    print("SAMPLE AUTOMATED CHECKS (first 10)")
    print("=" * 80)

    for i, check in enumerate(results['automated'][:10], 1):
        print(f"\n{i}. {check['vuln_id']} - {check['platform']}")
        print(f"   Title: {check['rule_title'][:80]}")
        print(f"   Reason: {check['reason']}")
        print(f"   Check: {check['check_content'][:150]}...")

    # Save detailed results
    output_file = Path('/home/user/STIGcheckScripts/automation_analysis.json')
    with open(output_file, 'w') as f:
        json.dump({
            'summary': {
                'total': total,
                'automated': len(results['automated']),
                'semi_automated': len(results['semi-automated']),
                'manual': len(results['manual']),
                'no_data': len(results['no-stig-data'])
            },
            'by_platform': dict(stats_by_platform),
            'details': results
        }, f, indent=2)

    print(f"\n\n✅ Detailed analysis saved to: {output_file}")
    print("=" * 80)

if __name__ == '__main__':
    main()
