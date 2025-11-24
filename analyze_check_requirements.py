#!/usr/bin/env python3
"""
Analyze STIG checks to identify:
1. User-defined parameters (org-specific values)
2. Documentation requirements (policy reviews, interviews)
3. Hybrid checks (technical + documentation)
"""

import json
import re
from pathlib import Path
from collections import defaultdict

def detect_user_defined_params(check_content: str, discussion: str) -> dict:
    """Detect organization-defined parameters"""

    params = {
        'has_user_params': False,
        'parameters': [],
        'examples': []
    }

    # Patterns for organization-defined values
    org_patterns = [
        r'organization[- ]defined\s+([^.]+)',
        r'site[- ]defined\s+([^.]+)',
        r'as\s+appropriate\s+for\s+the\s+organization',
        r'determined\s+by\s+the\s+organization',
        r'approved\s+by\s+.*?\s+organization',
    ]

    combined = (check_content or '') + ' ' + (discussion or '')

    for pattern in org_patterns:
        matches = re.findall(pattern, combined, re.IGNORECASE)
        if matches:
            params['has_user_params'] = True
            params['parameters'].extend([m.strip()[:50] for m in matches])

    # Specific value patterns
    value_patterns = [
        (r'(\d+)\s+(?:day|hour|minute|second)s?\s+\(or\s+less\)', 'time_period'),
        (r'password.*?(\d+)\s+character', 'password_length'),
        (r'session.*?timeout.*?(\d+)', 'session_timeout'),
        (r'must\s+be\s+set\s+to.*?(\d+)', 'numeric_value'),
    ]

    for pattern, param_type in value_patterns:
        matches = re.findall(pattern, combined, re.IGNORECASE)
        if matches:
            params['has_user_params'] = True
            params['examples'].append({
                'type': param_type,
                'suggested_value': matches[0]
            })

    return params

def detect_documentation_requirements(check_content: str, discussion: str) -> dict:
    """Detect when check requires documentation review"""

    doc_req = {
        'requires_documentation': False,
        'doc_types': [],
        'reasons': []
    }

    combined = (check_content or '') + ' ' + (discussion or '')

    # Documentation requirement patterns
    doc_patterns = [
        (r'review.*?documentation', 'documentation_review'),
        (r'verify.*?policy', 'policy_review'),
        (r'interview\s+(?:the\s+)?(?:SA|DBA|administrator)', 'interview_required'),
        (r'consult.*?(?:documentation|policy)', 'consultation_required'),
        (r'obtain.*?list\s+of', 'inventory_required'),
        (r'determine\s+if.*?organization', 'organizational_determination'),
        (r'approved\s+by.*?(?:IAO|ISSO|management)', 'approval_verification'),
    ]

    for pattern, doc_type in doc_patterns:
        if re.search(pattern, combined, re.IGNORECASE):
            doc_req['requires_documentation'] = True
            if doc_type not in doc_req['doc_types']:
                doc_req['doc_types'].append(doc_type)

    # Additional context patterns
    if 'documentation' in combined.lower():
        doc_req['reasons'].append('Requires documentation verification')
    if 'interview' in combined.lower():
        doc_req['reasons'].append('Requires administrator interview')
    if 'policy' in combined.lower() and 'review' in combined.lower():
        doc_req['reasons'].append('Requires policy review')

    return doc_req

def categorize_check_complexity(check_content: str, doc_req: dict, user_params: dict) -> str:
    """Categorize check by complexity"""

    # Fully automated - no doc requirements, no user params, has commands
    has_commands = bool(re.search(r'(?:grep|cat|ls|stat|rpm|sysctl|systemctl)', check_content or '', re.IGNORECASE))

    if has_commands and not doc_req['requires_documentation'] and not user_params['has_user_params']:
        return 'fully_automated'

    # Automated with user params - technical check but needs config
    if has_commands and user_params['has_user_params'] and not doc_req['requires_documentation']:
        return 'automated_with_config'

    # Hybrid - technical + documentation
    if has_commands and doc_req['requires_documentation']:
        return 'hybrid_technical_and_doc'

    # Documentation only
    if doc_req['requires_documentation'] and not has_commands:
        return 'documentation_only'

    # Complex/unclear
    return 'complex_manual'

def analyze_oracle_2025_stigs():
    """Analyze all Oracle 2025 STIGs for requirements"""

    with open('oracle_2025_stigs.json', 'r') as f:
        stigs = json.load(f)

    print("=" * 80)
    print("ORACLE 2025 STIG REQUIREMENTS ANALYSIS")
    print("=" * 80)
    print()

    by_category = defaultdict(list)
    stats = {
        'fully_automated': 0,
        'automated_with_config': 0,
        'hybrid_technical_and_doc': 0,
        'documentation_only': 0,
        'complex_manual': 0
    }

    for stig in stigs:
        check_content = stig.get('check_content', '')
        discussion = stig.get('discussion', '')

        user_params = detect_user_defined_params(check_content, discussion)
        doc_req = detect_documentation_requirements(check_content, discussion)
        category = categorize_check_complexity(check_content, doc_req, user_params)

        stats[category] += 1

        by_category[category].append({
            'vuln_id': stig['vuln_id'],
            'stig_id': stig['stig_id'],
            'benchmark': stig['benchmark'],
            'rule_title': stig['rule_title'][:60],
            'user_params': user_params,
            'doc_req': doc_req
        })

    # Display statistics
    print("Check Categorization:")
    print(f"  Fully Automated:                {stats['fully_automated']:4d} - No config, no doc requirements")
    print(f"  Automated with Config:          {stats['automated_with_config']:4d} - Needs user-defined parameters")
    print(f"  Hybrid (Technical + Doc):       {stats['hybrid_technical_and_doc']:4d} - Technical check + documentation")
    print(f"  Documentation Only:             {stats['documentation_only']:4d} - No technical check possible")
    print(f"  Complex/Manual:                 {stats['complex_manual']:4d} - Requires manual evaluation")
    print("  " + "-" * 76)
    print(f"  Total:                          {len(stigs):4d}")
    print()

    # Show examples of automated with config
    print("=" * 80)
    print("EXAMPLES: Automated Checks Requiring User-Defined Parameters")
    print("=" * 80)

    for i, check in enumerate(by_category['automated_with_config'][:5], 1):
        print(f"\n{i}. {check['vuln_id']} - {check['stig_id']}")
        print(f"   Platform: {check['benchmark']}")
        print(f"   Title: {check['rule_title']}...")
        print(f"   Parameters needed:")
        for param in check['user_params']['parameters'][:3]:
            print(f"     - {param}")
        if check['user_params']['examples']:
            print(f"   Suggested values:")
            for ex in check['user_params']['examples']:
                print(f"     - {ex['type']}: {ex['suggested_value']}")

    # Show examples of hybrid checks
    print("\n" + "=" * 80)
    print("EXAMPLES: Hybrid Checks (Technical + Documentation)")
    print("=" * 80)

    for i, check in enumerate(by_category['hybrid_technical_and_doc'][:5], 1):
        print(f"\n{i}. {check['vuln_id']} - {check['stig_id']}")
        print(f"   Platform: {check['benchmark']}")
        print(f"   Title: {check['rule_title']}...")
        print(f"   Documentation requirements:")
        for doc_type in check['doc_req']['doc_types']:
            print(f"     - {doc_type.replace('_', ' ').title()}")
        if check['doc_req']['reasons']:
            print(f"   Reasons:")
            for reason in check['doc_req']['reasons'][:2]:
                print(f"     - {reason}")

    # Save detailed analysis
    output = {
        'statistics': stats,
        'by_category': {k: v for k, v in by_category.items()}
    }

    with open('check_requirements_analysis.json', 'w') as f:
        json.dump(output, f, indent=2)

    print("\n" + "=" * 80)
    print("✅ Detailed analysis saved to: check_requirements_analysis.json")
    print("=" * 80)

if __name__ == '__main__':
    analyze_oracle_2025_stigs()
