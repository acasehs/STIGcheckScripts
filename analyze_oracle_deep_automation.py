#!/usr/bin/env python3
"""
Deep Oracle automation analysis to identify underlying config files and automation
methods even when not explicitly stated in check content.

Similar to Windows GPO→Registry mapping, this infers Oracle automation paths:
- Database parameters → V$PARAMETER queries or init.ora
- Listener settings → listener.ora
- Network settings → sqlnet.ora, tnsnames.ora
- HTTP Server → httpd.conf, ssl.conf
- WebLogic → config.xml, boot.properties
- OS settings → sysctl, file permissions, packages
"""

import json
import re
from pathlib import Path
from collections import defaultdict

# Known Oracle configuration file mappings
ORACLE_CONFIG_MAP = {
    # Oracle Database configuration files
    'database': {
        'init_params': {
            'files': ['$ORACLE_HOME/dbs/init$ORACLE_SID.ora', '$ORACLE_HOME/dbs/spfile$ORACLE_SID.ora'],
            'check_method': 'SQL: SELECT * FROM V$PARAMETER WHERE NAME = ?',
            'patterns': ['parameter', 'init', 'spfile', 'alter system']
        },
        'listener': {
            'files': ['$ORACLE_HOME/network/admin/listener.ora'],
            'check_method': 'grep in listener.ora',
            'patterns': ['listener', 'rate_limit', 'connection', 'protocol', 'port']
        },
        'sqlnet': {
            'files': ['$ORACLE_HOME/network/admin/sqlnet.ora'],
            'check_method': 'grep in sqlnet.ora',
            'patterns': ['sqlnet', 'encryption', 'authentication', 'network']
        },
        'tnsnames': {
            'files': ['$ORACLE_HOME/network/admin/tnsnames.ora'],
            'check_method': 'grep in tnsnames.ora',
            'patterns': ['tnsnames', 'service_name', 'connect']
        },
        'profiles': {
            'files': ['Database tables: DBA_PROFILES, DBA_USERS'],
            'check_method': 'SQL: SELECT * FROM DBA_PROFILES WHERE RESOURCE_NAME = ?',
            'patterns': ['profile', 'password_', 'sessions_per_user', 'failed_login', 'idle_time']
        },
        'audit': {
            'files': ['Database tables: DBA_AUDIT_TRAIL, UNIFIED_AUDIT_TRAIL'],
            'check_method': 'SQL: SELECT * FROM DBA_PRIV_AUDIT_OPTS',
            'patterns': ['audit', 'audit_trail', 'audit_sys_operations']
        }
    },

    # Oracle HTTP Server configuration
    'http_server': {
        'httpd_conf': {
            'files': ['$DOMAIN_HOME/config/fmwconfig/components/OHS/*/httpd.conf'],
            'check_method': 'grep in httpd.conf',
            'patterns': ['serverlimit', 'maxclients', 'timeout', 'keepalive', 'directive']
        },
        'ssl_conf': {
            'files': ['$DOMAIN_HOME/config/fmwconfig/components/OHS/*/ssl.conf'],
            'check_method': 'grep in ssl.conf',
            'patterns': ['ssl', 'cipher', 'protocol', 'certificate', 'encryption']
        },
        'mod_weblogic': {
            'files': ['$DOMAIN_HOME/config/fmwconfig/components/OHS/*/mod_wl_ohs.conf'],
            'check_method': 'grep in mod_wl_ohs.conf',
            'patterns': ['weblogic', 'wlsserver', 'weblogiccluster']
        }
    },

    # Oracle WebLogic configuration
    'weblogic': {
        'config_xml': {
            'files': ['$DOMAIN_HOME/config/config.xml'],
            'check_method': 'grep/xmllint in config.xml',
            'patterns': ['domain', 'server', 'security', 'ssl', 'authentication']
        },
        'boot_properties': {
            'files': ['$DOMAIN_HOME/servers/*/security/boot.properties'],
            'check_method': 'file permission check',
            'patterns': ['boot.properties', 'credentials', 'password']
        }
    },

    # Oracle Linux system configuration
    'linux': {
        'sysctl': {
            'files': ['/etc/sysctl.conf', '/etc/sysctl.d/*.conf'],
            'check_method': 'sysctl command or grep in config',
            'patterns': ['kernel', 'net.', 'vm.', 'fs.']
        },
        'file_permissions': {
            'files': ['Various Oracle files'],
            'check_method': 'stat command',
            'patterns': ['permission', 'chmod', 'ownership', 'chown', 'mode']
        },
        'packages': {
            'files': ['RPM database'],
            'check_method': 'rpm -q or yum list',
            'patterns': ['package', 'rpm', 'yum', 'install']
        },
        'services': {
            'files': ['systemd unit files'],
            'check_method': 'systemctl status',
            'patterns': ['service', 'daemon', 'systemctl', 'enabled', 'active']
        }
    }
}

def detect_automation_type(check_content: str, discussion: str, benchmark: str) -> dict:
    """Detect automation type and infer config files"""

    result = {
        'automation_types': [],
        'config_files': [],
        'check_methods': [],
        'confidence': 'unknown',
        'is_automatable': False
    }

    combined = (check_content or '').lower() + ' ' + (discussion or '').lower()
    benchmark_lower = benchmark.lower()

    # SQL Query checks (Database)
    if 'database' in benchmark_lower:
        # Explicit SQL queries
        if re.search(r'select\s+.*?\s+from\s+', combined, re.IGNORECASE):
            result['automation_types'].append('sql_query')
            result['check_methods'].append('Execute SQL query')
            result['confidence'] = 'high'
            result['is_automatable'] = True

            # Infer which tables/views are being queried
            if 'dba_profiles' in combined:
                result['config_files'].append('Database: DBA_PROFILES')
            if 'v$parameter' in combined or 'v_parameter' in combined:
                result['config_files'].append('Database: V$PARAMETER / init.ora')
            if 'dba_audit' in combined:
                result['config_files'].append('Database: DBA_AUDIT_TRAIL')
            if 'dba_users' in combined:
                result['config_files'].append('Database: DBA_USERS')
            if 'dba_roles' in combined:
                result['config_files'].append('Database: DBA_ROLES')
            if 'dba_sys_privs' in combined:
                result['config_files'].append('Database: DBA_SYS_PRIVS')

        # Database parameter checks (can query V$PARAMETER even if not explicit)
        elif any(param in combined for param in ['parameter', 'init.ora', 'spfile', 'alter system']):
            result['automation_types'].append('database_parameter')
            result['check_methods'].append('Query V$PARAMETER or check init.ora')
            result['config_files'].append('$ORACLE_HOME/dbs/init$ORACLE_SID.ora')
            result['confidence'] = 'medium'
            result['is_automatable'] = True

        # Profile checks (can query DBA_PROFILES)
        if any(word in combined for word in ['profile', 'password_life_time', 'sessions_per_user', 'failed_login']):
            if 'sql_query' not in result['automation_types']:
                result['automation_types'].append('database_profile')
                result['check_methods'].append('Query DBA_PROFILES')
                result['config_files'].append('Database: DBA_PROFILES')
                result['confidence'] = 'medium'
                result['is_automatable'] = True

        # Audit checks
        if 'audit' in combined:
            if 'sql_query' not in result['automation_types']:
                result['automation_types'].append('database_audit')
                result['check_methods'].append('Query audit tables or check audit_trail parameter')
                result['config_files'].append('Database: DBA_AUDIT_TRAIL / V$PARAMETER')
                result['confidence'] = 'medium'
                result['is_automatable'] = True

        # Listener checks
        if 'listener' in combined:
            result['automation_types'].append('listener_config')
            result['check_methods'].append('Check listener.ora file')
            result['config_files'].append('$ORACLE_HOME/network/admin/listener.ora')
            result['confidence'] = 'high' if 'listener.ora' in combined else 'medium'
            result['is_automatable'] = True

        # Network configuration
        if any(word in combined for word in ['sqlnet', 'encryption', 'network']):
            result['automation_types'].append('network_config')
            result['check_methods'].append('Check sqlnet.ora file')
            result['config_files'].append('$ORACLE_HOME/network/admin/sqlnet.ora')
            result['confidence'] = 'high' if 'sqlnet.ora' in combined else 'medium'
            result['is_automatable'] = True

    # Oracle HTTP Server checks
    if 'http server' in benchmark_lower or 'ohs' in benchmark_lower:
        # Config file checks
        if any(word in combined for word in ['httpd.conf', 'ssl.conf', 'directive', 'serverlimit']):
            result['automation_types'].append('http_config')
            result['check_methods'].append('Check httpd.conf or ssl.conf')
            if 'ssl' in combined or 'cipher' in combined:
                result['config_files'].append('$DOMAIN_HOME/config/fmwconfig/components/OHS/*/ssl.conf')
            else:
                result['config_files'].append('$DOMAIN_HOME/config/fmwconfig/components/OHS/*/httpd.conf')
            result['confidence'] = 'high'
            result['is_automatable'] = True

        # Infer config file even without explicit mention
        elif any(word in combined for word in ['timeout', 'keepalive', 'maxclients', 'protocol', 'server']):
            result['automation_types'].append('http_config_inferred')
            result['check_methods'].append('Check httpd.conf (inferred)')
            result['config_files'].append('$DOMAIN_HOME/config/fmwconfig/components/OHS/*/httpd.conf')
            result['confidence'] = 'medium'
            result['is_automatable'] = True

    # Oracle WebLogic checks
    if 'weblogic' in benchmark_lower:
        # Config.xml checks
        if any(word in combined for word in ['config.xml', 'domain', 'weblogic']):
            result['automation_types'].append('weblogic_config')
            result['check_methods'].append('Check config.xml')
            result['config_files'].append('$DOMAIN_HOME/config/config.xml')
            result['confidence'] = 'high'
            result['is_automatable'] = True

    # Oracle Linux OS checks
    if 'linux' in benchmark_lower:
        # File permission checks
        if any(word in combined for word in ['permission', 'chmod', 'ownership', 'mode', 'stat']):
            result['automation_types'].append('file_permissions')
            result['check_methods'].append('Check file permissions with stat')
            result['confidence'] = 'high'
            result['is_automatable'] = True

        # Package checks
        if any(word in combined for word in ['rpm -q', 'yum list', 'dnf list', 'package']):
            result['automation_types'].append('package_check')
            result['check_methods'].append('Check package installation')
            result['confidence'] = 'high'
            result['is_automatable'] = True

        # Kernel parameter checks
        if any(word in combined for word in ['sysctl', 'kernel', '/proc/sys']):
            result['automation_types'].append('kernel_parameter')
            result['check_methods'].append('Check sysctl or /etc/sysctl.conf')
            result['config_files'].append('/etc/sysctl.conf')
            result['confidence'] = 'high'
            result['is_automatable'] = True

        # Service checks
        if any(word in combined for word in ['systemctl', 'service', 'daemon', 'enabled', 'active']):
            result['automation_types'].append('service_status')
            result['check_methods'].append('Check service with systemctl')
            result['confidence'] = 'high'
            result['is_automatable'] = True

        # Config file grep checks
        if re.search(r'grep.*?\.conf', combined):
            result['automation_types'].append('config_grep')
            result['check_methods'].append('Search config file')
            result['confidence'] = 'high'
            result['is_automatable'] = True

            # Extract config file name
            config_match = re.search(r'([/\w\-\.]+\.conf)', combined)
            if config_match:
                result['config_files'].append(config_match.group(1))

    # Environment variable checks (all platforms)
    if any(word in combined for word in ['$oracle_home', '$oracle_sid', '$domain_home', 'environment']):
        if not result['automation_types']:
            result['automation_types'].append('environment_check')
            result['check_methods'].append('Check environment variables')
            result['confidence'] = 'medium'
            result['is_automatable'] = True

    # Documentation-only checks
    if any(word in combined for word in ['interview', 'review.*documentation', 'consult', 'determine if.*organization']):
        result['automation_types'].append('documentation_required')
        result['confidence'] = 'low'
        result['is_automatable'] = False

    # If still no automation type detected but has technical indicators
    if not result['automation_types']:
        # Look for any command indicators
        if any(word in combined for word in ['check', 'verify', 'query', 'run', 'execute', 'grep', 'cat', 'ls']):
            result['automation_types'].append('potentially_automatable')
            result['confidence'] = 'low'
            result['is_automatable'] = True

    return result

def analyze_oracle_stigs():
    """Analyze all Oracle 2025 STIGs for deep automation potential"""

    with open('oracle_2025_stigs.json', 'r') as f:
        stigs = json.load(f)

    print("=" * 80)
    print("ORACLE DEEP AUTOMATION ANALYSIS")
    print("=" * 80)
    print(f"\nAnalyzing {len(stigs)} Oracle 2025 STIGs...\n")

    # Group by benchmark
    by_benchmark = defaultdict(list)
    for stig in stigs:
        by_benchmark[stig['benchmark']].append(stig)

    # Statistics by automation type
    automation_stats = defaultdict(int)
    by_automation_type = defaultdict(list)

    # Overall stats
    total_automatable = 0
    total_manual = 0

    # Process each STIG
    for stig in stigs:
        check_content = stig.get('check_content', '')
        discussion = stig.get('discussion', '')
        benchmark = stig['benchmark']

        analysis = detect_automation_type(check_content, discussion, benchmark)

        if analysis['is_automatable']:
            total_automatable += 1
        else:
            total_manual += 1

        # Count each automation type
        for auto_type in analysis['automation_types']:
            automation_stats[auto_type] += 1
            by_automation_type[auto_type].append({
                'vuln_id': stig['vuln_id'],
                'stig_id': stig['stig_id'],
                'benchmark': benchmark,
                'rule_title': stig['rule_title'][:70],
                'config_files': analysis['config_files'],
                'check_methods': analysis['check_methods'],
                'confidence': analysis['confidence']
            })

    # Display overall statistics
    print("=" * 80)
    print("OVERALL AUTOMATION POTENTIAL")
    print("=" * 80)
    print(f"Total Oracle 2025 STIGs:     {len(stigs)}")
    print(f"Automatable:                 {total_automatable:4d} ({total_automatable/len(stigs)*100:.1f}%)")
    print(f"Manual/Documentation Only:   {total_manual:4d} ({total_manual/len(stigs)*100:.1f}%)")
    print()

    # Display by benchmark
    print("=" * 80)
    print("BREAKDOWN BY PLATFORM")
    print("=" * 80)
    for benchmark in sorted(by_benchmark.keys()):
        count = len(by_benchmark[benchmark])
        # Calculate automatable for this benchmark
        bench_automatable = sum(1 for s in by_benchmark[benchmark]
                                if detect_automation_type(s.get('check_content', ''),
                                                         s.get('discussion', ''),
                                                         s['benchmark'])['is_automatable'])
        print(f"{benchmark:40s} {count:4d} checks  ({bench_automatable:4d} automatable, {bench_automatable/count*100:5.1f}%)")
    print()

    # Display automation type statistics
    print("=" * 80)
    print("AUTOMATION TYPES DETECTED")
    print("=" * 80)

    # Sort by count
    sorted_types = sorted(automation_stats.items(), key=lambda x: x[1], reverse=True)

    for auto_type, count in sorted_types:
        pct = count / len(stigs) * 100
        print(f"{auto_type.replace('_', ' ').title():40s} {count:4d} ({pct:5.1f}%)")
    print()

    # Show examples for top automation types
    print("=" * 80)
    print("EXAMPLES BY AUTOMATION TYPE")
    print("=" * 80)

    for auto_type, count in sorted_types[:8]:  # Top 8 types
        print(f"\n{auto_type.replace('_', ' ').upper()}")
        print("-" * 80)

        examples = by_automation_type[auto_type][:3]  # Show 3 examples
        for i, ex in enumerate(examples, 1):
            print(f"\n{i}. {ex['vuln_id']} - {ex['stig_id']}")
            print(f"   Platform: {ex['benchmark']}")
            print(f"   Title: {ex['rule_title']}...")
            if ex['config_files']:
                print(f"   Config Files: {', '.join(ex['config_files'][:2])}")
            if ex['check_methods']:
                print(f"   Check Method: {ex['check_methods'][0]}")
            print(f"   Confidence: {ex['confidence']}")

    # Save detailed results
    output = {
        'summary': {
            'total': len(stigs),
            'automatable': total_automatable,
            'manual': total_manual,
            'automation_percentage': round(total_automatable / len(stigs) * 100, 1)
        },
        'by_benchmark': {
            benchmark: {
                'total': len(checks),
                'automatable': sum(1 for s in checks
                                  if detect_automation_type(s.get('check_content', ''),
                                                           s.get('discussion', ''),
                                                           s['benchmark'])['is_automatable'])
            }
            for benchmark, checks in by_benchmark.items()
        },
        'automation_types': dict(sorted_types),
        'detailed_analysis': {
            auto_type: examples
            for auto_type, examples in by_automation_type.items()
        }
    }

    with open('oracle_deep_automation_analysis.json', 'w') as f:
        json.dump(output, f, indent=2)

    print("\n" + "=" * 80)
    print("✅ Detailed analysis saved to: oracle_deep_automation_analysis.json")
    print("=" * 80)

    return output

if __name__ == '__main__':
    analyze_oracle_stigs()
