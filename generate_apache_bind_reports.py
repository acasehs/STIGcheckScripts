#!/usr/bin/env python3
"""
Generate comprehensive automation analysis reports for Apache and BIND STIG frameworks
"""

import json
import re
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Tuple

class STIGAnalyzer:
    def __init__(self):
        self.automatable_keywords = [
            'grep', 'cat', 'search', 'find', 'check for', 'verify', 'review',
            'examine', 'inspect', 'locate', 'determine', 'list'
        ]
        self.manual_keywords = [
            'interview', 'ask the sa', 'ask the system administrator',
            'ask site', 'documented', 'obtain documentation', 'review with',
            'policy', 'procedures', 'organizational', 'approval', 'authorized'
        ]
        self.partial_keywords = [
            'validate', 'confirm with', 'ensure', 'approved list',
            'site-defined', 'organizationally-defined'
        ]

    def categorize_check(self, check: Dict) -> Tuple[str, str, List[str], bool, bool]:
        """
        Categorize a check as Automatable, Partially Automatable, Manual, or Needs Analysis
        Returns: (status, method, notes, is_env_specific, is_sys_specific)
        """
        check_content = check.get('Check Content', '').lower()
        fix_text = check.get('Fix Text', '').lower()
        rule_title = check.get('Rule Title', '').lower()
        discussion = check.get('Discussion', '').lower()

        combined_text = f"{check_content} {fix_text} {rule_title}"

        notes = []
        is_env_specific = False
        is_sys_specific = False

        # Check for environment/system specific
        env_indicators = ['approved', 'authorized', 'site-specific', 'organizationally',
                         'organization-defined', 'ssp', 'system security plan']
        sys_indicators = ['custom', 'site-defined', 'local', 'deployment']

        for indicator in env_indicators:
            if indicator in combined_text:
                is_env_specific = True
                break

        for indicator in sys_indicators:
            if indicator in combined_text:
                is_sys_specific = True
                break

        # Determine automation status
        # Manual checks - requires human judgment or documentation review
        if any(kw in combined_text for kw in self.manual_keywords):
            if 'interview' in combined_text or 'ask the sa' in combined_text:
                return ('Manual Review Required', 'Requires SA Interview',
                       ['Requires system administrator interview or consultation'],
                       is_env_specific, is_sys_specific)
            elif 'documented' in combined_text or 'documentation' in combined_text:
                return ('Manual Review Required', 'Documentation Review',
                       ['Requires manual review of documentation'],
                       is_env_specific, is_sys_specific)
            elif 'policy' in combined_text or 'procedures' in combined_text:
                return ('Manual Review Required', 'Policy Review',
                       ['Requires review of organizational policies/procedures'],
                       is_env_specific, is_sys_specific)

        # Check for Apache-specific automation opportunities
        if 'httpd.conf' in check_content or 'ssl.conf' in check_content:
            notes.append('Configuration file parsing (httpd.conf/ssl.conf)')
            method = 'Bash (grep/awk/sed for config parsing)'

            if is_env_specific:
                return ('Partially Automatable', method, notes, is_env_specific, is_sys_specific)
            return ('Automatable', method, notes, is_env_specific, is_sys_specific)

        if 'apachectl' in check_content or 'httpd -' in check_content:
            notes.append('Apache command-line tool verification')
            method = 'Bash (apachectl/httpd commands)'

            if is_env_specific:
                return ('Partially Automatable', method, notes, is_env_specific, is_sys_specific)
            return ('Automatable', method, notes, is_env_specific, is_sys_specific)

        # Check for BIND-specific automation opportunities
        if 'named.conf' in check_content:
            notes.append('BIND configuration file parsing (named.conf)')
            method = 'Bash (grep/awk for named.conf parsing)'

            if is_env_specific:
                return ('Partially Automatable', method, notes, is_env_specific, is_sys_specific)
            return ('Automatable', method, notes, is_env_specific, is_sys_specific)

        if 'rndc' in check_content or 'named-checkconf' in check_content:
            notes.append('BIND command-line tool verification')
            method = 'Bash (rndc/named-checkconf commands)'

            if is_env_specific:
                return ('Partially Automatable', method, notes, is_env_specific, is_sys_specific)
            return ('Automatable', method, notes, is_env_specific, is_sys_specific)

        # SSL/TLS cipher checks
        if 'sslprotocol' in check_content.replace(' ', '') or 'sslcipher' in check_content.replace(' ', ''):
            notes.append('SSL/TLS configuration verification')
            method = 'Bash (SSL config parsing)'

            if is_env_specific:
                return ('Partially Automatable', method, notes, is_env_specific, is_sys_specific)
            return ('Automatable', method, notes, is_env_specific, is_sys_specific)

        # Module verification
        if 'module' in check_content and ('httpd -m' in check_content or 'apachectl -m' in check_content):
            notes.append('Apache module verification')
            return ('Automatable', 'Bash (httpd -M or apachectl -M)', notes, is_env_specific, is_sys_specific)

        # File permission checks
        if 'permission' in check_content or 'chmod' in combined_text or 'ls -l' in check_content:
            notes.append('File permission verification')
            return ('Automatable', 'Bash (ls -l, stat commands)', notes, is_env_specific, is_sys_specific)

        # Log configuration
        if 'log' in check_content and ('customlog' in check_content.replace(' ', '') or
                                       'errorlog' in check_content.replace(' ', '') or
                                       'logformat' in check_content.replace(' ', '')):
            notes.append('Log configuration verification')
            method = 'Bash (config file parsing)'

            if is_env_specific:
                return ('Partially Automatable', method, notes, is_env_specific, is_sys_specific)
            return ('Automatable', method, notes, is_env_specific, is_sys_specific)

        # General file/directory checks
        if any(cmd in check_content for cmd in ['cat ', 'grep ', 'find ', 'ls ', 'stat ']):
            notes.append('Command-line verification possible')
            method = 'Bash (native commands)'

            if is_env_specific:
                return ('Partially Automatable', method, notes, is_env_specific, is_sys_specific)
            return ('Automatable', method, notes, is_env_specific, is_sys_specific)

        # If we can determine file locations and check specific settings
        if 'file' in check_content or 'directory' in check_content:
            if is_env_specific:
                return ('Partially Automatable', 'Bash (file/directory checks)',
                       ['Requires environment-specific paths'], is_env_specific, is_sys_specific)
            return ('Automatable', 'Bash (file/directory checks)', notes, is_env_specific, is_sys_specific)

        # Default: if it's checking something specific, it's likely automatable with caveats
        if 'verify' in check_content or 'check' in check_content or 'ensure' in check_content:
            return ('Partially Automatable', 'Bash/Python (needs validation)',
                   ['Automation possible but may require manual validation'],
                   is_env_specific, is_sys_specific)

        # If we can't determine, mark as needs analysis
        return ('Needs Analysis', 'TBD', ['Automation feasibility needs further analysis'],
               is_env_specific, is_sys_specific)

    def analyze_json_file(self, json_path: Path) -> Dict:
        """Analyze a STIG JSON file and return statistics"""
        with open(json_path, 'r') as f:
            checks = json.load(f)

        stats = {
            'total': len(checks),
            'automatable': [],
            'partial': [],
            'manual': [],
            'needs_analysis': [],
            'by_severity': {'high': {}, 'medium': {}, 'low': {}},
            'env_specific': 0,
            'sys_specific': 0,
            'benchmark_name': checks[0].get('Benchmark Name', 'Unknown'),
            'benchmark_id': checks[0].get('Benchmark ID', 'Unknown'),
            'release_info': checks[0].get('Release Info', 'Unknown'),
            'checks_detail': []
        }

        for check in checks:
            status, method, notes, is_env, is_sys = self.categorize_check(check)

            check_info = {
                'group_id': check.get('Group ID', 'Unknown'),
                'stig_id': check.get('STIG ID', 'Unknown'),
                'severity': check.get('Severity', 'medium').lower(),
                'rule_title': check.get('Rule Title', 'Unknown'),
                'status': status,
                'method': method,
                'notes': notes,
                'is_env_specific': is_env,
                'is_sys_specific': is_sys,
                'check_content': check.get('Check Content', ''),
                'fix_text': check.get('Fix Text', ''),
                'ccis': check.get('CCIs', '')
            }

            stats['checks_detail'].append(check_info)

            if status == 'Automatable':
                stats['automatable'].append(check_info)
            elif status == 'Partially Automatable':
                stats['partial'].append(check_info)
            elif status == 'Manual Review Required':
                stats['manual'].append(check_info)
            else:
                stats['needs_analysis'].append(check_info)

            if is_env:
                stats['env_specific'] += 1
            if is_sys:
                stats['sys_specific'] += 1

            # Track by severity
            sev = check_info['severity']
            if sev not in stats['by_severity']:
                stats['by_severity'][sev] = {}

            if status not in stats['by_severity'][sev]:
                stats['by_severity'][sev][status] = 0
            stats['by_severity'][sev][status] += 1

        return stats

    def generate_report(self, stats: Dict, output_path: Path):
        """Generate markdown report following Oracle WebLogic template format"""

        total = stats['total']
        auto_count = len(stats['automatable'])
        partial_count = len(stats['partial'])
        manual_count = len(stats['manual'])
        needs_count = len(stats['needs_analysis'])

        auto_pct = (auto_count / total * 100) if total > 0 else 0
        partial_pct = (partial_count / total * 100) if total > 0 else 0
        manual_pct = (manual_count / total * 100) if total > 0 else 0
        needs_pct = (needs_count / total * 100) if total > 0 else 0

        # Calculate overall automation rate (automatable + partial)
        automation_rate = ((auto_count + partial_count) / total * 100) if total > 0 else 0

        env_pct = (stats['env_specific'] / total * 100) if total > 0 else 0
        sys_pct = (stats['sys_specific'] / total * 100) if total > 0 else 0
        standard_count = total - stats['env_specific'] - stats['sys_specific']
        standard_pct = (standard_count / total * 100) if total > 0 else 0

        # Count severities
        severity_counts = {'high': 0, 'medium': 0, 'low': 0}
        for check in stats['checks_detail']:
            sev = check['severity']
            if sev in severity_counts:
                severity_counts[sev] += 1

        high_total = severity_counts['high']
        med_total = severity_counts['medium']
        low_total = severity_counts['low']

        high_pct = (high_total / total * 100) if total > 0 else 0
        med_pct = (med_total / total * 100) if total > 0 else 0
        low_pct = (low_total / total * 100) if total > 0 else 0

        report = f"""# {stats['benchmark_name']} STIG Check Analysis Report
**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
**STIG:** {stats['benchmark_name']} :: {stats['release_info']}
**Total Checks:** {total}

---

## 📊 Executive Summary

### Automation Status Overview

| Automation Status | Count | Percentage | Status |
|------------------|-------|------------|--------|
| ✅ Automatable | {auto_count} | {auto_pct:.1f}% | Can be fully automated |
| ⚠️ Partially Automatable | {partial_count} | {partial_pct:.1f}% | Requires some manual validation |
| 📝 Manual Review Required | {manual_count} | {manual_pct:.1f}% | Cannot be automated |
| 🔍 Needs Analysis | {needs_count} | {needs_pct:.1f}% | Automation feasibility TBD |
| **TOTAL** | **{total}** | **100.0%** | |

### Automation Status by Severity

| Severity | Total | Automatable | Partial | Manual | Automation Rate |
|----------|-------|-------------|---------|--------|----------------|
"""

        # Add severity breakdown
        for sev_name, sev_display in [('high', 'HIGH'), ('medium', 'MEDIUM'), ('low', 'LOW')]:
            sev_total = severity_counts[sev_name]
            if sev_total == 0:
                continue

            sev_auto = sum(1 for c in stats['automatable'] if c['severity'] == sev_name)
            sev_partial = sum(1 for c in stats['partial'] if c['severity'] == sev_name)
            sev_manual = sum(1 for c in stats['manual'] if c['severity'] == sev_name)
            sev_rate = ((sev_auto + sev_partial) / sev_total * 100) if sev_total > 0 else 0

            report += f"| {sev_display} | {sev_total} | {sev_auto} | {sev_partial} | {sev_manual} | {sev_rate:.1f}% |\n"

        report += f"""| **TOTAL** | **{total}** | **{auto_count}** | **{partial_count}** | **{manual_count}** | **{automation_rate:.1f}%** |

### Configuration Dependencies

| Dependency Type | Count | Percentage | Description |
|----------------|-------|------------|-------------|
| 🌐 Environment-Specific | {stats['env_specific']} | {env_pct:.1f}% | Requires site-specific/organizational values |
| 🖥️ System-Specific | {stats['sys_specific']} | {sys_pct:.1f}% | Depends on deployment/installation config |
| ✓ Standard | {standard_count} | {standard_pct:.1f}% | No special dependencies |

### Severity Distribution

| Severity | Count | Percentage |
|----------|-------|------------|
| 🔴 HIGH | {high_total} | {high_pct:.1f}% |
| 🟡 MEDIUM | {med_total} | {med_pct:.1f}% |
| 🟢 LOW | {low_total} | {low_pct:.1f}% |
| **TOTAL** | **{total}** | **100.0%** |

### Tool Preference (Priority: Bash > PowerShell > Python > Third-Party)

| Tool Type | Count | Notes |
|-----------|-------|-------|
| Bash (Native) | {auto_count + partial_count} | Primary method - no dependencies |
| Python (Native) | 0 | Fallback - uses stdlib only |
| Third-Party Optional | 0 | All checks use native commands |
| **Minimal Third-Party** | **{auto_count + partial_count}** | **{automation_rate:.1f}% can run without third-party tools** |

## Summary
- **Automatable Checks:** {auto_count} ({auto_pct:.1f}%)
- **Partially Automatable:** {partial_count} ({partial_pct:.1f}%)
- **Manual Review Required:** {manual_count} ({manual_pct:.1f}%)
- **Needs Analysis:** {needs_count} ({needs_pct:.1f}%)

### Environment/System Specific Checks
- **Environment-Specific:** {stats['env_specific']} ({env_pct:.1f}%)
  - *These checks require site-specific, organizational, or approved values*
- **System-Specific:** {stats['sys_specific']} ({sys_pct:.1f}%)
  - *These checks depend on deployment or installation-specific configurations*

### Severity Distribution
- **High:** {high_total}
- **Medium:** {med_total}
- **Low:** {low_total}

---

## Detailed Check Analysis

"""

        # Add detailed sections for each category
        if stats['automatable']:
            report += f"### Automatable ({auto_count} checks)\n\n"
            for check in stats['automatable']:
                report += self._format_check_detail(check)

        if stats['partial']:
            report += f"### Partially Automatable ({partial_count} checks)\n\n"
            for check in stats['partial']:
                report += self._format_check_detail(check)

        if stats['manual']:
            report += f"### Manual Review Required ({manual_count} checks)\n\n"
            for check in stats['manual']:
                report += self._format_check_detail(check)

        if stats['needs_analysis']:
            report += f"### Needs Analysis ({needs_count} checks)\n\n"
            for check in stats['needs_analysis']:
                report += self._format_check_detail(check)

        # Write report
        with open(output_path, 'w') as f:
            f.write(report)

    def _format_check_detail(self, check: Dict) -> str:
        """Format individual check details"""
        severity = check['severity'].upper()

        # Extract NIST controls from CCIs
        nist_controls = self._extract_nist_controls(check['ccis'])

        detail = f"""#### {check['group_id']} - {check['stig_id']}
**Severity:** {severity}

**Rule Title:** {check['rule_title']}

**Automation Status:** {check['status']}

**Automation Method:** {check['method']}

**Preferred Tool:** Bash (primary), Python (fallback)

**Third-Party Tools:** None (uses native bash/python commands)

**Requires Elevation:** Yes (root/admin access typically required)

"""

        if check['is_env_specific'] or check['is_sys_specific']:
            detail += "**🔧 Configuration Dependencies:**\n"
            if check['is_env_specific']:
                detail += "- ⚠️ **ENVIRONMENT-SPECIFIC**: This check requires site-specific or organizational values\n"
            if check['is_sys_specific']:
                detail += "- ⚠️ **SYSTEM-SPECIFIC**: This check depends on deployment/installation-specific configuration\n"
            detail += "\n"

        if check['notes']:
            detail += "**Notes:**\n"
            for note in check['notes']:
                detail += f"- {note}\n"
            detail += "\n"

        # Truncate check content for readability
        check_content = check['check_content'][:500] + "..." if len(check['check_content']) > 500 else check['check_content']

        detail += f"""**Check Content:**
```
{check_content}
```
"""

        if nist_controls:
            detail += f"**NIST SP 800-53 Rev 4:** {nist_controls}\n"

        detail += "\n" + "-" * 80 + "\n\n"

        return detail

    def _extract_nist_controls(self, ccis: str) -> str:
        """Extract NIST control references from CCIs"""
        if not ccis:
            return ""

        # Look for NIST SP 800-53 Revision 4 controls
        matches = re.findall(r'NIST SP 800-53 Revision 4::([A-Z]+-\d+[^\\n]*)', ccis)
        if matches:
            # Return first unique match
            unique = list(dict.fromkeys(matches))
            return unique[0].strip()

        # Fallback to any NIST reference
        matches = re.findall(r'NIST SP 800-53::([A-Z]+-\d+[^\\n]*)', ccis)
        if matches:
            unique = list(dict.fromkeys(matches))
            return unique[0].strip()

        return ""


def main():
    analyzer = STIGAnalyzer()

    # Define the STIG files to process
    stig_files = [
        ('apache_2.4_unix_server_checks.json', 'Apache_2.4_UNIX_Server_STIG_Analysis.md'),
        ('apache_2.4_unix_site_checks.json', 'Apache_2.4_UNIX_Site_STIG_Analysis.md'),
        ('apache_2.4_windows_server_checks.json', 'Apache_2.4_Windows_Server_STIG_Analysis.md'),
        ('apache_2.4_windows_site_checks.json', 'Apache_2.4_Windows_Site_STIG_Analysis.md'),
        ('apache_2.2_unix_site_checks.json', 'Apache_2.2_UNIX_Site_STIG_Analysis.md'),
        ('apache_2.2_windows_site_checks.json', 'Apache_2.2_Windows_Site_STIG_Analysis.md'),
        ('bind_9.x_checks.json', 'BIND_9.x_STIG_Analysis.md'),
    ]

    base_dir = Path('/home/user/STIGcheckScripts')
    reports_dir = base_dir / 'reports'
    reports_dir.mkdir(exist_ok=True)

    total_checks = 0
    total_automatable = 0
    total_partial = 0
    reports_generated = []

    print(f"Starting STIG analysis for {len(stig_files)} frameworks...")
    print("=" * 80)

    for json_file, report_file in stig_files:
        json_path = base_dir / json_file
        report_path = reports_dir / report_file

        if not json_path.exists():
            print(f"⚠️  WARNING: {json_file} not found, skipping...")
            continue

        print(f"\nProcessing: {json_file}")
        print(f"  Analyzing checks...")

        stats = analyzer.analyze_json_file(json_path)

        print(f"  Generating report: {report_file}")
        analyzer.generate_report(stats, report_path)

        auto_count = len(stats['automatable'])
        partial_count = len(stats['partial'])
        manual_count = len(stats['manual'])
        needs_count = len(stats['needs_analysis'])

        total_checks += stats['total']
        total_automatable += auto_count
        total_partial += partial_count

        automation_rate = ((auto_count + partial_count) / stats['total'] * 100) if stats['total'] > 0 else 0

        print(f"  ✅ Total Checks: {stats['total']}")
        print(f"  ✅ Automatable: {auto_count} ({auto_count/stats['total']*100:.1f}%)")
        print(f"  ⚠️  Partially: {partial_count} ({partial_count/stats['total']*100:.1f}%)")
        print(f"  📝 Manual: {manual_count} ({manual_count/stats['total']*100:.1f}%)")
        print(f"  🔍 Needs Analysis: {needs_count} ({needs_count/stats['total']*100:.1f}%)")
        print(f"  📊 Automation Rate: {automation_rate:.1f}%")

        reports_generated.append(str(report_path))

    # Final summary
    overall_automation_pct = ((total_automatable + total_partial) / total_checks * 100) if total_checks > 0 else 0

    print("\n" + "=" * 80)
    print("ANALYSIS COMPLETE")
    print("=" * 80)
    print(f"\n📊 Summary Statistics:")
    print(f"  Reports Generated: {len(reports_generated)}")
    print(f"  Total Checks Analyzed: {total_checks}")
    print(f"  Total Automatable: {total_automatable} ({total_automatable/total_checks*100:.1f}%)")
    print(f"  Total Partially Automatable: {total_partial} ({total_partial/total_checks*100:.1f}%)")
    print(f"  Overall Automation Rate: {overall_automation_pct:.1f}%")
    print(f"\n📁 Reports created:")
    for report in reports_generated:
        print(f"  - {report}")
    print()

if __name__ == '__main__':
    main()
