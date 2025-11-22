#!/usr/bin/env python3
"""
Generate STIG Check Analysis Report for Oracle WebLogic Server 12c
"""

import json
import re
from datetime import datetime

def analyze_check_automation(check):
    """Determine if a check can be automated"""
    check_content = check.get('Check Content', '').lower()
    fix_text = check.get('Fix Text', '').lower()
    discussion = check.get('Discussion', '').lower()

    # Keywords that indicate manual review required
    manual_keywords = [
        'network diagram',
        'documentation',
        'policy',
        'interview',
        'ask the ',
        'verify with',
        'obtain',
        'review organizational',
        'check with',
        'coordinate with'
    ]

    # Keywords that indicate environment-specific checks
    environment_keywords = [
        'approved',
        'organizational',
        'site-defined',
        'locally defined',
        'authorized',
        'designated',
        'appropriate to',
        'as needed',
        'in accordance with',
        'network topology',
        'security plan',
        'ssp'
    ]

    # Keywords that indicate system-specific checks
    system_keywords = [
        'production environment',
        'specific to',
        'depends on',
        'varies by',
        'deployment-specific',
        'installation-specific',
        'custom',
        'tailored'
    ]

    # Keywords that indicate configuration file checks
    config_keywords = [
        'config.xml',
        'configuration file',
        'property file',
        'setting',
        'parameter'
    ]

    # Keywords that indicate AC/EM checks (Admin Console/Enterprise Manager)
    gui_keywords = [
        'access ac',
        'access em',
        'admin console',
        'enterprise manager',
        'from \'domain structure\'',
        'select the domain',
        'click',
        'configuration tab'
    ]

    # Keywords that indicate WLST automatable
    wlst_keywords = [
        'server',
        'mbean',
        'jmx',
        'configuration',
        'domain'
    ]

    automation_status = 'Unknown'
    automation_method = 'Unknown'
    requires_elevation = True  # Most WebLogic checks require admin access
    notes = []
    is_environment_specific = False
    is_system_specific = False
    environment_notes = []

    # Check for environment-specific indicators
    for keyword in environment_keywords:
        if keyword in check_content or keyword in discussion or keyword in fix_text:
            is_environment_specific = True
            environment_notes.append(f'Environment-specific: Contains "{keyword}"')

    # Check for system-specific indicators
    for keyword in system_keywords:
        if keyword in check_content or keyword in discussion or keyword in fix_text:
            is_system_specific = True
            environment_notes.append(f'System-specific: Contains "{keyword}"')

    # Check for manual indicators
    for keyword in manual_keywords:
        if keyword in check_content or keyword in discussion:
            automation_status = 'Manual'
            automation_method = 'Manual review required'
            notes.append(f'Contains keyword: "{keyword}"')
            return automation_status, automation_method, requires_elevation, notes, is_environment_specific, is_system_specific, environment_notes

    # Check for GUI-based checks (can be automated via WLST)
    for keyword in gui_keywords:
        if keyword in check_content:
            automation_status = 'Automatable'
            automation_method = 'WLST (WebLogic Scripting Tool)'
            notes.append('Admin Console/EM check - can be automated via WLST/JMX')
            return automation_status, automation_method, requires_elevation, notes, is_environment_specific, is_system_specific, environment_notes

    # Check for config file checks
    for keyword in config_keywords:
        if keyword in check_content or keyword in fix_text:
            automation_status = 'Automatable'
            automation_method = 'XML/Config file parsing'
            notes.append('Configuration file check - can be automated')
            return automation_status, automation_method, requires_elevation, notes, is_environment_specific, is_system_specific, environment_notes

    # Default: if it mentions servers/configuration, likely automatable
    for keyword in wlst_keywords:
        if keyword in check_content:
            automation_status = 'Partially Automatable'
            automation_method = 'WLST or manual verification'
            notes.append('May require WLST scripting with manual validation')
            return automation_status, automation_method, requires_elevation, notes, is_environment_specific, is_system_specific, environment_notes

    # If we get here, mark as needs analysis
    automation_status = 'Needs Analysis'
    automation_method = 'Review required'
    notes.append('Automation feasibility needs detailed analysis')

    return automation_status, automation_method, requires_elevation, notes, is_environment_specific, is_system_specific, environment_notes


def generate_markdown_report(checks):
    """Generate comprehensive markdown report"""

    report = []
    report.append("# Oracle WebLogic Server 12c STIG Check Analysis Report\n")
    report.append(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    report.append(f"**STIG:** {checks[0]['STIG']}\n")
    report.append(f"**Total Checks:** {len(checks)}\n")
    report.append("\n---\n")

    report.append("\n## 📊 Executive Summary\n")

    # Calculate statistics
    automatable = 0
    partial = 0
    manual = 0
    needs_analysis = 0
    environment_specific_count = 0
    system_specific_count = 0

    severity_counts = {'high': 0, 'medium': 0, 'low': 0}
    automation_by_severity = {
        'high': {'automatable': 0, 'partial': 0, 'manual': 0, 'total': 0},
        'medium': {'automatable': 0, 'partial': 0, 'manual': 0, 'total': 0},
        'low': {'automatable': 0, 'partial': 0, 'manual': 0, 'total': 0}
    }

    for check in checks:
        auto_status, _, _, _, is_env, is_sys, _ = analyze_check_automation(check)
        severity = check.get('Severity', 'medium').lower()

        if auto_status == 'Automatable':
            automatable += 1
            automation_by_severity[severity]['automatable'] += 1
        elif auto_status == 'Partially Automatable':
            partial += 1
            automation_by_severity[severity]['partial'] += 1
        elif auto_status == 'Manual':
            manual += 1
            automation_by_severity[severity]['manual'] += 1
        else:
            needs_analysis += 1

        if is_env:
            environment_specific_count += 1
        if is_sys:
            system_specific_count += 1

        severity_counts[severity] = severity_counts.get(severity, 0) + 1
        automation_by_severity[severity]['total'] += 1

    # Generate summary tables
    report.append("\n### Automation Status Overview\n\n")
    report.append("| Automation Status | Count | Percentage | Status |\n")
    report.append("|------------------|-------|------------|--------|\n")
    report.append(f"| ✅ Automatable | {automatable} | {automatable/len(checks)*100:.1f}% | Can be fully automated |\n")
    report.append(f"| ⚠️ Partially Automatable | {partial} | {partial/len(checks)*100:.1f}% | Requires some manual validation |\n")
    report.append(f"| 📝 Manual Review Required | {manual} | {manual/len(checks)*100:.1f}% | Cannot be automated |\n")
    report.append(f"| 🔍 Needs Analysis | {needs_analysis} | {needs_analysis/len(checks)*100:.1f}% | Automation feasibility TBD |\n")
    report.append(f"| **TOTAL** | **{len(checks)}** | **100.0%** | |\n")

    report.append("\n### Automation Status by Severity\n\n")
    report.append("| Severity | Total | Automatable | Partial | Manual | Automation Rate |\n")
    report.append("|----------|-------|-------------|---------|--------|----------------|\n")
    for sev in ['high', 'medium', 'low']:
        total = automation_by_severity[sev]['total']
        auto = automation_by_severity[sev]['automatable']
        part = automation_by_severity[sev]['partial']
        man = automation_by_severity[sev]['manual']
        auto_rate = ((auto + part) / total * 100) if total > 0 else 0
        report.append(f"| {sev.upper()} | {total} | {auto} | {part} | {man} | {auto_rate:.1f}% |\n")

    total_all = len(checks)
    auto_all = automatable + partial
    auto_rate_all = (auto_all / total_all * 100)
    report.append(f"| **TOTAL** | **{total_all}** | **{automatable}** | **{partial}** | **{manual}** | **{auto_rate_all:.1f}%** |\n")

    report.append("\n### Configuration Dependencies\n\n")
    report.append("| Dependency Type | Count | Percentage | Description |\n")
    report.append("|----------------|-------|------------|-------------|\n")
    report.append(f"| 🌐 Environment-Specific | {environment_specific_count} | {environment_specific_count/len(checks)*100:.1f}% | Requires site-specific/organizational values |\n")
    report.append(f"| 🖥️ System-Specific | {system_specific_count} | {system_specific_count/len(checks)*100:.1f}% | Depends on deployment/installation config |\n")
    report.append(f"| ✓ Standard | {len(checks) - environment_specific_count - system_specific_count} | {(len(checks) - environment_specific_count - system_specific_count)/len(checks)*100:.1f}% | No special dependencies |\n")

    report.append("\n### Severity Distribution\n\n")
    report.append("| Severity | Count | Percentage |\n")
    report.append("|----------|-------|------------|\n")
    report.append(f"| 🔴 HIGH | {severity_counts.get('high', 0)} | {severity_counts.get('high', 0)/len(checks)*100:.1f}% |\n")
    report.append(f"| 🟡 MEDIUM | {severity_counts.get('medium', 0)} | {severity_counts.get('medium', 0)/len(checks)*100:.1f}% |\n")
    report.append(f"| 🟢 LOW | {severity_counts.get('low', 0)} | {severity_counts.get('low', 0)/len(checks)*100:.1f}% |\n")
    report.append(f"| **TOTAL** | **{len(checks)}** | **100.0%** |\n")

    # Keep old summary for compatibility
    report.append("\n## Summary\n")
    report.append(f"- **Automatable Checks:** {automatable} ({automatable/len(checks)*100:.1f}%)\n")
    report.append(f"- **Partially Automatable:** {partial} ({partial/len(checks)*100:.1f}%)\n")
    report.append(f"- **Manual Review Required:** {manual} ({manual/len(checks)*100:.1f}%)\n")
    report.append(f"- **Needs Analysis:** {needs_analysis} ({needs_analysis/len(checks)*100:.1f}%)\n")
    report.append("\n### Environment/System Specific Checks\n")
    report.append(f"- **Environment-Specific:** {environment_specific_count} ({environment_specific_count/len(checks)*100:.1f}%)\n")
    report.append(f"  - *These checks require site-specific, organizational, or approved values*\n")
    report.append(f"- **System-Specific:** {system_specific_count} ({system_specific_count/len(checks)*100:.1f}%)\n")
    report.append(f"  - *These checks depend on deployment or installation-specific configurations*\n")
    report.append("\n### Severity Distribution\n")
    report.append(f"- **High:** {severity_counts.get('high', 0)}\n")
    report.append(f"- **Medium:** {severity_counts.get('medium', 0)}\n")
    report.append(f"- **Low:** {severity_counts.get('low', 0)}\n")

    report.append("\n---\n")

    # Detailed check listing
    report.append("\n## Detailed Check Analysis\n")

    # Group by automation status
    grouped_checks = {
        'Automatable': [],
        'Partially Automatable': [],
        'Manual': [],
        'Needs Analysis': []
    }

    for check in checks:
        auto_status, auto_method, requires_elev, notes, is_env, is_sys, env_notes = analyze_check_automation(check)
        check_info = {
            'check': check,
            'auto_method': auto_method,
            'requires_elev': requires_elev,
            'notes': notes,
            'is_environment_specific': is_env,
            'is_system_specific': is_sys,
            'environment_notes': env_notes
        }
        grouped_checks[auto_status].append(check_info)

    # Output each group
    for group_name in ['Automatable', 'Partially Automatable', 'Manual', 'Needs Analysis']:
        group_checks = grouped_checks[group_name]
        if not group_checks:
            continue

        report.append(f"\n### {group_name} ({len(group_checks)} checks)\n")

        for item in group_checks:
            check = item['check']
            vuln_id = check['Vuln ID']
            stig_id = check.get('STIG ID', 'N/A')
            severity = check['Severity']
            title = check['Rule Title']

            report.append(f"\n#### {vuln_id} - {stig_id}\n")
            report.append(f"**Severity:** {severity.upper()}\n\n")
            report.append(f"**Rule Title:** {title}\n\n")
            report.append(f"**Automation Status:** {group_name}\n\n")
            report.append(f"**Automation Method:** {item['auto_method']}\n\n")
            report.append(f"**Requires Elevation:** {'Yes (WebLogic Admin credentials)' if item['requires_elev'] else 'No'}\n\n")

            # Add environment/system specific indicators
            if item['is_environment_specific'] or item['is_system_specific']:
                report.append(f"**🔧 Configuration Dependencies:**\n")
                if item['is_environment_specific']:
                    report.append(f"- ⚠️ **ENVIRONMENT-SPECIFIC**: This check requires site-specific or organizational values\n")
                if item['is_system_specific']:
                    report.append(f"- ⚠️ **SYSTEM-SPECIFIC**: This check depends on deployment/installation-specific configuration\n")
                report.append("\n")

            if item['notes']:
                report.append(f"**Notes:**\n")
                for note in item['notes']:
                    report.append(f"- {note}\n")
                report.append("\n")

            if item['environment_notes']:
                report.append(f"**Environment/System Annotations:**\n")
                for env_note in item['environment_notes']:
                    report.append(f"- {env_note}\n")
                report.append("\n")

            # Add check content summary
            check_content = check.get('Check Content', 'N/A')
            # Truncate if too long
            if len(check_content) > 500:
                check_content = check_content[:500] + "..."

            report.append(f"**Check Content:**\n```\n{check_content}\n```\n")

            # Execution command for automatable checks
            if group_name == 'Automatable' or group_name == 'Partially Automatable':
                script_name = f"V-{vuln_id.split('-')[1]}.py"
                report.append(f"**Execution Command:**\n")
                report.append(f"```bash\n")
                report.append(f"# Standard execution\n")
                report.append(f"python3 checks/application/oracle_weblogic_server_12c/{script_name} \\\n")
                report.append(f"  --admin-url t3://localhost:7001 \\\n")
                report.append(f"  --username weblogic \\\n")
                report.append(f"  --password <password>\n\n")
                report.append(f"# With JSON output\n")
                report.append(f"python3 checks/application/oracle_weblogic_server_12c/{script_name} \\\n")
                report.append(f"  --admin-url t3://localhost:7001 \\\n")
                report.append(f"  --username weblogic \\\n")
                report.append(f"  --password <password> \\\n")
                report.append(f"  --output-json results/{vuln_id}.json\n\n")
                report.append(f"# Force execution without elevation check\n")
                report.append(f"python3 checks/application/oracle_weblogic_server_12c/{script_name} \\\n")
                report.append(f"  --admin-url t3://localhost:7001 \\\n")
                report.append(f"  --username weblogic \\\n")
                report.append(f"  --password <password> \\\n")
                report.append(f"  --force\n")
                report.append(f"```\n")

            # NIST references
            nist_refs = check.get('NIST SP 800-53 Revision 4 References', 'N/A')
            report.append(f"\n**NIST SP 800-53 Rev 4:** {nist_refs}\n")

            report.append("\n" + "-"*80 + "\n")

    # Appendix
    report.append("\n## Appendix\n")
    report.append("\n### Prerequisites\n")
    report.append("- Oracle WebLogic Server 12c installation\n")
    report.append("- WLST (WebLogic Scripting Tool) available in PATH or WLST_PATH environment variable set\n")
    report.append("- WebLogic admin credentials\n")
    report.append("- Python 3.6 or higher\n")
    report.append("- Network access to WebLogic Admin Server\n")

    report.append("\n### Environment Variables\n")
    report.append("```bash\n")
    report.append("export WLST_PATH=/path/to/oracle/middleware/oracle_common/common/bin/wlst.sh\n")
    report.append("export WL_HOME=/path/to/oracle/middleware/wlserver\n")
    report.append("```\n")

    report.append("\n### Exit Codes\n")
    report.append("- `0` - **PASS**: Check passed, no findings\n")
    report.append("- `1` - **FAIL**: Check failed, findings detected\n")
    report.append("- `2` - **N/A**: Check not applicable or requires manual review\n")
    report.append("- `3` - **ERROR**: Error occurred during check execution\n")

    report.append("\n### Output Formats\n")
    report.append("All automated checks support multiple output formats:\n\n")
    report.append("1. **Human Readable** (default to stdout)\n")
    report.append("2. **JSON** (via `--output-json` parameter)\n")
    report.append("3. **Exit Codes** (for scripting/automation)\n")

    report.append("\n### JSON Output Schema\n")
    report.append("```json\n")
    report.append("""{
  "vuln_id": "V-235928",
  "severity": "medium",
  "stig_id": "WBLC-01-000009",
  "rule_title": "Rule description",
  "status": "NotAFinding|Open|Manual Review Required|Error",
  "finding_details": [],
  "timestamp": "ISO 8601 timestamp",
  "requires_elevation": true,
  "exit_code": 0
}
""")
    report.append("```\n")

    return ''.join(report)


def main():
    import sys

    # Determine which version to use
    if len(sys.argv) > 1 and sys.argv[1] == 'v2':
        json_file = 'weblogic_checks_v2.json'
        report_file = 'reports/Oracle_WebLogic_Server_12c_STIG_Analysis_v2.md'
        version_label = 'v2'
    else:
        json_file = 'weblogic_checks.json'
        report_file = 'reports/Oracle_WebLogic_Server_12c_STIG_Analysis.md'
        version_label = 'v1'

    # Load WebLogic checks
    try:
        with open(json_file, 'r') as f:
            checks = json.load(f)
    except FileNotFoundError:
        print(f"Error: {json_file} not found!")
        sys.exit(1)

    # Generate report
    report = generate_markdown_report(checks)

    # Save report
    with open(report_file, 'w') as f:
        f.write(report)

    print(f"Report generated: {report_file}")
    print(f"Total checks analyzed: {len(checks)}")
    print(f"Version: {version_label}")


if __name__ == '__main__':
    main()
