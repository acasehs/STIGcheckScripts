#!/usr/bin/env python3
"""
Universal Oracle STIG Generator

Generates complete STIG automation frameworks from AllSTIGS2.json for Oracle products.
Follows tool priority: bash > powershell > python > third-party

Usage:
    python3 generate_oracle_stigs.py --benchmark "Oracle Linux 8" --output-dir checks/os/oracle_linux_8_v2r5
    python3 generate_oracle_stigs.py --benchmark "Oracle Linux 9" --output-dir checks/os/oracle_linux_9_v1r2
    python3 generate_oracle_stigs.py --benchmark "Oracle WebLogic Server 12c" --output-dir checks/application/oracle_weblogic_12c_v2r2
"""

import json
import os
import argparse
from pathlib import Path
from datetime import datetime
import re


# Bash script template (HIGHEST PRIORITY for Linux/UNIX)
BASH_TEMPLATE = '''#!/usr/bin/env bash
# STIG Check: {vuln_id}
# STIG ID: {stig_id}
# Severity: {severity}
# Rule Title: {rule_title}
#
# Description:
# {description}
#
# Tool Priority: bash (1st priority) > python (fallback) > third-party (if required)
# Exit Codes: 0=PASS, 1=FAIL, 2=N/A, 3=ERROR

set -euo pipefail

# Configuration
VULN_ID="{vuln_id}"
STIG_ID="{stig_id}"
SEVERITY="{severity}"
STATUS="Open"
CONFIG_FILE=""
OUTPUT_JSON=false

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --config)
            CONFIG_FILE="$2"
            shift 2
            ;;
        --output-json)
            OUTPUT_JSON=true
            shift
            ;;
        --help)
            echo "Usage: $0 [--config FILE] [--output-json] [--help]"
            echo "  --config FILE    : Load configuration from FILE"
            echo "  --output-json    : Output results in JSON format"
            echo "  --help           : Show this help message"
            exit 0
            ;;
        *)
            shift
            ;;
    esac
done

# Load configuration if provided
if [[ -n "$CONFIG_FILE" ]] && [[ -f "$CONFIG_FILE" ]]; then
    # TODO: Load config values
    :
fi

# Main check logic
main() {{
    # TODO: Implement check logic based on:
    # Check Content: {check_method}

    {check_logic}
}}

# Execute check
if main; then
    if [[ "$OUTPUT_JSON" == "true" ]]; then
        cat <<EOF
{{
  "vuln_id": "$VULN_ID",
  "stig_id": "$STIG_ID",
  "severity": "$SEVERITY",
  "status": "NotAFinding",
  "finding_details": "",
  "comments": "Check passed",
  "evidence": {{}}
}}
EOF
    else
        echo "[$VULN_ID] PASS - Not a Finding"
    fi
    exit 0
else
    if [[ "$OUTPUT_JSON" == "true" ]]; then
        cat <<EOF
{{
  "vuln_id": "$VULN_ID",
  "stig_id": "$STIG_ID",
  "severity": "$SEVERITY",
  "status": "Open",
  "finding_details": "Check failed",
  "comments": "",
  "compliance_issues": []
}}
EOF
    else
        echo "[$VULN_ID] FAIL - Finding"
    fi
    exit 1
fi
'''

# Python script template (2nd priority - FALLBACK)
PYTHON_TEMPLATE = '''#!/usr/bin/env python3
"""
STIG Check: {vuln_id}
STIG ID: {stig_id}
Severity: {severity}
Rule Title: {rule_title}

Description:
{description}

Tool Priority: bash (1st priority) > python (2nd priority/fallback) > third-party (if required)
Exit Codes: 0=PASS, 1=FAIL, 2=N/A, 3=ERROR
"""

import json
import sys
import argparse
from pathlib import Path

# Configuration
VULN_ID = "{vuln_id}"
STIG_ID = "{stig_id}"
SEVERITY = "{severity}"

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
    # Check Content: {check_method}

    {python_check_logic}

    return False, dict(), ["Check not implemented"]

def main():
    parser = argparse.ArgumentParser(description='{rule_title}')
    parser.add_argument('--config', help='Configuration file path')
    parser.add_argument('--output-json', action='store_true', help='Output in JSON format')
    args = parser.parse_args()

    # Load configuration
    config = load_config(args.config)

    # Perform check
    passed, evidence, issues = perform_check(config)

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
        print(f"[{{VULN_ID}}] {{status}} - {{finding_status}}")

    return 0 if passed else 1

if __name__ == '__main__':
    sys.exit(main())
'''


def extract_checks(benchmark_name, source_json='AllSTIGS2.json'):
    """Extract checks for a specific benchmark from AllSTIGS2.json"""
    print(f"Loading {source_json}...")
    with open(source_json, 'r') as f:
        all_checks = json.load(f)

    # Filter by exact benchmark name
    checks = [c for c in all_checks if c.get('Benchmark Name', '') == benchmark_name]
    print(f"Found {len(checks)} checks for '{benchmark_name}'")

    if not checks:
        print(f"ERROR: No checks found for benchmark '{benchmark_name}'")
        return None

    # Get version info from first check
    version = checks[0].get('Version', 1)
    release_info = checks[0].get('Release Info', '')
    benchmark_id = checks[0].get('Benchmark ID', '')

    print(f"Benchmark ID: {benchmark_id}")
    print(f"Version: {version}")
    print(f"Release: {release_info}")

    return checks


def analyze_automation(check, platform='linux'):
    """Determine if check can be automated and recommend tool"""
    check_content = check.get('Check Content', '').lower()

    # Default: bash for Linux, powershell for Windows
    tool = 'bash' if platform == 'linux' else 'powershell'
    automatable = True
    method = 'Script-based check'

    # Check for manual review requirements
    manual_keywords = ['manual review', 'site security plan', 'organizational policy',
                       'documented', 'organization-defined']
    if any(kw in check_content for kw in manual_keywords):
        automatable = False
        method = 'Manual review required'

    return automatable, tool, method


def generate_bash_script(check, output_dir):
    """Generate bash script for a check (1st PRIORITY for Linux)"""
    vuln_id = check.get('Group ID', 'UNKNOWN')
    stig_id = check.get('STIG ID', 'UNKNOWN')
    severity = check.get('Severity', 'medium')
    rule_title = check.get('Rule Title', '')
    discussion = check.get('Discussion', '')[:200]  # Truncate
    check_content = check.get('Check Content', '')[:200]  # Truncate

    # Simple check logic placeholder
    check_logic = '''
    # TODO: Implement specific check logic
    # This is a placeholder - customize based on check requirements
    echo "Check not yet implemented" >&2
    return 3  # ERROR
'''

    script_content = BASH_TEMPLATE.format(
        vuln_id=vuln_id,
        stig_id=stig_id,
        severity=severity,
        rule_title=rule_title,
        description=discussion,
        check_method=check_content,
        check_logic=check_logic
    )

    # Write script
    script_path = Path(output_dir) / f"{vuln_id}.sh"
    with open(script_path, 'w') as f:
        f.write(script_content)

    # Make executable
    script_path.chmod(0o755)

    return script_path


def generate_python_script(check, output_dir):
    """Generate Python script for a check (2nd PRIORITY - FALLBACK)"""
    vuln_id = check.get('Group ID', 'UNKNOWN')
    stig_id = check.get('STIG ID', 'UNKNOWN')
    severity = check.get('Severity', 'medium')
    rule_title = check.get('Rule Title', '')
    discussion = check.get('Discussion', '')[:200]
    check_content = check.get('Check Content', '')[:200]

    # Simple check logic placeholder
    python_check_logic = '''
    # TODO: Implement specific check logic
    # This is a placeholder - customize based on check requirements
    return False, {}, ["Check not implemented"]
'''

    script_content = PYTHON_TEMPLATE.format(
        vuln_id=vuln_id,
        stig_id=stig_id,
        severity=severity,
        rule_title=rule_title,
        description=discussion,
        check_method=check_content,
        python_check_logic=python_check_logic
    )

    # Write script
    script_path = Path(output_dir) / f"{vuln_id}.py"
    with open(script_path, 'w') as f:
        f.write(script_content)

    # Make executable
    script_path.chmod(0o755)

    return script_path


def main():
    parser = argparse.ArgumentParser(description='Generate Oracle STIG automation framework')
    parser.add_argument('--benchmark', required=True, help='Benchmark name (e.g., "Oracle Linux 8")')
    parser.add_argument('--output-dir', required=True, help='Output directory')
    parser.add_argument('--source-json', default='AllSTIGS2.json', help='Source JSON file')
    parser.add_argument('--limit', type=int, help='Limit number of checks to generate (for testing)')

    args = parser.parse_args()

    # Extract checks
    checks = extract_checks(args.benchmark, args.source_json)
    if not checks:
        return 1

    # Create output directory
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    # Apply limit if specified
    if args.limit:
        checks = checks[:args.limit]
        print(f"Limiting to first {args.limit} checks for testing")

    # Determine platform
    platform = 'windows' if 'windows' in args.benchmark.lower() else 'linux'

    # Generate scripts (following priority: bash > python for Linux)
    print(f"\nGenerating {len(checks)} check scripts...")
    print(f"Tool Priority: {'bash > python' if platform == 'linux' else 'powershell > python'}")

    generated_count = 0
    for idx, check in enumerate(checks, 1):
        vuln_id = check.get('Group ID', f'UNKNOWN-{idx}')

        automatable, tool, method = analyze_automation(check, platform)

        if not automatable:
            print(f"  [{idx}/{len(checks)}] {vuln_id} - SKIPPED (manual review required)")
            continue

        # Generate bash script (1st PRIORITY for Linux)
        if platform == 'linux':
            bash_path = generate_bash_script(check, output_dir)
            python_path = generate_python_script(check, output_dir)
            generated_count += 1
            if idx % 50 == 0:
                print(f"  [{idx}/{len(checks)}] {vuln_id} - Generated (bash + python fallback)")
        else:
            # TODO: Add PowerShell generation for Windows
            python_path = generate_python_script(check, output_dir)
            generated_count += 1
            if idx % 50 == 0:
                print(f"  [{idx}/{len(checks)}] {vuln_id} - Generated (python)")

    print(f"\nGeneration complete!")
    print(f"Total checks: {len(checks)}")
    print(f"Generated: {generated_count}")
    print(f"Output directory: {output_dir}")

    return 0


if __name__ == '__main__':
    exit(main())
