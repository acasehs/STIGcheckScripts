#!/usr/bin/env python3
"""
Batch RHEL STIG Framework Generator
Processes all 2 RHEL products from their extracted JSON files.
"""

import json
import sys
from pathlib import Path
from datetime import datetime
import stat

# Define all RHEL STIG products
RHEL_STIGS = [
    {
        "name": "Red Hat Enterprise Linux 8",
        "version": "2",
        "release": "4",
        "json_file": "rhel_8_v2r4_checks.json",
        "category": "os",
        "dir_name": "rhel_8_v2r4",
        "total_checks": 369
    },
    {
        "name": "Red Hat Enterprise Linux 9",
        "version": "2",
        "release": "5",
        "json_file": "rhel_9_v2r5_checks.json",
        "category": "os",
        "dir_name": "rhel_9_v2r5",
        "total_checks": 450
    }
]

# Bash script template
BASH_TEMPLATE = '''#!/usr/bin/env bash
################################################################################
# STIG Check: {vuln_id}
# Severity: {severity}
# Rule Title: {rule_title}
# STIG ID: {stig_id}
# Rule ID: {rule_id}
#
# Description:
#     {description}
#
# Check Content:
#     {check_content}
#
# Exit Codes:
#     0 = Check Passed (Compliant)
#     1 = Check Failed (Finding)
#     2 = Check Not Applicable
#     3 = Check Error
################################################################################

# Configuration
VULN_ID="{vuln_id}"
STIG_ID="{stig_id}"
SEVERITY="{severity}"
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
CONFIG_FILE=""
OUTPUT_JSON=""

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --config)
            CONFIG_FILE="$2"
            shift 2
            ;;
        --output-json)
            OUTPUT_JSON="$2"
            shift 2
            ;;
        -h|--help)
            cat << 'EOF'
Usage: $0 [OPTIONS]

Options:
  --config <file>         Configuration file (JSON)
  --output-json <file>    Output results in JSON format
  -h, --help             Show this help message

Exit Codes:
  0 = Pass (Compliant)
  1 = Fail (Finding)
  2 = Not Applicable
  3 = Error

Example:
  $0
  $0 --config stig-config.json
  $0 --output-json results.json
EOF
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 3
            ;;
    esac
done

# Load configuration if provided
if [[ -n "$CONFIG_FILE" ]]; then
    if [[ ! -f "$CONFIG_FILE" ]]; then
        echo "ERROR: Configuration file not found: $CONFIG_FILE"
        exit 3
    fi
    # TODO: Load configuration values using jq if available
fi

################################################################################
# CHECK IMPLEMENTATION
################################################################################

# TODO: Implement the actual check logic
#
# STIG Check Method from the official STIG:
# (See check header for details)
#
# Fix Text from the official STIG:
# (See check header for details)

echo "TODO: Implement check for {vuln_id}"
echo "This is a placeholder that requires implementation."

# Placeholder status
STATUS="Not Implemented"
EXIT_CODE=2
FINDING_DETAILS="Check logic not yet implemented - requires domain expertise"

################################################################################
# OUTPUT RESULTS
################################################################################

# JSON output if requested
if [[ -n "$OUTPUT_JSON" ]]; then
    cat > "$OUTPUT_JSON" << EOF_JSON
{{
  "vuln_id": "$VULN_ID",
  "stig_id": "$STIG_ID",
  "severity": "$SEVERITY",
  "rule_title": "{rule_title}",
  "status": "$STATUS",
  "finding_details": "$FINDING_DETAILS",
  "timestamp": "$TIMESTAMP",
  "exit_code": $EXIT_CODE
}}
EOF_JSON
fi

# Human-readable output
cat << EOF

================================================================================
STIG Check: $VULN_ID - $STIG_ID
Severity: ${{SEVERITY^^}}
================================================================================
Rule: {rule_title}
Status: $STATUS
Timestamp: $TIMESTAMP

--------------------------------------------------------------------------------
Finding Details:
--------------------------------------------------------------------------------
$FINDING_DETAILS

================================================================================

EOF

exit $EXIT_CODE
'''

# Python script template
PYTHON_TEMPLATE = '''#!/usr/bin/env python3
"""
STIG Check: {vuln_id}
Severity: {severity}
Rule Title: {rule_title}
STIG ID: {stig_id}
Rule ID: {rule_id}

Description:
    {description}

Check Content:
    {check_content}

Exit Codes:
    0 = Check Passed (Compliant)
    1 = Check Failed (Finding)
    2 = Check Not Applicable
    3 = Check Error
"""

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path

# Check metadata
VULN_ID = "{vuln_id}"
STIG_ID = "{stig_id}"
SEVERITY = "{severity}"
RULE_TITLE = """{rule_title}"""


def load_config(config_file):
    """Load configuration from JSON file."""
    try:
        with open(config_file, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"ERROR: Configuration file not found: {{config_file}}")
        sys.exit(3)
    except json.JSONDecodeError as e:
        print(f"ERROR: Invalid JSON: {{e}}")
        sys.exit(3)


def run_check(config=None):
    """
    Execute the STIG check.

    Args:
        config: Configuration dictionary

    Returns:
        tuple: (status, finding_details, exit_code)
    """
    # TODO: Implement the actual check logic
    #
    # STIG Check Method from the official STIG:
    # (See docstring above for details)
    #
    # Fix Text from the official STIG:
    # (See docstring above for details)

    status = "Not Implemented"
    finding_details = "Check logic not yet implemented - requires domain expertise"
    exit_code = 2

    return status, finding_details, exit_code


def output_json(result, output_file):
    """Write results to JSON file."""
    try:
        with open(output_file, 'w') as f:
            json.dump(result, f, indent=2)
    except IOError as e:
        print(f"ERROR: Failed to write JSON: {{e}}")
        sys.exit(3)


def output_human_readable(result):
    """Print human-readable results."""
    print()
    print("=" * 80)
    print(f"STIG Check: {{result['vuln_id']}} - {{result['stig_id']}}")
    print(f"Severity: {{result['severity'].upper()}}")
    print("=" * 80)
    print(f"Rule: {{result['rule_title']}}")
    print(f"Status: {{result['status']}}")
    print(f"Timestamp: {{result['timestamp']}}")
    print()
    print("-" * 80)
    print("Finding Details:")
    print("-" * 80)
    print(result['finding_details'])
    print()
    print("=" * 80)
    print()


def main():
    """Main function."""
    parser = argparse.ArgumentParser(
        description=f"Check {{VULN_ID}}: {{RULE_TITLE}}",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument(
        '--config',
        help='Configuration file (JSON)'
    )

    parser.add_argument(
        '--output-json',
        help='Output results in JSON format to specified file'
    )

    args = parser.parse_args()

    # Load configuration if provided
    config = None
    if args.config:
        config = load_config(args.config)

    # Run the check
    status, finding_details, exit_code = run_check(config)

    # Prepare result
    result = {{
        'vuln_id': VULN_ID,
        'stig_id': STIG_ID,
        'severity': SEVERITY,
        'rule_title': RULE_TITLE,
        'status': status,
        'finding_details': finding_details,
        'timestamp': datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ'),
        'exit_code': exit_code
    }}

    # Output JSON if requested
    if args.output_json:
        output_json(result, args.output_json)

    # Always output human-readable
    output_human_readable(result)

    sys.exit(exit_code)


if __name__ == '__main__':
    main()
'''

# README template
README_TEMPLATE = '''# {stig_name} v{version}r{release} - STIG Automation Framework

## Overview

Automated STIG compliance checks for **{stig_name} Version {version} Release {release}**.

- **Total Checks**: {total_checks}
- **Category**: {category}
- **STIG Version**: v{version}r{release}
- **Generated**: {generated_date}

## Quick Start

### Running Individual Checks

```bash
# Run bash version (primary)
bash {example_vuln}.sh

# Run python version (fallback)
python3 {example_vuln}.py

# With JSON output
bash {example_vuln}.sh --output-json results.json

# With configuration file
bash {example_vuln}.sh --config stig-config.json
```

### Running All Checks

```bash
# Create results directory
mkdir -p results

# Run all bash checks
for check in *.sh; do
    bash "$check" --output-json "results/${{check%.sh}}.json"
done
```

## Exit Codes

- **0** = PASS (Compliant)
- **1** = FAIL (Finding)
- **2** = N/A (Not Applicable)
- **3** = ERROR (Check execution error)

## Tool Requirements

### Bash Checks (Primary)
- bash 4.0+
- Standard UNIX utilities (grep, sed, awk)
- Optional: jq (for config file parsing)

### Python Checks (Fallback)
- Python 3.6+
- Standard library only

## Configuration File Support

Checks support a `stig-config.json` file for environment-specific values.

Example:
```json
{{
  "organization": {{
    "name": "Your Organization",
    "contact": "security@example.com"
  }}
}}
```

## Tool Priority

Following STIG automation best practices:
1. **bash** (1st priority for Linux/UNIX)
2. **python** (2nd priority - fallback)
3. third-party tools (avoided when possible)

## Check Structure

Each check script includes:
- STIG metadata (Vuln ID, STIG ID, Severity)
- Configuration file support (`--config`)
- JSON output support (`--output-json`)
- Help text (`--help`)
- Standardized exit codes

## Implementation Status

**Status**: Framework generated - implementation required

All checks are currently stubs with TODO comments. Full implementation requires:
1. Domain expertise for {stig_name}
2. Access to target systems for testing
3. Organization-specific configuration

## Contributing

To implement a check:
1. Open the check script ({example_vuln}.sh or {example_vuln}.py)
2. Review STIG requirements in header
3. Implement check logic in TODO section
4. Test on actual systems
5. Update documentation

## References

- [Official STIG Documentation](https://public.cyber.mil/stigs/)
- [STIG Viewer](https://www.stigviewer.com/)

## Directory Structure

```
{dir_name}/
├── README.md (this file)
├── {example_vuln}.sh (bash check)
├── {example_vuln}.py (python check)
└── ... ({total_checks} checks total)
```

---

**Generated**: {generated_date}
**STIG Version**: v{version}r{release}
**Total Checks**: {total_checks}
'''


def truncate_text(text, max_len=200):
    """Truncate text to specified length."""
    if not text:
        return ""
    text = text.replace('\n', ' ').replace('\r', '').strip()
    if len(text) > max_len:
        return text[:max_len] + "..."
    return text


def escape_bash(text):
    """Escape text for bash strings."""
    if not text:
        return ""
    return text.replace('\\', '\\\\').replace('"', '\\"').replace('$', '\\$')


def make_executable(file_path):
    """Make file executable."""
    current = file_path.stat().st_mode
    file_path.chmod(current | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def generate_scripts(check, output_dir):
    """Generate both bash and python scripts for a check."""
    vuln_id = check.get('Group ID', 'UNKNOWN')
    stig_id = check.get('STIG ID', 'UNKNOWN')
    severity = check.get('Severity', 'medium')
    rule_id = check.get('Rule ID', 'UNKNOWN')
    rule_title = check.get('Rule Title', 'Unknown')
    discussion = truncate_text(check.get('Discussion', ''), 300)
    check_content = truncate_text(check.get('Check Content', ''), 300)

    # Generate bash script
    bash_content = BASH_TEMPLATE.format(
        vuln_id=vuln_id,
        stig_id=stig_id,
        severity=severity,
        rule_id=rule_id,
        rule_title=rule_title,
        description=discussion,
        check_content=check_content
    )

    bash_path = output_dir / f"{vuln_id}.sh"
    bash_path.write_text(bash_content)
    make_executable(bash_path)

    # Generate python script
    python_content = PYTHON_TEMPLATE.format(
        vuln_id=vuln_id,
        stig_id=stig_id,
        severity=severity,
        rule_id=rule_id,
        rule_title=rule_title,
        description=discussion,
        check_content=check_content
    )

    python_path = output_dir / f"{vuln_id}.py"
    python_path.write_text(python_content)
    make_executable(python_path)

    return bash_path, python_path


def process_stig(stig, base_dir):
    """Process a single STIG product."""
    print(f"\n{'='*80}")
    print(f"Processing: {stig['name']} v{stig['version']}r{stig['release']}")
    print(f"{'='*80}")

    # Load JSON file
    json_path = base_dir / stig['json_file']
    if not json_path.exists():
        print(f"ERROR: JSON file not found: {json_path}")
        return False

    with open(json_path, 'r') as f:
        checks = json.load(f)

    print(f"Loaded {len(checks)} checks from {stig['json_file']}")

    # Create output directory
    output_dir = base_dir / 'checks' / stig['category'] / stig['dir_name']
    output_dir.mkdir(parents=True, exist_ok=True)
    print(f"Output directory: {output_dir}")

    # Generate scripts
    print(f"Generating check scripts...")
    for i, check in enumerate(checks, 1):
        bash_path, python_path = generate_scripts(check, output_dir)

        if i % 50 == 0 or i == len(checks):
            print(f"  Progress: {i}/{len(checks)} checks generated")

    # Generate README
    example_vuln = checks[0].get('Group ID', 'V-000000') if checks else 'V-000000'
    readme_content = README_TEMPLATE.format(
        stig_name=stig['name'],
        version=stig['version'],
        release=stig['release'],
        total_checks=len(checks),
        category=stig['category'],
        generated_date=datetime.now().strftime('%Y-%m-%d'),
        example_vuln=example_vuln,
        dir_name=stig['dir_name']
    )

    readme_path = output_dir / 'README.md'
    readme_path.write_text(readme_content)
    print(f"Generated README.md")

    print(f"\nCompleted: {stig['name']}")
    print(f"  Location: {output_dir}")
    print(f"  Files: {len(checks) * 2 + 1} ({len(checks)} bash, {len(checks)} python, 1 README)")

    return True


def main():
    """Main function."""
    base_dir = Path(__file__).parent

    print("="*80)
    print("RHEL STIG Automation Framework Generator")
    print("="*80)
    print(f"Base directory: {base_dir}")
    print(f"Processing {len(RHEL_STIGS)} RHEL products")

    summary = []
    total_checks = 0

    for stig in RHEL_STIGS:
        success = process_stig(stig, base_dir)
        summary.append({
            'name': stig['name'],
            'version': f"v{stig['version']}r{stig['release']}",
            'checks': stig['total_checks'],
            'success': success,
            'dir': f"checks/{stig['category']}/{stig['dir_name']}"
        })
        if success:
            total_checks += stig['total_checks']

    # Print summary
    print("\n" + "="*80)
    print("GENERATION SUMMARY")
    print("="*80)

    for item in summary:
        status = "SUCCESS" if item['success'] else "FAILED"
        print(f"{status:12} | {item['name']:40} {item['version']:10} ({item['checks']:3} checks)")
        print(f"             | {item['dir']}")

    print("\n" + "="*80)
    print(f"Total checks generated: {total_checks} (x2 for bash+python = {total_checks * 2} scripts)")
    print("="*80)
    print("\nNext Steps:")
    print("1. Review generated check scripts in checks/ directory")
    print("2. Implement actual check logic (replace TODO sections)")
    print("3. Create stig-config.json for environment-specific values")
    print("4. Test on target systems")
    print("5. Commit to version control")
    print("\nAll frameworks use:")
    print("  - bash (1st priority) + python (fallback)")
    print("  - Standardized exit codes (0=PASS, 1=FAIL, 2=N/A, 3=ERROR)")
    print("  - Config file support (--config)")
    print("  - JSON output support (--output-json)")

    return 0


if __name__ == '__main__':
    sys.exit(main())
