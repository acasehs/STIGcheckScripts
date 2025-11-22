#!/usr/bin/env python3
"""
Universal Windows STIG Generator

Generates complete STIG automation frameworks from JSON files for Windows products.
Follows tool priority: PowerShell > Python > third-party

Usage:
    python3 generate_windows_stigs.py --source windows_10_checks.json --output-dir checks/os/windows_10_v3r4
    python3 generate_windows_stigs.py --source windows_11_checks.json --output-dir checks/os/windows_11_v2r4
"""

import json
import os
import argparse
from pathlib import Path
from datetime import datetime
import re


# PowerShell script template (HIGHEST PRIORITY for Windows)
POWERSHELL_TEMPLATE = '''# STIG Check: {vuln_id}
# STIG ID: {stig_id}
# Severity: {severity}
# Rule Title: {rule_title}
#
# Description:
# {description}
#
# Tool Priority: PowerShell (1st priority) > Python (fallback) > third-party (if required)
# Exit Codes: 0=PASS, 1=FAIL, 2=N/A, 3=ERROR

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$ConfigFile,

    [Parameter(Mandatory=$false)]
    [switch]$OutputJson,

    [Parameter(Mandatory=$false)]
    [switch]$Help
)

# Configuration
$VulnID = "{vuln_id}"
$StigID = "{stig_id}"
$Severity = "{severity}"
$Status = "Open"

# Show help
if ($Help) {{
    Write-Host "Usage: .\\{vuln_id}.ps1 [-ConfigFile FILE] [-OutputJson] [-Help]"
    Write-Host "  -ConfigFile FILE : Load configuration from FILE"
    Write-Host "  -OutputJson      : Output results in JSON format"
    Write-Host "  -Help            : Show this help message"
    exit 0
}}

# Load configuration if provided
if ($ConfigFile -and (Test-Path $ConfigFile)) {{
    # TODO: Load config values from JSON file
    $config = Get-Content $ConfigFile | ConvertFrom-Json
}}

# Main check logic
function Invoke-Check {{
    # TODO: Implement check logic based on:
    # {check_method}

    {check_logic}
}}

# Execute check
try {{
    $result = Invoke-Check

    if ($result) {{
        if ($OutputJson) {{
            $output = @{{
                vuln_id = $VulnID
                stig_id = $StigID
                severity = $Severity
                status = "NotAFinding"
                finding_details = ""
                comments = "Check passed"
                evidence = @{{}}
            }}
            Write-Host ($output | ConvertTo-Json -Depth 10)
        }} else {{
            Write-Host "[$VulnID] PASS - Not a Finding"
        }}
        exit 0
    }} else {{
        if ($OutputJson) {{
            $output = @{{
                vuln_id = $VulnID
                stig_id = $StigID
                severity = $Severity
                status = "Open"
                finding_details = "Check failed"
                comments = ""
                compliance_issues = @()
            }}
            Write-Host ($output | ConvertTo-Json -Depth 10)
        }} else {{
            Write-Host "[$VulnID] FAIL - Finding"
        }}
        exit 1
    }}
}} catch {{
    if ($OutputJson) {{
        $output = @{{
            vuln_id = $VulnID
            stig_id = $StigID
            severity = $Severity
            status = "Error"
            finding_details = $_.Exception.Message
            comments = "Error during check execution"
            compliance_issues = @()
        }}
        Write-Host ($output | ConvertTo-Json -Depth 10)
    }} else {{
        Write-Host "[$VulnID] ERROR - $($_.Exception.Message)"
    }}
    exit 3
}}
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

Tool Priority: PowerShell (1st priority) > Python (2nd priority/fallback) > third-party (if required)
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
    # {check_method}

    {python_check_logic}

def main():
    parser = argparse.ArgumentParser(description='{rule_title}')
    parser.add_argument('--config', help='Configuration file path')
    parser.add_argument('--output-json', action='store_true', help='Output in JSON format')
    args = parser.parse_args()

    # Load configuration
    config = load_config(args.config)

    # Perform check
    try:
        passed, evidence, issues = perform_check(config)
    except Exception as e:
        if args.output_json:
            result = {{
                "vuln_id": VULN_ID,
                "stig_id": STIG_ID,
                "severity": SEVERITY,
                "status": "Error",
                "finding_details": str(e),
                "comments": "Error during check execution",
                "compliance_issues": []
            }}
            print(json.dumps(result, indent=2))
        else:
            print(f"[{{VULN_ID}}] ERROR - {{str(e)}}")
        return 3

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

# README template for Windows
README_TEMPLATE = '''# {benchmark_name} STIG Automation Framework

## Overview

Automated compliance checking framework for {benchmark_name}.

- **Benchmark ID**: {benchmark_id}
- **Version**: {version}
- **Release**: {release_info}
- **Total Checks**: {total_checks}
- **Generated**: {generated_date}

## Tool Priority

For Windows systems, automation tools are prioritized as follows:

1. **PowerShell** (.ps1) - Primary automation tool
2. **Python** (.py) - Fallback/cross-platform option
3. **Third-party tools** - Only when necessary

## Exit Codes

All check scripts use standardized exit codes:

- `0` = PASS (Not a Finding)
- `1` = FAIL (Finding)
- `2` = N/A (Not Applicable)
- `3` = ERROR (Check execution error)

## Usage

### PowerShell (Primary)

```powershell
# Run a single check
.\\V-XXXXXX.ps1

# Run with JSON output
.\\V-XXXXXX.ps1 -OutputJson

# Run with configuration file
.\\V-XXXXXX.ps1 -ConfigFile config.json

# Show help
.\\V-XXXXXX.ps1 -Help
```

### Python (Fallback)

```bash
# Run a single check
python V-XXXXXX.py

# Run with JSON output
python V-XXXXXX.py --output-json

# Run with configuration file
python V-XXXXXX.py --config config.json
```

## Running All Checks

### PowerShell
```powershell
# Run all checks and save results
Get-ChildItem -Filter "V-*.ps1" | ForEach-Object {{
    $result = & $_.FullName -OutputJson | ConvertFrom-Json
    $result | Add-Member -NotePropertyName "script" -NotePropertyValue $_.Name
    $result
}} | ConvertTo-Json -Depth 10 | Out-File results.json
```

### Python
```bash
# Run all checks and save results
for script in V-*.py; do
    python "$script" --output-json
done > results.json
```

## Configuration

Create a `config.json` file to customize check parameters:

```json
{{
  "domain_joined": true,
  "org_policy_path": "/path/to/policy",
  "excluded_accounts": ["Administrator"],
  "custom_settings": {{}}
}}
```

## Directory Structure

```
{output_dir}/
├── README.md
├── V-XXXXXX.ps1          # PowerShell check (primary)
├── V-XXXXXX.py           # Python check (fallback)
├── ...
└── generation_report.txt
```

## Notes

- PowerShell scripts are the primary automation method for Windows
- Python scripts provide cross-platform fallback options
- Some checks may require manual review (documented in script comments)
- All scripts support both human-readable and JSON output formats
- Configuration file support allows customization for your environment

## Support

For issues or questions about these automation scripts, refer to the STIG documentation:
- {benchmark_name} STIG Viewer
- DISA STIG Library

Generated by: generate_windows_stigs.py
'''


def load_checks(source_json):
    """Load checks from JSON file"""
    print(f"Loading {source_json}...")
    with open(source_json, 'r') as f:
        checks = json.load(f)

    print(f"Found {len(checks)} checks")

    if not checks:
        print(f"ERROR: No checks found in {source_json}")
        return None, None

    # Get metadata from first check
    metadata = {
        'benchmark_name': checks[0].get('Benchmark Name', 'Unknown'),
        'benchmark_id': checks[0].get('Benchmark ID', 'Unknown'),
        'version': checks[0].get('Version', 1),
        'release_info': checks[0].get('Release Info', ''),
    }

    print(f"Benchmark: {metadata['benchmark_name']}")
    print(f"Benchmark ID: {metadata['benchmark_id']}")
    print(f"Version: {metadata['version']}")
    print(f"Release: {metadata['release_info']}")

    return checks, metadata


def analyze_automation(check):
    """Determine if check can be automated"""
    check_content = check.get('Check Content', '').lower()

    automatable = True
    method = 'Script-based check'

    # Check for manual review requirements
    manual_keywords = ['manual review', 'site security plan', 'organizational policy',
                       'organization-defined', 'interview', 'verify with']
    if any(kw in check_content for kw in manual_keywords):
        automatable = False
        method = 'Manual review required'

    return automatable, method


def generate_powershell_script(check, output_dir):
    """Generate PowerShell script for a check (1st PRIORITY for Windows)"""
    vuln_id = check.get('Group ID', 'UNKNOWN')
    stig_id = check.get('STIG ID', 'UNKNOWN')
    severity = check.get('Severity', 'medium')
    rule_title = check.get('Rule Title', '')
    discussion = check.get('Discussion', '')[:500]  # Truncate for comment
    check_content_raw = check.get('Check Content', '')

    # Format check content as PowerShell comment block
    check_content_lines = check_content_raw.split('\n')
    check_content = '\n    # '.join(check_content_lines[:20])  # Limit to 20 lines

    # Simple check logic placeholder
    check_logic = '''
    # TODO: Implement specific check logic
    # This is a placeholder - customize based on check requirements
    Write-Warning "Check not yet implemented"
    return $false
'''

    script_content = POWERSHELL_TEMPLATE.format(
        vuln_id=vuln_id,
        stig_id=stig_id,
        severity=severity,
        rule_title=rule_title,
        description=discussion,
        check_method=check_content,
        check_logic=check_logic
    )

    # Write script
    script_path = Path(output_dir) / f"{vuln_id}.ps1"
    with open(script_path, 'w', newline='\n') as f:
        f.write(script_content)

    return script_path


def generate_python_script(check, output_dir):
    """Generate Python script for a check (2nd PRIORITY - FALLBACK)"""
    vuln_id = check.get('Group ID', 'UNKNOWN')
    stig_id = check.get('STIG ID', 'UNKNOWN')
    severity = check.get('Severity', 'medium')
    rule_title = check.get('Rule Title', '')
    discussion = check.get('Discussion', '')[:500]
    check_content_raw = check.get('Check Content', '')

    # Format check content as Python comment block
    check_content_lines = check_content_raw.split('\n')
    check_content = '\n    # '.join(check_content_lines[:20])  # Limit to 20 lines

    # Simple check logic placeholder
    python_check_logic = '''# TODO: Implement specific check logic
    # This is a placeholder - customize based on check requirements
    return False, {}, ["Check not implemented"]'''

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


def generate_readme(metadata, output_dir, total_checks, generated_count):
    """Generate README.md for the framework"""
    content = README_TEMPLATE.format(
        benchmark_name=metadata['benchmark_name'],
        benchmark_id=metadata['benchmark_id'],
        version=metadata['version'],
        release_info=metadata['release_info'],
        total_checks=total_checks,
        generated_date=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        output_dir=output_dir.name
    )

    readme_path = output_dir / 'README.md'
    with open(readme_path, 'w') as f:
        f.write(content)

    return readme_path


def main():
    parser = argparse.ArgumentParser(description='Generate Windows STIG automation framework')
    parser.add_argument('--source', required=True, help='Source JSON file (e.g., windows_10_checks.json)')
    parser.add_argument('--output-dir', required=True, help='Output directory')
    parser.add_argument('--limit', type=int, help='Limit number of checks to generate (for testing)')

    args = parser.parse_args()

    # Load checks
    checks, metadata = load_checks(args.source)
    if not checks:
        return 1

    # Create output directory
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    # Apply limit if specified
    total_checks = len(checks)
    if args.limit:
        checks = checks[:args.limit]
        print(f"Limiting to first {args.limit} checks for testing")

    # Generate scripts (following priority: PowerShell > Python for Windows)
    print(f"\nGenerating {len(checks)} check scripts...")
    print(f"Tool Priority: PowerShell (primary) > Python (fallback)")

    generated_count = 0
    skipped_count = 0

    for idx, check in enumerate(checks, 1):
        vuln_id = check.get('Group ID', f'UNKNOWN-{idx}')

        automatable, method = analyze_automation(check)

        if not automatable:
            print(f"  [{idx}/{len(checks)}] {vuln_id} - SKIPPED (manual review required)")
            skipped_count += 1
            continue

        # Generate PowerShell script (1st PRIORITY for Windows)
        ps_path = generate_powershell_script(check, output_dir)

        # Generate Python script (FALLBACK)
        py_path = generate_python_script(check, output_dir)

        generated_count += 1
        if idx % 50 == 0 or idx == len(checks):
            print(f"  [{idx}/{len(checks)}] {vuln_id} - Generated (PowerShell + Python)")

    # Generate README
    readme_path = generate_readme(metadata, output_dir, total_checks, generated_count)

    # Generate summary report
    report_path = output_dir / 'generation_report.txt'
    with open(report_path, 'w') as f:
        f.write(f"Windows STIG Automation Framework Generation Report\n")
        f.write(f"{'='*60}\n\n")
        f.write(f"Benchmark: {metadata['benchmark_name']}\n")
        f.write(f"Benchmark ID: {metadata['benchmark_id']}\n")
        f.write(f"Version: {metadata['version']}\n")
        f.write(f"Release: {metadata['release_info']}\n")
        f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        f.write(f"Statistics:\n")
        f.write(f"  Total checks in source: {total_checks}\n")
        f.write(f"  Checks processed: {len(checks)}\n")
        f.write(f"  Scripts generated: {generated_count}\n")
        f.write(f"  Checks skipped (manual): {skipped_count}\n")
        f.write(f"  PowerShell scripts: {generated_count}\n")
        f.write(f"  Python scripts: {generated_count}\n")
        f.write(f"  Total files created: {generated_count * 2 + 2}\n\n")
        f.write(f"Output Directory: {output_dir}\n")
        f.write(f"Tool Priority: PowerShell (primary) > Python (fallback)\n")

    print(f"\nGeneration complete!")
    print(f"{'='*60}")
    print(f"Total checks in source: {total_checks}")
    print(f"Checks processed: {len(checks)}")
    print(f"Scripts generated: {generated_count}")
    print(f"Checks skipped (manual): {skipped_count}")
    print(f"PowerShell scripts (.ps1): {generated_count}")
    print(f"Python scripts (.py): {generated_count}")
    print(f"Total files created: {generated_count * 2 + 2} (scripts + README + report)")
    print(f"{'='*60}")
    print(f"Output directory: {output_dir}")
    print(f"README: {readme_path}")
    print(f"Report: {report_path}")

    return 0


if __name__ == '__main__':
    exit(main())
