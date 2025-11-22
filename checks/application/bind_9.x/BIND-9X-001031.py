#!/usr/bin/env python3
"""
STIG Check: V-207544
Severity: low
Rule Title: The print-time variable for the configuration of BIND 9.x server logs must be configured to establish when (date and time) the events occurred.
STIG ID: BIND-9X-001031
Rule ID: SV-207544r879564

Description:
    Without establishing when events occurred, it is impossible to establish, correlate, and investigate the events relating to an incident.   Associating event types with detected events in the application and audit logs provides a means of investigating an attack, recognizing resource utilization or c...

Check Content:
    For each logging channel that is defined, verify that the "print-time" sub statement is listed.  Inspect the "named.conf" file for the following:  logging { channel channel_name { print-time yes; }; };  If the "print-time" statement is missing, this is a finding.  If the "print-time" statement is no...

Exit Codes:
    0 = Check Passed (Compliant)
    1 = Check Failed (Finding)
    2 = Check Not Applicable
    3 = Check Error
"""

import argparse
import json
import sys
import subprocess
from datetime import datetime
from pathlib import Path

# Check metadata
VULN_ID = "V-207544"
STIG_ID = "BIND-9X-001031"
SEVERITY = "low"
RULE_TITLE = """The print-time variable for the configuration of BIND 9.x server logs must be configured to establish when (date and time) the events occurred."""


def load_config(config_file):
    """Load configuration from JSON file."""
    try:
        with open(config_file, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"ERROR: Configuration file not found: {config_file}")
        sys.exit(3)
    except json.JSONDecodeError as e:
        print(f"ERROR: Invalid JSON: {e}")
        sys.exit(3)


def get_bind_version():
    """Get BIND version."""
    try:
        result = subprocess.run(
            ['named', '-v'],
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.returncode == 0:
            return result.stdout.strip()
        return result.stderr.strip()
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None


def check_chroot():
    """Check if BIND is running in chroot."""
    try:
        result = subprocess.run(
            ['ps', '-ef'],
            capture_output=True,
            text=True,
            timeout=5
        )
        for line in result.stdout.split('\n'):
            if 'named' in line and 'grep' not in line:
                return line
        return None
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None


def get_bind_config():
    """Get BIND configuration file path."""
    config_locations = [
        '/etc/named.conf',
        '/etc/bind/named.conf',
        '/var/named/chroot/etc/named.conf',
        '/usr/local/etc/namedb/named.conf'
    ]

    for config_path in config_locations:
        if Path(config_path).exists():
            return config_path

    return None


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
    # This is a placeholder that requires BIND domain expertise.
    # Review the official STIG documentation for detailed check and fix procedures.

    status = "Not Implemented"
    finding_details = "Check logic not yet implemented - requires BIND domain expertise"
    exit_code = 2

    return status, finding_details, exit_code


def output_json(result, output_file):
    """Write results to JSON file."""
    try:
        with open(output_file, 'w') as f:
            json.dump(result, f, indent=2)
    except IOError as e:
        print(f"ERROR: Failed to write JSON: {e}")
        sys.exit(3)


def output_human_readable(result):
    """Print human-readable results."""
    print()
    print("=" * 80)
    print(f"STIG Check: {result['vuln_id']} - {result['stig_id']}")
    print(f"Severity: {result['severity'].upper()}")
    print("=" * 80)
    print(f"Rule: {result['rule_title']}")
    print(f"Status: {result['status']}")
    print(f"Timestamp: {result['timestamp']}")
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
        description=f"Check {VULN_ID}: {RULE_TITLE}",
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
    result = {
        'vuln_id': VULN_ID,
        'stig_id': STIG_ID,
        'severity': SEVERITY,
        'rule_title': RULE_TITLE,
        'status': status,
        'finding_details': finding_details,
        'timestamp': datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ'),
        'exit_code': exit_code
    }

    # Output JSON if requested
    if args.output_json:
        output_json(result, args.output_json)

    # Always output human-readable
    output_human_readable(result)

    sys.exit(exit_code)


if __name__ == '__main__':
    main()
