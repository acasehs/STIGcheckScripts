#!/usr/bin/env python3
"""
STIG Check: V-2270
Severity: medium
Rule Title: Anonymous FTP user access to interactive scripts must be prohibited.
STIG ID: WG430 W22
Rule ID: SV-36714r1

Description:
    The directories containing the CGI scripts, such as PERL, must not be accessible to anonymous users via FTP. This applies to all directories that contain scripts that can dynamically produce web pages in an interactive manner (i.e., scripts based upon user-provided input). Such scripts contain infor...

Check Content:
    Locate the directories containing the CGI scripts. These directories should be language-specific (e.g., PERL, ASP, JS, JSP, etc.). _x000D_ _x000D_ Right-click on the web content directory and the related CGI directories. On the Properties tab, examine the access rights for the CGI, cgi-bin, or cgi-shl directories. _x000D_ _x000D_ Anonymous FTP users must not have access to these directories._x000D...

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
VULN_ID = "V-2270"
STIG_ID = "WG430 W22"
SEVERITY = "medium"
RULE_TITLE = """Anonymous FTP user access to interactive scripts must be prohibited."""


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


def get_apache_config():
    """Get Apache configuration paths."""
    commands = ['apachectl', 'apache2ctl', 'httpd']

    for cmd in commands:
        try:
            result = subprocess.run(
                [cmd, '-V'],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                httpd_root = None
                server_config = None

                for line in result.stdout.split('\n'):
                    if 'HTTPD_ROOT' in line:
                        httpd_root = line.split('"')[1]
                    if 'SERVER_CONFIG_FILE' in line:
                        server_config = line.split('"')[1]

                if httpd_root and server_config:
                    if server_config.startswith('/'):
                        return server_config
                    else:
                        return f"{httpd_root}/{server_config}"
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue

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
    # STIG Check Method from the official STIG:
    # Locate the directories containing the CGI scripts. These directories should be language-specific (e.g., PERL, ASP, JS, JSP, etc.). _x000D_ _x000D_ Right-click on the web content directory and the related CGI directories. On the Properties tab, examine the access rights for the CGI, cgi-bin, or cgi-shl directories. _x000D_ _x000D_ Anonymous FTP users must not have access to these directories._x000D_ _x000D_ If the CGI, the cgi-bin, or the cgi-shl directories can be accessed by any group that does...
    #
    # Fix Text from the official STIG:
    # If the CGI, the cgi-bin, or the cgi-shl directories can be accessed via FTP by any group or user that does not require access, remove permissions to such directories for all but the web administrators and the SAs. Ensure that any such access employs an encrypted connection.

    status = "Not Implemented"
    finding_details = "Check logic not yet implemented - requires Apache domain expertise"
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
