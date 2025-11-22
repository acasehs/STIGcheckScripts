#!/usr/bin/env python3
"""
STIG Check: V-248519
Severity: medium
Rule Title: The OL 8 audit package must be installed.
STIG ID: OL08-00-030180
STIG Version: Oracle Linux 8 v1r7
Requires Elevation: No (package query doesn't require root)
Third-Party Tools: None (uses Python stdlib)

Description:
    Verifies that the audit package is installed on the system.
    The audit service is required for security auditing and compliance.

Execution:
    python3 V-248519.py
    python3 V-248519.py --config stig-config.json
    python3 V-248519.py --config stig-config.json --output-json results.json

Output Formats:
    - Exit Code: 0 (Pass), 1 (Fail), 2 (Not Applicable), 3 (Error)
    - JSON: --output-json results.json
    - Human Readable: Default to stdout
"""

import sys
import os
import json
import argparse
import subprocess
from datetime import datetime
from pathlib import Path


class STIGCheck:
    def __init__(self, config_file=None, force=False):
        self.config_file = Path(config_file) if config_file else None
        self.force = force

        # Default required package
        self.required_package = "audit"

        # Load configuration if provided
        if self.config_file:
            self.load_config()

        self.results = {
            'vuln_id': 'V-248519',
            'severity': 'medium',
            'stig_id': 'OL08-00-030180',
            'stig_version': 'Oracle Linux 8 v1r7',
            'rule_title': 'The OL 8 audit package must be installed.',
            'status': 'Not Checked',
            'finding_details': [],
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'requires_elevation': False,
            'third_party_tools': 'None (uses Python stdlib)',
            'check_method': 'Python - subprocess package manager query',
            'config_file': str(self.config_file) if self.config_file else 'None (using defaults)'
        }

    def load_config(self):
        """Load environment-specific values from config file"""
        try:
            with open(self.config_file, 'r') as f:
                config = json.load(f)

            os_config = config.get('operating_system', {})

            # Verify required package is in the config
            if 'required_packages' in os_config:
                required_packages = os_config['required_packages'].get('values', [])
                if self.required_package in required_packages:
                    print(f"INFO: Loaded configuration from {self.config_file}")
                    print(f"  - Required package: {self.required_package} (verified in config)")

        except FileNotFoundError:
            print(f"ERROR: Configuration file not found: {self.config_file}")
            sys.exit(3)
        except json.JSONDecodeError as e:
            print(f"ERROR: Invalid JSON in config file: {e}")
            sys.exit(3)
        except Exception as e:
            print(f"ERROR: Failed to load config file: {e}")
            sys.exit(3)

    def check_package_installed(self, package):
        """Check if a package is installed using yum/rpm"""
        # Try yum first
        try:
            result = subprocess.run(
                ['yum', 'list', 'installed', package],
                capture_output=True,
                text=True,
                timeout=30
            )
            if result.returncode == 0:
                return True, self.get_package_version(package)
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

        # Fallback to rpm
        try:
            result = subprocess.run(
                ['rpm', '-q', package],
                capture_output=True,
                text=True,
                timeout=30
            )
            if result.returncode == 0:
                return True, result.stdout.strip()
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

        return False, 'N/A'

    def get_package_version(self, package):
        """Get installed package version"""
        try:
            result = subprocess.run(
                ['rpm', '-q', package],
                capture_output=True,
                text=True,
                timeout=30
            )
            if result.returncode == 0:
                return result.stdout.strip()
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

        return 'unknown'

    def run_check(self):
        """Execute the STIG check"""
        try:
            # Check if audit package is installed
            is_installed, package_version = self.check_package_installed(self.required_package)

            finding = {
                'package': self.required_package,
                'check_details': {
                    'what_was_checked': 'Audit package installation status',
                    'requirement': 'The audit package must be installed for security auditing'
                }
            }

            if is_installed:
                # PASS - Package is installed
                self.results['status'] = 'NotAFinding'

                finding.update({
                    'status': 'PASS',
                    'reason': 'Required audit package is installed',
                    'check_details': {
                        **finding['check_details'],
                        'actual_configuration': {
                            'package_name': self.required_package,
                            'installed': 'true',
                            'version': package_version
                        },
                        'expected_configuration': {
                            'package_name': self.required_package,
                            'installed': 'true',
                            'version': 'any'
                        }
                    },
                    'evidence': {
                        'package_installed': f"Package '{self.required_package}' is installed",
                        'package_version': f"Version: {package_version}",
                        'verification_method': 'Verified using yum/rpm package manager',
                        'conclusion': 'System meets audit package installation requirements'
                    }
                })

                self.results['finding_details'].append(finding)
                return 0  # PASS

            else:
                # FAIL - Package not installed
                self.results['status'] = 'Open'

                finding.update({
                    'status': 'FAIL',
                    'reason': 'Required audit package is not installed',
                    'check_details': {
                        **finding['check_details'],
                        'actual_configuration': {
                            'package_name': self.required_package,
                            'installed': 'false',
                            'version': 'N/A'
                        },
                        'expected_configuration': {
                            'package_name': self.required_package,
                            'installed': 'true',
                            'version': 'any'
                        }
                    },
                    'compliance_issues': [
                        {
                            'issue': 'Audit package not installed',
                            'evidence': f"Package '{self.required_package}' is not present on the system",
                            'expected': f"Package '{self.required_package}' must be installed",
                            'risk': 'Without the audit package, the system cannot perform security auditing, making it difficult to investigate security incidents and maintain compliance',
                            'remediation': f"Install the audit package using: sudo yum install {self.required_package}"
                        }
                    ],
                    'recommendation': 'Install the audit package immediately to enable security auditing'
                })

                self.results['finding_details'].append(finding)
                return 1  # FAIL

        except Exception as e:
            self.results['status'] = 'Error'
            self.results['finding_details'].append({
                'error': str(e),
                'message': 'Failed to check package installation status'
            })
            return 3

    def get_results(self):
        """Return results dictionary"""
        return self.results

    def print_results(self):
        """Print human-readable results"""
        print(f"\n{'='*80}")
        print(f"STIG Check: {self.results['vuln_id']} - {self.results['stig_id']}")
        print(f"STIG Version: {self.results['stig_version']}")
        print(f"Severity: {self.results['severity'].upper()}")
        print(f"{'='*80}")
        print(f"Rule: {self.results['rule_title']}")
        print(f"Status: {self.results['status']}")
        print(f"Timestamp: {self.results['timestamp']}")
        print(f"Requires Elevation: {self.results['requires_elevation']}")
        print(f"Third-Party Tools: {self.results['third_party_tools']}")
        print(f"Check Method: {self.results['check_method']}")
        print(f"\n{'-'*80}")
        print("Finding Details:")
        print(f"{'-'*80}")

        for detail in self.results['finding_details']:
            if isinstance(detail, dict):
                if 'package' in detail:
                    print(f"\nPackage: {detail['package']}")
                    print(f"  Status: {detail.get('status', 'N/A')}")
                    print(f"  Reason: {detail.get('reason', 'N/A')}")

                    # Show check details
                    if 'check_details' in detail:
                        check_info = detail['check_details']
                        print(f"\n  What Was Checked:")
                        print(f"    {check_info.get('what_was_checked', 'N/A')}")
                        print(f"  Requirement:")
                        print(f"    {check_info.get('requirement', 'N/A')}")

                    # Show compliance issues for FAIL status
                    if detail.get('status') == 'FAIL' and 'compliance_issues' in detail:
                        print(f"\n  Compliance Issues ({len(detail['compliance_issues'])}):")
                        for i, issue in enumerate(detail['compliance_issues'], 1):
                            print(f"\n    Issue #{i}: {issue.get('issue', 'N/A')}")
                            print(f"      Evidence Found: {issue.get('evidence', 'N/A')}")
                            print(f"      Expected: {issue.get('expected', 'N/A')}")
                            print(f"      Risk: {issue.get('risk', 'N/A')}")
                            print(f"      Remediation: {issue.get('remediation', 'N/A')}")

                        if 'recommendation' in detail:
                            print(f"\n  Recommendation: {detail['recommendation']}")

                    # Show evidence for PASS status
                    elif detail.get('status') == 'PASS' and 'evidence' in detail:
                        print(f"\n  Evidence Supporting PASS:")
                        evidence = detail['evidence']
                        for key, value in evidence.items():
                            if key != 'conclusion':
                                print(f"    ✓ {value}")
                        if 'conclusion' in evidence:
                            print(f"\n  Conclusion: {evidence['conclusion']}")

                    # Show actual vs expected configuration
                    if 'check_details' in detail:
                        check_info = detail['check_details']
                        if 'actual_configuration' in check_info:
                            print(f"\n  Actual Configuration:")
                            for key, value in check_info['actual_configuration'].items():
                                print(f"    - {key}: {value}")
                        if 'expected_configuration' in check_info:
                            print(f"  Expected Configuration:")
                            for key, value in check_info['expected_configuration'].items():
                                print(f"    - {key}: {value}")

                elif 'error' in detail:
                    print(f"\nError: {detail['error']}")
                    if 'message' in detail:
                        print(f"Message: {detail['message']}")
            else:
                print(f"  {detail}")

        print(f"\n{'='*80}\n")


def main():
    parser = argparse.ArgumentParser(
        description='V-248519: Check audit package installation',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    parser.add_argument('--config', metavar='FILE',
                       help='STIG configuration file (JSON) with environment-specific values')
    parser.add_argument('--force', action='store_true',
                       help='Force execution even without proper elevation')
    parser.add_argument('--output-json', metavar='FILE',
                       help='Output results to JSON file')

    args = parser.parse_args()

    # Run the check
    check = STIGCheck(args.config, args.force)
    exit_code = check.run_check()

    # Output results
    if args.output_json:
        results = check.get_results()
        results['exit_code'] = exit_code
        with open(args.output_json, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"Results written to: {args.output_json}")

    check.print_results()

    sys.exit(exit_code)


if __name__ == '__main__':
    main()
