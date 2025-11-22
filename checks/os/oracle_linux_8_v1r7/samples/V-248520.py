#!/usr/bin/env python3
"""
STIG Check: V-248520
Severity: medium
Rule Title: OL 8 audit records must contain information to establish what type of events occurred, the source of events, where events occurred, and the outcome of events.
STIG ID: OL08-00-030181
STIG Version: Oracle Linux 8 v1r7
Requires Elevation: No (systemctl status doesn't require root)
Third-Party Tools: None (uses Python stdlib)

Description:
    Verifies that the auditd service is active and running.
    The audit service must be operational to produce audit records.

Execution:
    python3 V-248520.py
    python3 V-248520.py --config stig-config.json
    python3 V-248520.py --config stig-config.json --output-json results.json

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

        # Default required service
        self.required_service = "auditd"

        # Load configuration if provided
        if self.config_file:
            self.load_config()

        self.results = {
            'vuln_id': 'V-248520',
            'severity': 'medium',
            'stig_id': 'OL08-00-030181',
            'stig_version': 'Oracle Linux 8 v1r7',
            'rule_title': 'OL 8 audit records must contain information to establish what type of events occurred, the source of events, where events occurred, and the outcome of events.',
            'status': 'Not Checked',
            'finding_details': [],
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'requires_elevation': False,
            'third_party_tools': 'None (uses Python stdlib)',
            'check_method': 'Python - subprocess systemctl commands',
            'config_file': str(self.config_file) if self.config_file else 'None (using defaults)'
        }

    def load_config(self):
        """Load environment-specific values from config file"""
        try:
            with open(self.config_file, 'r') as f:
                config = json.load(f)

            os_config = config.get('operating_system', {})

            # Verify audit enabled setting
            if 'audit_settings' in os_config:
                audit_settings = os_config['audit_settings']
                audit_enabled = audit_settings.get('audit_enabled', {}).get('value', True)
                if audit_enabled:
                    print(f"INFO: Loaded configuration from {self.config_file}")
                    print(f"  - Audit enabled requirement: {audit_enabled}")

        except FileNotFoundError:
            print(f"ERROR: Configuration file not found: {self.config_file}")
            sys.exit(3)
        except json.JSONDecodeError as e:
            print(f"ERROR: Invalid JSON in config file: {e}")
            sys.exit(3)
        except Exception as e:
            print(f"ERROR: Failed to load config file: {e}")
            sys.exit(3)

    def check_service_status(self, service):
        """Check if a service is active and enabled"""
        try:
            # Check if service is active
            result_active = subprocess.run(
                ['systemctl', 'is-active', service],
                capture_output=True,
                text=True,
                timeout=10
            )
            is_active = result_active.stdout.strip()

            # Check if service is enabled
            result_enabled = subprocess.run(
                ['systemctl', 'is-enabled', service],
                capture_output=True,
                text=True,
                timeout=10
            )
            is_enabled = result_enabled.stdout.strip()

            return is_active, is_enabled

        except subprocess.TimeoutExpired:
            print("ERROR: systemctl command timed out")
            return None, None
        except FileNotFoundError:
            print("ERROR: systemctl not found")
            return None, None
        except Exception as e:
            print(f"ERROR: Failed to check service status: {e}")
            return None, None

    def run_check(self):
        """Execute the STIG check"""
        try:
            # Check service status
            is_active, is_enabled = self.check_service_status(self.required_service)

            if is_active is None:
                self.results['status'] = 'Error'
                self.results['finding_details'].append({
                    'error': 'Failed to check service status',
                    'message': 'systemctl command failed or not available'
                })
                return 3

            finding = {
                'service': self.required_service,
                'check_details': {
                    'what_was_checked': 'Audit service (auditd) operational status',
                    'requirement': 'The audit service must be active and running to produce audit records'
                }
            }

            if is_active == 'active':
                # PASS - Service is active
                self.results['status'] = 'NotAFinding'

                finding.update({
                    'status': 'PASS',
                    'reason': 'Audit service is active and running',
                    'check_details': {
                        **finding['check_details'],
                        'actual_configuration': {
                            'service_name': self.required_service,
                            'active_state': is_active,
                            'enabled_state': is_enabled,
                            'status': 'running'
                        },
                        'expected_configuration': {
                            'service_name': self.required_service,
                            'active_state': 'active',
                            'enabled_state': 'enabled',
                            'status': 'running'
                        }
                    },
                    'evidence': {
                        'service_active': "Service is in 'active' state",
                        'service_enabled': f"Service is '{is_enabled}' (will start at boot)",
                        'verification_method': 'Verified using systemctl is-active and is-enabled commands',
                        'conclusion': 'System meets audit service operational requirements'
                    }
                })

                self.results['finding_details'].append(finding)
                return 0  # PASS

            else:
                # FAIL - Service not active
                self.results['status'] = 'Open'

                compliance_issues = []

                # Add issue for service not active
                compliance_issues.append({
                    'issue': 'Audit service is not active',
                    'evidence': f"Service active state: {is_active}",
                    'expected': 'Service active state must be: active',
                    'risk': 'Without an active audit service, the system cannot produce audit records for security events, making it impossible to investigate incidents or maintain compliance',
                    'remediation': 'Start the audit service: sudo systemctl start auditd.service'
                })

                # Add issue if service not enabled
                if is_enabled != 'enabled':
                    compliance_issues.append({
                        'issue': 'Audit service is not enabled at boot',
                        'evidence': f"Service enabled state: {is_enabled}",
                        'expected': 'Service enabled state must be: enabled',
                        'risk': 'Service will not start automatically after system reboot',
                        'remediation': 'Enable the audit service: sudo systemctl enable auditd.service'
                    })

                finding.update({
                    'status': 'FAIL',
                    'reason': 'Audit service is not active and running',
                    'check_details': {
                        **finding['check_details'],
                        'actual_configuration': {
                            'service_name': self.required_service,
                            'active_state': is_active,
                            'enabled_state': is_enabled,
                            'status': 'not running'
                        },
                        'expected_configuration': {
                            'service_name': self.required_service,
                            'active_state': 'active',
                            'enabled_state': 'enabled',
                            'status': 'running'
                        }
                    },
                    'compliance_issues': compliance_issues,
                    'recommendation': 'Start and enable the audit service immediately to begin producing required audit records'
                })

                self.results['finding_details'].append(finding)
                return 1  # FAIL

        except Exception as e:
            self.results['status'] = 'Error'
            self.results['finding_details'].append({
                'error': str(e),
                'message': 'Failed to check service status'
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
                if 'service' in detail:
                    print(f"\nService: {detail['service']}")
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
        description='V-248520: Check auditd service status',
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
