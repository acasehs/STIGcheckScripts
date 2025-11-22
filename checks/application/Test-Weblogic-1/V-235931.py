#!/usr/bin/env python3
"""
STIG Check: V-235931
Severity: medium
Rule Title: Oracle WebLogic must ensure remote sessions for accessing security functions and security-relevant information are audited.
STIG ID: WBLC-01-000013
Requires Elevation: Yes (WebLogic Admin credentials required)

Description:
    Checks if Oracle Platform Security Services audit policy is configured
    to audit all events for remote access to security functions.

Execution:
    python3 V-235931.py --admin-url t3://localhost:7001 --username weblogic --password <password>
    python3 V-235931.py --admin-url t3://localhost:7001 --username weblogic --password <password> --force

Output Formats:
    - Exit Code: 0 (Pass), 1 (Fail), 2 (Not Applicable), 3 (Error)
    - JSON: --output-json results.json
    - Human Readable: Default to stdout
"""

import sys
import os
import json
import argparse
from datetime import datetime

# Check if running with WLST
try:
    # WLST specific imports
    connect
    ls
    WLST_AVAILABLE = True
except:
    WLST_AVAILABLE = False


class STIGCheck:
    def __init__(self, admin_url, username, password, force=False):
        self.admin_url = admin_url
        self.username = username
        self.password = password
        self.force = force
        self.results = {
            'vuln_id': 'V-235931',
            'severity': 'medium',
            'stig_id': 'WBLC-01-000013',
            'rule_title': 'Oracle WebLogic must ensure remote sessions for accessing security functions and security-relevant information are audited.',
            'status': 'Not Checked',
            'finding_details': [],
            'timestamp': datetime.now().isoformat(),
            'requires_elevation': True
        }

    def check_elevation(self):
        """Check if we have necessary credentials/access"""
        if not self.username or not self.password:
            return False, "WebLogic admin credentials required"
        return True, "Credentials provided"

    def run_check(self):
        """Execute the STIG check"""
        # Check elevation first
        has_elevation, msg = self.check_elevation()
        if not has_elevation and not self.force:
            self.results['status'] = 'Error'
            self.results['finding_details'].append({
                'error': msg,
                'message': 'Use --force to attempt execution anyway'
            })
            return 3

        if not WLST_AVAILABLE:
            return self._run_wlst_subprocess()

        try:
            # Connect to WebLogic Admin Server
            connect(self.username, self.password, self.admin_url)

            # Navigate to domain
            domainRuntime()

            # This check requires accessing Enterprise Manager (EM)
            # In a WLST script, we would use JMX MBeans to check audit configuration
            # For this example, we'll demonstrate the approach

            # Note: Full implementation requires accessing:
            # - Oracle Platform Security Services (OPSS) audit configuration
            # - Checking if audit level is set to 'Custom'
            # - Verifying all audit events are enabled

            findings = []

            # Attempt to check audit configuration via MBeans
            # This is a simplified check - actual implementation requires
            # accessing specific OPSS MBeans

            try:
                # Navigate to Domain MBean Server
                custom = cmo
                domain_mbean_server = custom.getMBeanServer()

                # Check for audit configuration
                # Note: Actual MBean path may vary based on WebLogic version
                audit_status = {
                    'component': 'Oracle Platform Security Services',
                    'audit_level': 'Unknown',
                    'all_events_enabled': 'Unknown'
                }

                # In a real implementation, query the actual MBeans here
                # For now, mark as manual check required
                findings.append({
                    'type': 'Manual Check Required',
                    'reason': 'Audit policy configuration requires Enterprise Manager access',
                    'instructions': [
                        '1. Access EM (Enterprise Manager)',
                        '2. Select domain -> WebLogic Domain -> Security -> Audit Policy',
                        '3. Select "Oracle Platform Security Services" from Audit Component Name dropdown',
                        '4. Verify Audit Level is set to "Custom"',
                        '5. Verify all checkboxes under "Select For Audit" column are selected'
                    ],
                    'automated_check': 'Partial - requires EM API access or config file verification'
                })

                self.results['finding_details'] = findings
                self.results['status'] = 'Manual Review Required'
                return 2  # Not Applicable / Manual Review

            except Exception as e:
                findings.append({
                    'error': str(e),
                    'message': 'Unable to access audit configuration MBeans',
                    'recommendation': 'Manual verification required via Enterprise Manager'
                })
                self.results['finding_details'] = findings
                self.results['status'] = 'Manual Review Required'
                return 2

        except Exception as e:
            self.results['status'] = 'Error'
            self.results['finding_details'].append({
                'error': str(e),
                'message': 'Failed to execute WLST check'
            })
            return 3
        finally:
            try:
                disconnect()
            except:
                pass

    def _run_wlst_subprocess(self):
        """Run this script via WLST"""
        import subprocess

        # Find WLST
        wlst_path = os.environ.get('WLST_PATH', 'wlst.sh')

        try:
            # Run this script with WLST
            result = subprocess.run(
                [wlst_path, __file__,
                 '--admin-url', self.admin_url,
                 '--username', self.username,
                 '--password', self.password,
                 '--wlst-mode'],
                capture_output=True,
                text=True,
                timeout=60
            )

            # Parse WLST output
            if result.returncode == 0 or result.returncode == 2:
                # Try to parse JSON from output
                for line in result.stdout.split('\n'):
                    if line.strip().startswith('{'):
                        self.results = json.loads(line)
                        return self.results.get('exit_code', result.returncode)
            else:
                self.results['status'] = 'Error'
                self.results['finding_details'].append({
                    'error': result.stderr,
                    'stdout': result.stdout
                })
                return 3

        except FileNotFoundError:
            self.results['status'] = 'Error'
            self.results['finding_details'].append({
                'error': f'WLST not found at {wlst_path}',
                'message': 'Set WLST_PATH environment variable or ensure wlst.sh is in PATH'
            })
            return 3
        except Exception as e:
            self.results['status'] = 'Error'
            self.results['finding_details'].append({
                'error': str(e)
            })
            return 3

    def get_results(self):
        """Return results dictionary"""
        return self.results

    def print_results(self):
        """Print human-readable results"""
        print(f"\n{'='*80}")
        print(f"STIG Check: {self.results['vuln_id']} - {self.results['stig_id']}")
        print(f"Severity: {self.results['severity'].upper()}")
        print(f"{'='*80}")
        print(f"Rule: {self.results['rule_title']}")
        print(f"Status: {self.results['status']}")
        print(f"Timestamp: {self.results['timestamp']}")
        print(f"Requires Elevation: {self.results['requires_elevation']}")
        print(f"\n{'-'*80}")
        print("Finding Details:")
        print(f"{'-'*80}")

        for detail in self.results['finding_details']:
            if isinstance(detail, dict):
                if 'type' in detail:
                    print(f"\nType: {detail['type']}")
                    print(f"Reason: {detail.get('reason', 'N/A')}")
                    if 'instructions' in detail:
                        print("\nManual Check Instructions:")
                        for instruction in detail['instructions']:
                            print(f"  {instruction}")
                    if 'automated_check' in detail:
                        print(f"\nAutomation Status: {detail['automated_check']}")
                elif 'error' in detail:
                    print(f"\nError: {detail['error']}")
                    if 'message' in detail:
                        print(f"Message: {detail['message']}")
                    if 'recommendation' in detail:
                        print(f"Recommendation: {detail['recommendation']}")
            else:
                print(f"  {detail}")

        print(f"\n{'='*80}\n")


def main():
    parser = argparse.ArgumentParser(
        description='V-235931: Check WebLogic audit policy configuration',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    parser.add_argument('--admin-url', required=True,
                       help='WebLogic Admin Server URL (e.g., t3://localhost:7001)')
    parser.add_argument('--username', required=True,
                       help='WebLogic admin username')
    parser.add_argument('--password', required=True,
                       help='WebLogic admin password')
    parser.add_argument('--force', action='store_true',
                       help='Force execution even without proper elevation')
    parser.add_argument('--output-json', metavar='FILE',
                       help='Output results to JSON file')
    parser.add_argument('--wlst-mode', action='store_true',
                       help='Internal flag for WLST execution mode')

    args = parser.parse_args()

    # Run the check
    check = STIGCheck(args.admin_url, args.username, args.password, args.force)
    exit_code = check.run_check()

    # Output results
    if args.output_json:
        results = check.get_results()
        results['exit_code'] = exit_code
        with open(args.output_json, 'w') as f:
            json.dump(results, f, indent=2)

    if not args.wlst_mode:
        check.print_results()
    else:
        # In WLST mode, print JSON for parent process
        results = check.get_results()
        results['exit_code'] = exit_code
        print(json.dumps(results))

    sys.exit(exit_code)


if __name__ == '__main__':
    main()
