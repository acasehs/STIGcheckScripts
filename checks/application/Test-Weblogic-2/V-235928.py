#!/usr/bin/env python3
"""
STIG Check: V-235928
Severity: medium
Rule Title: Oracle WebLogic must utilize cryptography to protect the confidentiality of remote access management sessions.
STIG ID: WBLC-01-000009
Requires Elevation: Yes (WebLogic Admin credentials required)

Description:
    Checks if Oracle WebLogic servers have SSL Listen Port enabled and
    non-SSL Listen Port disabled for all servers in the domain.

Execution:
    python3 V-235928.py --admin-url t3://localhost:7001 --username weblogic --password <password>
    python3 V-235928.py --admin-url t3://localhost:7001 --username weblogic --password <password> --force

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
            'vuln_id': 'V-235928',
            'severity': 'medium',
            'stig_id': 'WBLC-01-000009',
            'rule_title': 'Oracle WebLogic must utilize cryptography to protect the confidentiality of remote access management sessions.',
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

            # Get domain runtime
            domainRuntime()

            # Get all servers
            servers = cmo.getServers()

            findings = []
            has_findings = False

            for server in servers:
                server_name = server.getName()
                listen_port_enabled = server.isListenPortEnabled()
                ssl_enabled = server.isSSLMBean() and server.getSSL().isEnabled()
                ssl_port = server.getSSL().getListenPort() if ssl_enabled else None

                finding = {
                    'server': server_name,
                    'listen_port_enabled': listen_port_enabled,
                    'ssl_enabled': ssl_enabled,
                    'ssl_port': ssl_port
                }

                # Check compliance
                if listen_port_enabled:
                    finding['status'] = 'FAIL'
                    finding['reason'] = 'Listen Port Enabled is selected (should be disabled)'
                    has_findings = True
                elif not ssl_enabled:
                    finding['status'] = 'FAIL'
                    finding['reason'] = 'SSL Listen Port is not enabled'
                    has_findings = True
                else:
                    finding['status'] = 'PASS'
                    finding['reason'] = 'SSL enabled and non-SSL port disabled'

                findings.append(finding)

            self.results['finding_details'] = findings

            if has_findings:
                self.results['status'] = 'Open'
                return 1  # FAIL
            else:
                self.results['status'] = 'NotAFinding'
                return 0  # PASS

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
            if result.returncode == 0:
                # Try to parse JSON from output
                for line in result.stdout.split('\n'):
                    if line.strip().startswith('{'):
                        self.results = json.loads(line)
                        return self.results.get('exit_code', 0)
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
                if 'server' in detail:
                    print(f"\nServer: {detail['server']}")
                    print(f"  Listen Port Enabled: {detail.get('listen_port_enabled', 'N/A')}")
                    print(f"  SSL Enabled: {detail.get('ssl_enabled', 'N/A')}")
                    print(f"  SSL Port: {detail.get('ssl_port', 'N/A')}")
                    print(f"  Status: {detail.get('status', 'N/A')}")
                    print(f"  Reason: {detail.get('reason', 'N/A')}")
                elif 'error' in detail:
                    print(f"\nError: {detail['error']}")
                    if 'message' in detail:
                        print(f"Message: {detail['message']}")
            else:
                print(f"  {detail}")

        print(f"\n{'='*80}\n")


def main():
    parser = argparse.ArgumentParser(
        description='V-235928: Check WebLogic SSL configuration for remote access',
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
