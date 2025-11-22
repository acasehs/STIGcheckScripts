#!/usr/bin/env python3
"""
STIG Check: V-235928
Severity: medium
Rule Title: Oracle WebLogic must utilize cryptography to protect the confidentiality of remote access management sessions.
STIG ID: WBLC-01-000009
Requires Elevation: Yes (Read access to WebLogic domain directory)
Third-Party Tools: None (uses Python stdlib - xml.etree.ElementTree)

Description:
    Checks if Oracle WebLogic servers have SSL Listen Port enabled and
    non-SSL Listen Port disabled for all servers in the domain by parsing
    config.xml files directly using Python's built-in XML parser.

Execution:
    python3 V-235928.py --domain-home /u01/oracle/user_projects/domains/base_domain
    python3 V-235928.py --domain-home /u01/oracle/user_projects/domains/base_domain --output-json results.json
    python3 V-235928.py --domain-home /u01/oracle/user_projects/domains/base_domain --force

Output Formats:
    - Exit Code: 0 (Pass), 1 (Fail), 2 (Not Applicable), 3 (Error)
    - JSON: --output-json results.json
    - Human Readable: Default to stdout
"""

import sys
import os
import json
import argparse
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path


class STIGCheck:
    def __init__(self, domain_home, config_file=None, force=False):
        self.domain_home = Path(domain_home)
        self.config_file = Path(config_file) if config_file else None
        self.force = force

        # Environment-specific defaults (can be overridden by config file)
        self.approved_ports = [7002, 9002]
        self.approved_protocols = ['t3s', 'https', 'iiops']

        # Load configuration if provided
        if self.config_file:
            self.load_config()

        self.results = {
            'vuln_id': 'V-235928',
            'severity': 'medium',
            'stig_id': 'WBLC-01-000009',
            'rule_title': 'Oracle WebLogic must utilize cryptography to protect the confidentiality of remote access management sessions.',
            'status': 'Not Checked',
            'finding_details': [],
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'requires_elevation': True,
            'third_party_tools': 'None (uses Python stdlib)',
            'check_method': 'Python - Direct config.xml parsing',
            'config_file': str(self.config_file) if self.config_file else 'None (using defaults)'
        }

    def load_config(self):
        """Load environment-specific values from config file"""
        try:
            with open(self.config_file, 'r') as f:
                config = json.load(f)

            weblogic_config = config.get('weblogic', {})

            # Load approved values from config
            if 'approved_ports' in weblogic_config:
                self.approved_ports = weblogic_config['approved_ports']

            if 'approved_protocols' in weblogic_config:
                self.approved_protocols = weblogic_config['approved_protocols']

            print(f"INFO: Loaded configuration from {self.config_file}")
            print(f"  - Approved ports: {self.approved_ports}")
            print(f"  - Approved protocols: {self.approved_protocols}")

        except FileNotFoundError:
            print(f"ERROR: Configuration file not found: {self.config_file}")
            sys.exit(3)
        except json.JSONDecodeError as e:
            print(f"ERROR: Invalid JSON in config file: {e}")
            sys.exit(3)
        except Exception as e:
            print(f"ERROR: Failed to load config file: {e}")
            sys.exit(3)

    def check_elevation(self):
        """Check if we have necessary read access"""
        config_file = self.domain_home / 'config' / 'config.xml'

        if not self.domain_home.exists():
            return False, f"Domain home directory does not exist: {self.domain_home}"

        if not config_file.exists():
            return False, f"config.xml not found at: {config_file}"

        if not os.access(config_file, os.R_OK):
            return False, f"Cannot read {config_file} - insufficient permissions"

        return True, "Access verified"

    def parse_weblogic_config(self):
        """Parse WebLogic config.xml and extract server configurations"""
        config_file = self.domain_home / 'config' / 'config.xml'

        try:
            tree = ET.parse(config_file)
            root = tree.getroot()

            # WebLogic config.xml uses a namespace
            # Try to detect namespace
            namespace = ''
            if root.tag.startswith('{'):
                namespace = root.tag[root.tag.find('{')+1:root.tag.find('}')]
                ns = {'wls': namespace}
            else:
                ns = {}

            # Find all server elements
            if ns:
                servers = root.findall('.//wls:server', ns)
            else:
                servers = root.findall('.//server')

            return servers, ns

        except ET.ParseError as e:
            raise Exception(f"Failed to parse config.xml: {e}")
        except Exception as e:
            raise Exception(f"Error reading config.xml: {e}")

    def get_element_text(self, element, tag, ns, default=''):
        """Safely get text from an XML element"""
        if ns:
            child = element.find(f'wls:{tag}', ns)
        else:
            child = element.find(tag)

        if child is not None and child.text:
            return child.text.strip()
        return default

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

        try:
            servers, ns = self.parse_weblogic_config()

            if not servers:
                self.results['status'] = 'Not Applicable'
                self.results['finding_details'].append({
                    'info': 'No servers found in config.xml'
                })
                return 2

            findings = []
            has_findings = False

            for server in servers:
                server_name = self.get_element_text(server, 'name', ns, 'Unknown')

                # Check listen-port-enabled (default is true if not specified)
                listen_enabled = self.get_element_text(server, 'listen-port-enabled', ns, 'true')

                # Check SSL configuration
                if ns:
                    ssl_elem = server.find('wls:ssl', ns)
                else:
                    ssl_elem = server.find('ssl')

                if ssl_elem is not None:
                    ssl_enabled = self.get_element_text(ssl_elem, 'enabled', ns, 'false')
                    ssl_port = self.get_element_text(ssl_elem, 'listen-port', ns, 'N/A')
                else:
                    ssl_enabled = 'false'
                    ssl_port = 'N/A'

                finding = {
                    'server': server_name,
                    'listen_port_enabled': listen_enabled.lower() == 'true',
                    'ssl_enabled': ssl_enabled.lower() == 'true',
                    'ssl_port': ssl_port
                }

                # Check compliance with detailed evidence
                finding['check_details'] = {
                    'what_was_checked': 'SSL/TLS configuration for server',
                    'requirement': 'SSL must be enabled AND non-SSL listen port must be disabled',
                    'actual_configuration': {
                        'listen_port_enabled': listen_enabled.lower(),
                        'ssl_enabled': ssl_enabled.lower(),
                        'ssl_port': ssl_port
                    },
                    'expected_configuration': {
                        'listen_port_enabled': 'false',
                        'ssl_enabled': 'true',
                        'ssl_port': 'Valid port number (e.g., 7002, 9002)'
                    }
                }

                # Detailed compliance check with audit evidence
                compliance_issues = []

                if listen_enabled.lower() == 'true':
                    compliance_issues.append({
                        'issue': 'Non-SSL listen port is enabled',
                        'evidence': f'listen-port-enabled = {listen_enabled}',
                        'expected': 'listen-port-enabled = false',
                        'risk': 'Allows unencrypted administrative connections',
                        'remediation': 'Disable non-SSL listen port in WebLogic config'
                    })
                    has_findings = True

                if ssl_enabled.lower() != 'true':
                    compliance_issues.append({
                        'issue': 'SSL is not enabled for this server',
                        'evidence': f'SSL enabled = {ssl_enabled}',
                        'expected': 'SSL enabled = true',
                        'risk': 'Server cannot accept encrypted connections',
                        'remediation': 'Enable SSL and configure keystore/truststore'
                    })
                    has_findings = True

                if not ssl_port or ssl_port == 'N/A':
                    if ssl_enabled.lower() == 'true':
                        compliance_issues.append({
                            'issue': 'SSL is enabled but no SSL port configured',
                            'evidence': f'SSL port = {ssl_port}',
                            'expected': 'SSL port = valid port number',
                            'risk': 'SSL configuration incomplete',
                            'remediation': 'Configure SSL listen port'
                        })
                        has_findings = True

                # Set status based on findings
                if compliance_issues:
                    finding['status'] = 'FAIL'
                    finding['reason'] = f"Found {len(compliance_issues)} compliance issue(s)"
                    finding['compliance_issues'] = compliance_issues
                    finding['recommendation'] = 'Configure SSL properly and disable non-SSL listen port'
                else:
                    finding['status'] = 'PASS'
                    finding['reason'] = 'SSL enabled and properly configured, non-SSL port disabled'
                    finding['evidence'] = {
                        'ssl_enabled': f'SSL is enabled (ssl.enabled = {ssl_enabled})',
                        'ssl_port': f'SSL port configured: {ssl_port}',
                        'non_ssl_disabled': f'Non-SSL port disabled (listen-port-enabled = {listen_enabled})',
                        'conclusion': 'Server meets cryptographic protection requirements'
                    }

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
                'message': 'Failed to parse WebLogic configuration'
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
        print(f"Third-Party Tools: {self.results['third_party_tools']}")
        print(f"Check Method: {self.results['check_method']}")
        print(f"\n{'-'*80}")
        print("Finding Details:")
        print(f"{'-'*80}")

        for detail in self.results['finding_details']:
            if isinstance(detail, dict):
                if 'server' in detail:
                    print(f"\nServer: {detail['server']}")
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
                elif 'info' in detail:
                    print(f"\nInfo: {detail['info']}")
            else:
                print(f"  {detail}")

        print(f"\n{'='*80}\n")


def main():
    parser = argparse.ArgumentParser(
        description='V-235928: Check WebLogic SSL configuration',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    parser.add_argument('--domain-home', required=True,
                       help='WebLogic domain home directory (e.g., /u01/oracle/user_projects/domains/base_domain)')
    parser.add_argument('--config', metavar='FILE',
                       help='STIG configuration file (JSON) with environment-specific values')
    parser.add_argument('--force', action='store_true',
                       help='Force execution even without proper elevation')
    parser.add_argument('--output-json', metavar='FILE',
                       help='Output results to JSON file')

    args = parser.parse_args()

    # Run the check
    check = STIGCheck(args.domain_home, args.config, args.force)
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
