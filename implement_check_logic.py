#!/usr/bin/env python3
"""
Intelligent STIG Check Logic Implementation Generator

Analyzes the "Check Content" field from STIG checks and generates
actual bash and Python implementation logic.
"""

import json
import re
import sys
from pathlib import Path

def parse_command_from_check_content(check_content):
    """
    Extract commands and logic from the Check Content field

    Returns:
        dict: {
            'commands': [list of commands to execute],
            'pass_pattern': regex pattern for PASS,
            'fail_pattern': regex pattern for FAIL,
            'logic_type': 'command_output' | 'process_check' | 'file_check' | 'api_check'
        }
    """
    check_lower = check_content.lower()

    # Extract commands between common patterns
    commands = []

    # Look for shell commands (common patterns)
    cmd_patterns = [
        r'(?:execute|run)(?:\sthe)?(?:\sfollowing)?(?:\scommand[s]?):\s*\n\n([^\n]+)',
        r'`([^`]+)`',
        r'ps -ef \| grep ([^\n]+)',
        r'docker ([^\n]+)',
        r'kubectl ([^\n]+)',
        r'systemctl ([^\n]+)',
        r'curl ([^\n]+)',
    ]

    for pattern in cmd_patterns:
        matches = re.findall(pattern, check_content, re.MULTILINE | re.IGNORECASE)
        commands.extend(matches)

    # Determine check type and patterns
    logic = {
        'commands': list(set(commands)),  # Deduplicate
        'pass_pattern': None,
        'fail_pattern': None,
        'logic_type': 'unknown',
        'raw_check_content': check_content
    }

    # Determine logic type
    if 'ps -ef | grep' in check_content or 'ps aux' in check_content:
        logic['logic_type'] = 'process_check'
    elif 'curl' in check_content or '/api/' in check_content:
        logic['logic_type'] = 'api_check'
    elif 'cat' in check_content or 'grep' in check_content or 'file' in check_lower:
        logic['logic_type'] = 'file_check'
    elif 'docker' in check_content or 'kubectl' in check_content:
        logic['logic_type'] = 'command_output'

    # Determine pass/fail patterns
    if 'is not a finding' in check_lower:
        # Extract what pattern means NOT a finding
        not_finding_pattern = re.search(r'if\s+(.+?),?\s+this is not a finding', check_lower, re.IGNORECASE)
        if not_finding_pattern:
            logic['pass_pattern'] = not_finding_pattern.group(1).strip()

    if 'this is a finding' in check_lower:
        # Extract what pattern means a finding
        finding_pattern = re.search(r'if\s+(.+?),?\s+(?:then\s+)?this is a finding', check_lower, re.IGNORECASE)
        if finding_pattern:
            logic['fail_pattern'] = finding_pattern.group(1).strip()

    return logic

def generate_bash_implementation(stig_id, check_info, logic):
    """Generate bash implementation based on parsed logic"""

    commands = logic.get('commands', [])
    logic_type = logic.get('logic_type', 'unknown')
    check_content = logic.get('raw_check_content', '')

    # Start with basic structure
    implementation = """
    # Validate prerequisites
    if ! command -v docker &> /dev/null && ! command -v kubectl &> /dev/null; then
        echo "ERROR: Required command not found"
        [[ -n "$OUTPUT_JSON" ]] && output_json "ERROR" "Required command not available" ""
        exit 3
    fi

"""

    # Generate logic based on check type
    if logic_type == 'process_check':
        # Process check logic
        if 'dockerd' in check_content:
            implementation += """    # Check docker daemon process arguments
    output=$(ps -ef | grep dockerd | grep -v grep)

    # Check for TCP binding (should NOT be present in UCP cluster)
    if echo "$output" | grep -q "\\-H TCP://"; then
        echo "FAIL: Docker daemon is configured with TCP binding"
        [[ -n "$OUTPUT_JSON" ]] && output_json "FAIL" "TCP binding detected on dockerd" "$output"
        exit 1
    elif echo "$output" | grep -q "\\-H UNIX://\\|/var/run/docker.sock"; then
        echo "PASS: Docker daemon using UNIX socket (compliant)"
        [[ -n "$OUTPUT_JSON" ]] && output_json "PASS" "Compliant - UNIX socket only" "$output"
        exit 0
    else
        echo "FAIL: Unable to determine docker daemon configuration"
        [[ -n "$OUTPUT_JSON" ]] && output_json "FAIL" "Inconclusive check" "$output"
        exit 1
    fi
"""

    elif logic_type == 'api_check':
        # API check logic (Docker UCP/DTR)
        if 'per_user_limit' in check_content.lower():
            implementation += """    # Check UCP per_user_limit setting
    # Requires UCP credentials from config file
    if [[ -z "$UCP_URL" ]] || [[ -z "$UCP_USERNAME" ]]; then
        echo "ERROR: UCP credentials not configured"
        [[ -n "$OUTPUT_JSON" ]] && output_json "ERROR" "UCP credentials required" ""
        exit 3
    fi

    # Authenticate to UCP
    AUTHTOKEN=$(curl -sk -d "{\\\"username\\\":\\\"$UCP_USERNAME\\\",\\\"password\\\":\\\"$UCP_PASSWORD\\\"}" \\
        https://$UCP_URL/auth/login 2>/dev/null | jq -r .auth_token)

    if [[ -z "$AUTHTOKEN" ]] || [[ "$AUTHTOKEN" == "null" ]]; then
        echo "ERROR: Failed to authenticate to UCP"
        [[ -n "$OUTPUT_JSON" ]] && output_json "ERROR" "UCP authentication failed" ""
        exit 3
    fi

    # Get UCP config
    output=$(curl -sk -H "Authorization: Bearer $AUTHTOKEN" \\
        https://$UCP_URL/api/ucp/config-toml 2>/dev/null | grep per_user_limit)

    if [[ -z "$output" ]]; then
        echo "FAIL: Unable to retrieve per_user_limit setting"
        [[ -n "$OUTPUT_JSON" ]] && output_json "FAIL" "Could not retrieve setting" ""
        exit 1
    fi

    # Extract value
    limit=$(echo "$output" | grep -oP 'per_user_limit\\s*=\\s*\\K\\d+')

    # Check against configured requirement (default to 10 if not specified)
    REQUIRED_LIMIT=${REQUIRED_PER_USER_LIMIT:-10}

    if [[ "$limit" -eq "$REQUIRED_LIMIT" ]] || [[ "$limit" -gt 0 && "$limit" -le "$REQUIRED_LIMIT" ]]; then
        echo "PASS: per_user_limit is set to $limit (compliant)"
        [[ -n "$OUTPUT_JSON" ]] && output_json "PASS" "Compliant - limit: $limit" "$output"
        exit 0
    else
        echo "FAIL: per_user_limit is $limit (required: $REQUIRED_LIMIT)"
        [[ -n "$OUTPUT_JSON" ]] && output_json "FAIL" "Non-compliant - limit: $limit" "$output"
        exit 1
    fi
"""

    elif logic_type == 'command_output':
        # Docker/kubectl command output check
        if 'fips' in check_content.lower():
            implementation += """    # Check FIPS mode
    # Check host FIPS mode first
    if [[ -f /proc/sys/crypto/fips_enabled ]]; then
        host_fips=$(cat /proc/sys/crypto/fips_enabled)
        if [[ "$host_fips" == "1" ]]; then
            echo "PASS: FIPS mode enabled on host"
            [[ -n "$OUTPUT_JSON" ]] && output_json "PASS" "FIPS enabled" "host fips: $host_fips"
            exit 0
        fi
    fi

    # Check DOCKER_FIPS environment variable
    if docker_fips=$(docker info 2>/dev/null | grep -i "FIPS mode"); then
        if echo "$docker_fips" | grep -qi "enabled\\|true\\|1"; then
            echo "PASS: FIPS mode enabled on Docker"
            [[ -n "$OUTPUT_JSON" ]] && output_json "PASS" "FIPS enabled" "$docker_fips"
            exit 0
        fi
    fi

    echo "FAIL: FIPS mode not enabled"
    [[ -n "$OUTPUT_JSON" ]] && output_json "FAIL" "FIPS mode not enabled" ""
    exit 1
"""
        else:
            # Generic command output check
            implementation += """    # Execute check command
    output=$(docker info 2>&1 || kubectl version 2>&1)

    if [[ $? -ne 0 ]]; then
        echo "ERROR: Failed to execute check command"
        [[ -n "$OUTPUT_JSON" ]] && output_json "ERROR" "Command execution failed" "$output"
        exit 3
    fi

    # Analyze output (customize based on specific check requirements)
    # TODO: Implement specific pass/fail logic based on output

    echo "TODO: Implement specific check logic for """ + stig_id + """"
    echo "Check Content indicates: """ + check_content[:200].replace('"', '\\"').replace('\n', '\\n') + """..."
    [[ -n "$OUTPUT_JSON" ]] && output_json "ERROR" "Not implemented" "Stub implementation"
    exit 3
"""

    else:
        # Unknown/generic check
        implementation += """    # Generic check implementation
    # TODO: Implement specific logic based on check content

    echo "TODO: Implement check logic for """ + stig_id + """"
    echo "Check Type: """ + logic_type + """"
    echo "Check Content: """ + check_content[:200].replace('"', '\\"').replace('\n', '\\n') + """..."

    [[ -n "$OUTPUT_JSON" ]] && output_json "ERROR" "Not implemented" "Requires domain expertise"
    exit 3
"""

    return implementation

def generate_python_implementation(stig_id, check_info, logic):
    """Generate Python implementation based on parsed logic"""

    logic_type = logic.get('logic_type', 'unknown')
    check_content = logic.get('raw_check_content', '')

    implementation = '''
    """
    Perform the actual STIG check
    """

    # Execute check based on type
'''

    if logic_type == 'process_check':
        implementation += '''
    # Check docker daemon process
    stdout, error = run_command("ps -ef | grep dockerd | grep -v grep")

    if error:
        return (3, f"Error checking docker process: {error}", "")

    # Check for TCP binding
    if "-H TCP://" in stdout:
        return (1, "FAIL: Docker daemon configured with TCP binding", stdout)
    elif "-H UNIX://" in stdout or "/var/run/docker.sock" in stdout:
        return (0, "PASS: Docker daemon using UNIX socket (compliant)", stdout)
    else:
        return (1, "FAIL: Unable to determine docker daemon configuration", stdout)
'''

    elif logic_type == 'api_check':
        implementation += '''
    # API-based check (requires requests library)
    try:
        import requests
        import json

        # Get UCP credentials from config
        ucp_url = config.get('docker', {}).get('ucp_url')
        ucp_user = config.get('docker', {}).get('ucp_username')
        ucp_pass = config.get('docker', {}).get('ucp_password')

        if not all([ucp_url, ucp_user, ucp_pass]):
            return (3, "ERROR: UCP credentials not configured", "")

        # Authenticate
        auth_data = {'username': ucp_user, 'password': ucp_pass}
        auth_response = requests.post(
            f"https://{ucp_url}/auth/login",
            json=auth_data,
            verify=False
        )

        if auth_response.status_code != 200:
            return (3, "ERROR: UCP authentication failed", "")

        auth_token = auth_response.json().get('auth_token')

        # Get config
        headers = {'Authorization': f'Bearer {auth_token}'}
        config_response = requests.get(
            f"https://{ucp_url}/api/ucp/config-toml",
            headers=headers,
            verify=False
        )

        config_text = config_response.text

        # Parse for per_user_limit
        match = re.search(r'per_user_limit\\s*=\\s*(\\d+)', config_text)
        if match:
            limit = int(match.group(1))
            required_limit = config.get('docker', {}).get('required_per_user_limit', 10)

            if limit <= required_limit and limit > 0:
                return (0, f"PASS: per_user_limit is {limit} (compliant)", config_text)
            else:
                return (1, f"FAIL: per_user_limit is {limit} (required: {required_limit})", config_text)
        else:
            return (1, "FAIL: per_user_limit not found in config", config_text)

    except ImportError:
        return (3, "ERROR: requests library required for API checks", "pip3 install requests")
    except Exception as e:
        return (3, f"ERROR: {str(e)}", "")
'''

    elif 'fips' in check_content.lower():
        implementation += '''
    # Check FIPS mode
    # Check host FIPS
    stdout, error = run_command("cat /proc/sys/crypto/fips_enabled 2>/dev/null || echo 0")

    if stdout and stdout.strip() == "1":
        return (0, "PASS: FIPS mode enabled on host", stdout)

    # Check Docker FIPS
    stdout, error = run_command("docker info 2>/dev/null | grep -i 'FIPS mode'")

    if stdout and any(x in stdout.lower() for x in ['enabled', 'true', '1']):
        return (0, "PASS: FIPS mode enabled on Docker", stdout)

    return (1, "FAIL: FIPS mode not enabled", "")
'''

    else:
        implementation += f'''
    # TODO: Implement specific check logic
    # STIG ID: {stig_id}
    # Check Type: {logic_type}
    # Check Content: {check_content[:200]}...

    return (3, "Not implemented - Requires domain expertise", "Stub implementation")
'''

    return implementation

def update_script_with_implementation(script_file, implementation, is_bash=True):
    """Update a script file with the actual implementation"""

    try:
        with open(script_file, 'r') as f:
            content = f.read()

        if is_bash:
            # Replace the TODO section in bash script
            # Find the main() function and replace the TODO block
            pattern = r'(main\(\) \{\{.*?# TODO: Implement actual STIG check logic.*?exit 3\n\}\})'

            def replacer(match):
                # Keep the function start, replace the TODO section
                return match.group(0).replace(
                    re.search(r'# TODO: Implement actual STIG check logic.*?exit 3', match.group(0), re.DOTALL).group(0),
                    implementation.strip()
                )

            new_content = re.sub(pattern, replacer, content, flags=re.DOTALL)
        else:
            # Replace the TODO section in Python script
            pattern = r'(def perform_check\(.*?\):.*?""".*?""")(.*?)(return \(3, "Not implemented.*?\))'

            def replacer(match):
                return match.group(1) + implementation + '\n    ' + match.group(3)

            new_content = re.sub(pattern, replacer, content, flags=re.DOTALL)

        # Write back
        with open(script_file, 'w') as f:
            f.write(new_content)

        return True
    except Exception as e:
        print(f"ERROR updating {script_file}: {e}")
        return False

def implement_checks_for_stig(checks_json_file, scripts_dir):
    """Implement check logic for all checks in a STIG"""

    # Load checks
    with open(checks_json_file, 'r') as f:
        checks = json.load(f)

    print(f"Processing {len(checks)} checks from {checks_json_file.name}")

    implemented_count = 0
    skipped_count = 0

    for check in checks:
        stig_id = check.get('STIG ID', 'Unknown')
        check_content = check.get('Check Content', '')

        if not check_content:
            print(f"  Skipping {stig_id} - No check content")
            skipped_count += 1
            continue

        # Parse check content
        logic = parse_command_from_check_content(check_content)

        # Generate implementations
        bash_impl = generate_bash_implementation(stig_id, check, logic)
        python_impl = generate_python_implementation(stig_id, check, logic)

        # Find script files
        # Sanitize STIG ID for filename
        safe_stig_id = re.sub(r'[^a-zA-Z0-9_-]', '_', stig_id)
        bash_file = scripts_dir / f"{safe_stig_id}.sh"
        python_file = scripts_dir / f"{safe_stig_id}.py"

        # Update scripts
        bash_updated = False
        python_updated = False

        if bash_file.exists():
            bash_updated = update_script_with_implementation(bash_file, bash_impl, is_bash=True)

        if python_file.exists():
            python_updated = update_script_with_implementation(python_file, python_impl, is_bash=False)

        if bash_updated or python_updated:
            print(f"  ✓ Implemented {stig_id}")
            implemented_count += 1
        else:
            print(f"  ✗ Failed to implement {stig_id}")
            skipped_count += 1

    print(f"\nResults: {implemented_count} implemented, {skipped_count} skipped")
    return implemented_count

def main():
    """Main execution"""
    base_dir = Path(__file__).parent

    # Docker Enterprise
    docker_checks = base_dir / "docker_enterprise_2.x_linux_unix_v2r2_checks.json"
    docker_scripts = base_dir / "checks/container/docker_enterprise_2.x_linux_unix_v2r2"

    if docker_checks.exists() and docker_scripts.exists():
        print("\n" + "="*80)
        print("Implementing Docker Enterprise 2.x Checks")
        print("="*80)
        implement_checks_for_stig(docker_checks, docker_scripts)

    # Kubernetes
    k8s_checks = base_dir / "kubernetes_v1r11_checks.json"
    k8s_scripts = base_dir / "checks/container/kubernetes_v1r11"

    if k8s_checks.exists() and k8s_scripts.exists():
        print("\n" + "="*80)
        print("Implementing Kubernetes Checks")
        print("="*80)
        implement_checks_for_stig(k8s_checks, k8s_scripts)

    print("\n" + "="*80)
    print("Implementation Complete")
    print("="*80)

if __name__ == '__main__':
    main()
