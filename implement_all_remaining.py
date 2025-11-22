#!/usr/bin/env python3
"""
Optimized STIG Implementation - Handles versioned directories
Processes all remaining 4,383 checks
"""

import json
import re
import sys
from pathlib import Path
from collections import defaultdict

stats = defaultdict(lambda: {'total': 0, 'implemented': 0})

def find_script_dir(base_dir, json_filename):
    """Find script directory for a given JSON file, handling versions"""
    # Remove _checks.json suffix
    stem = json_filename.stem.replace('_checks', '')

    # Try direct match first
    for check_type in ['application', 'os', 'network', 'database', 'container']:
        check_dir = base_dir / 'checks' / check_type
        if not check_dir.exists():
            continue

        # Try exact match
        exact = check_dir / stem
        if exact.exists():
            return exact

        # Try pattern match (handles versions)
        for d in check_dir.iterdir():
            if d.is_dir() and stem in d.name:
                return d

    return None

def gen_registry_check(reg_path, key_name, expected_val):
    """Generate PowerShell registry check"""
    return f'''
    $regPath = "Registry::{reg_path}"
    $keyName = "{key_name}"
    $expectedValue = "{expected_val}"

    try {{
        if (-not (Test-Path $regPath)) {{
            Write-Output "FAIL: Registry path not found"
            if ($OutputJson) {{ @{{vuln_id="$VULN_ID";status="FAIL";message="Registry path not found"}} | ConvertTo-Json | Out-File $OutputJson }}
            exit 1
        }}

        $actual = (Get-ItemProperty -Path $regPath -Name $keyName -ErrorAction Stop).$keyName

        if ($actual -eq $expectedValue) {{
            Write-Output "PASS: $keyName = $actual (compliant)"
            if ($OutputJson) {{ @{{vuln_id="$VULN_ID";status="PASS";message="Compliant"}} | ConvertTo-Json | Out-File $OutputJson }}
            exit 0
        }} else {{
            Write-Output "FAIL: $keyName = $actual (expected: $expectedValue)"
            if ($OutputJson) {{ @{{vuln_id="$VULN_ID";status="FAIL";message="Value mismatch"}} | ConvertTo-Json | Out-File $OutputJson }}
            exit 1
        }}
    }} catch {{
        Write-Output "FAIL: Registry key not found"
        if ($OutputJson) {{ @{{vuln_id="$VULN_ID";status="FAIL";message="Key not found"}} | ConvertTo-Json | Out-File $OutputJson }}
        exit 1
    }}
'''

def gen_file_perm_check(file_path, perms):
    """Generate bash file permission check"""
    return f'''
    TARGET="{file_path}"
    REQUIRED_PERMS="{perms}"

    if [[ ! -e "$TARGET" ]]; then
        echo "ERROR: File not found: $TARGET"
        [[ -n "$OUTPUT_JSON" ]] && output_json "ERROR" "File not found" "$TARGET"
        exit 3
    fi

    actual=$(stat -c "%a" "$TARGET" 2>/dev/null)
    if [[ -z "$actual" ]]; then
        echo "ERROR: Cannot read permissions"
        [[ -n "$OUTPUT_JSON" ]] && output_json "ERROR" "Permission read failed" ""
        exit 3
    fi

    if [[ $((8#$actual)) -le $((8#$REQUIRED_PERMS)) ]]; then
        echo "PASS: Permissions $actual (compliant)"
        [[ -n "$OUTPUT_JSON" ]] && output_json "PASS" "Permissions compliant" "$actual"
        exit 0
    else
        echo "FAIL: Permissions $actual (required: $REQUIRED_PERMS or less)"
        [[ -n "$OUTPUT_JSON" ]] && output_json "FAIL" "Permissions too open" "$actual"
        exit 1
    fi
'''

def gen_sysctl_check(param, value):
    """Generate sysctl check"""
    return f'''
    PARAM="{param}"
    EXPECTED="{value}"

    actual=$(sysctl -n "$PARAM" 2>/dev/null)
    if [[ -z "$actual" ]]; then
        echo "ERROR: Parameter not found"
        [[ -n "$OUTPUT_JSON" ]] && output_json "ERROR" "Parameter not found" "$PARAM"
        exit 3
    fi

    if [[ "$actual" == "$EXPECTED" ]]; then
        echo "PASS: $PARAM = $actual (compliant)"
        [[ -n "$OUTPUT_JSON" ]] && output_json "PASS" "Compliant" "$PARAM=$actual"
        exit 0
    else
        echo "FAIL: $PARAM = $actual (expected: $EXPECTED)"
        [[ -n "$OUTPUT_JSON" ]] && output_json "FAIL" "Mismatch" "Expected: $EXPECTED"
        exit 1
    fi
'''

def gen_package_check(pkg, should_exist=True):
    """Generate package check"""
    if should_exist:
        return f'''
    PKG="{pkg}"

    if rpm -q "$PKG" &>/dev/null || dpkg -l "$PKG" 2>/dev/null | grep -q "^ii"; then
        ver=$(rpm -q "$PKG" 2>/dev/null || dpkg -l "$PKG" 2>/dev/null | awk '{{print $3}}')
        echo "PASS: Package $PKG installed ($ver)"
        [[ -n "$OUTPUT_JSON" ]] && output_json "PASS" "Package installed" "$PKG"
        exit 0
    else
        echo "FAIL: Package $PKG not installed"
        [[ -n "$OUTPUT_JSON" ]] && output_json "FAIL" "Package missing" "$PKG"
        exit 1
    fi
'''
    else:
        return f'''
    PKG="{pkg}"

    if rpm -q "$PKG" &>/dev/null || dpkg -l "$PKG" 2>/dev/null | grep -q "^ii"; then
        echo "FAIL: Prohibited package $PKG is installed"
        [[ -n "$OUTPUT_JSON" ]] && output_json "FAIL" "Prohibited package present" "$PKG"
        exit 1
    else
        echo "PASS: Package $PKG not installed (compliant)"
        [[ -n "$OUTPUT_JSON" ]] && output_json "PASS" "Package not present" "$PKG"
        exit 0
    fi
'''

def replace_todo_bash(file_path, logic):
    """Replace TODO in bash script"""
    try:
        content = file_path.read_text()
        pattern = r'(    # TODO: Implement actual STIG check logic.*?)exit 3\n}'
        replacement = logic.lstrip() + '\n}'
        new_content = re.sub(pattern, replacement, content, flags=re.DOTALL)

        if new_content != content:
            file_path.write_text(new_content)
            return True
    except:
        pass
    return False

def replace_todo_ps1(file_path, logic):
    """Replace TODO in PowerShell script"""
    try:
        content = file_path.read_text()
        pattern = r'    # TODO: Implement actual STIG check logic.*?exit 3'
        new_content = re.sub(pattern, logic.lstrip(), content, flags=re.DOTALL)

        if new_content != content:
            file_path.write_text(new_content)
            return True
    except:
        pass
    return False

def process_check(check, script_dir, is_ps1=False):
    """Generate and apply implementation for a single check"""
    stig_id = check.get('STIG ID', '')
    content = check.get('Check Content', '').lower()

    logic = None

    # Determine check type and generate logic
    if is_ps1:
        # PowerShell/Windows checks
        reg_match = re.search(r'(hk[lcu][mu]\\[^"\n]+)', content, re.I)
        if reg_match:
            path = reg_match.group(1)
            key = re.search(r'value.*?:\s*([^\n]+)', content, re.I)
            val = re.search(r'(?:data|value).*?:\s*(\d+)', content, re.I)
            if key and val:
                logic = gen_registry_check(path, key.group(1).strip(), val.group(1))
    else:
        # Bash/Linux checks
        if 'permission' in content or 'chmod' in content:
            file_m = re.search(r'(/(?:etc|var|usr)/[^\s]+)', content)
            perm_m = re.search(r'(\d{3,4})', content)
            if file_m and perm_m:
                logic = gen_file_perm_check(file_m.group(1), perm_m.group(1))

        elif 'sysctl' in content:
            param_m = re.search(r'([a-z_]+\.[a-z_\.]+)', content)
            val_m = re.search(r'(?:=|value)\s*(\d+)', content, re.I)
            if param_m and val_m:
                logic = gen_sysctl_check(param_m.group(1), val_m.group(1))

        elif 'package' in content:
            pkg_m = re.search(r'(\w+)\s+package', content)
            if pkg_m:
                should_install = 'installed' in content
                logic = gen_package_check(pkg_m.group(1), should_install)

    if not logic:
        return False

    # Find script file
    safe_id = re.sub(r'[^a-zA-Z0-9_-]', '_', stig_id)
    ext = '.ps1' if is_ps1 else '.sh'
    script_file = script_dir / f"{safe_id}{ext}"

    if script_file.exists():
        if is_ps1:
            return replace_todo_ps1(script_file, logic)
        else:
            return replace_todo_bash(script_file, logic)

    return False

def main():
    base = Path('/home/user/STIGcheckScripts')

    # Process each JSON file
    for json_file in sorted(base.glob('*_checks.json')):
        if 'AllSTIGS' in json_file.name or 'docker' in json_file.name or 'kubernetes' in json_file.name:
            continue  # Skip these

        script_dir = find_script_dir(base, json_file)
        if not script_dir:
            continue

        try:
            checks = json.load(json_file.open())
        except:
            continue

        # Determine if PowerShell
        is_ps1 = any(x in json_file.name for x in ['windows', 'microsoft', 'office', 'word', 'excel'])

        platform = json_file.stem.replace('_checks', '')
        for check in checks:
            stats[platform]['total'] += 1
            if process_check(check, script_dir, is_ps1):
                stats[platform]['implemented'] += 1
                print(f"✓ {check.get('STIG ID', 'Unknown')}")

    # Summary
    print("\n" + "="*80)
    total_proc = sum(s['total'] for s in stats.values())
    total_impl = sum(s['implemented'] for s in stats.values())
    print(f"TOTAL: {total_impl}/{total_proc} implemented")
    for platform, s in stats.items():
        if s['total'] > 0:
            pct = s['implemented']/s['total']*100
            print(f"  {platform}: {s['implemented']}/{s['total']} ({pct:.0f}%)")

if __name__ == '__main__':
    main()
