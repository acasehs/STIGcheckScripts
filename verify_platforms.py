#!/usr/bin/env python3
"""Verify actual implementation status by checking exit codes"""

from pathlib import Path
import re

def check_real_implementation(script_path):
    """Check if script has real implementation or just placeholder"""
    try:
        content = script_path.read_text(encoding='utf-8', errors='ignore')
        
        # Check for placeholder/not implemented patterns
        if 'exit 3  # Not implemented' in content:
            return False
        if 'exit 3  # ERROR - Not yet implemented' in content:
            return False
        if 'echo "ERROR: Not yet implemented"' in content:
            return False
        if 'Write-Host "TODO:' in content and 'exit 3' in content:
            return False
        
        # Has actual implementation if it has exit 0, 1, or 2 (not just exit 3)
        has_exit_012 = bool(re.search(r'exit [012]', content))
        return has_exit_012
        
    except:
        return False

# Check specific interesting platforms
platforms_to_check = [
    ('checks/os/ubuntu_22.04_lts_v2r5', 'Ubuntu 22.04'),
    ('checks/os/ubuntu_20.04_lts_v1r9', 'Ubuntu 20.04'),
    ('checks/database/oracle_database_19c_v1r2', 'Oracle Database 19c'),
    ('checks/application/apache_2.4_unix_server_v2r6', 'Apache 2.4 Unix Server'),
    ('checks/application/apache_2.4_windows_server_v2r3', 'Apache 2.4 Windows Server'),
    ('checks/application/oracle_weblogic_server_12c_v2r2', 'Oracle WebLogic 12c'),
    ('checks/application/oracle_http_server_12.1.3_v2r3', 'Oracle HTTP Server'),
    ('checks/network/fortinet_fortigate_ndm', 'FortiGate'),
    ('checks/network/cisco_asa_ndm', 'Cisco ASA'),
]

print("=" * 90)
print("PLATFORM IMPLEMENTATION VERIFICATION")
print("=" * 90)
print(f"{'Platform':<40} {'Total':>8} {'Impl':>8} {'Not':>8} {'%':>8}")
print("-" * 90)

for dir_str, name in platforms_to_check:
    dir_path = Path(dir_str)
    if not dir_path.exists():
        print(f"{name:<40} {'N/A':>8} {'N/A':>8} {'N/A':>8} {'N/A':>8}")
        continue
    
    scripts = list(dir_path.glob('*.sh')) + list(dir_path.glob('*.ps1'))
    total = len(scripts)
    implemented = sum(1 for s in scripts if check_real_implementation(s))
    not_impl = total - implemented
    pct = (implemented / total * 100) if total > 0 else 0
    
    print(f"{name:<40} {total:>8} {implemented:>8} {not_impl:>8} {pct:>7.1f}%")

print("=" * 90)
