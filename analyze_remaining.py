#!/usr/bin/env python3
"""Analyze remaining unimplemented checks for 80% milestone"""

from pathlib import Path

def check_implementation_status(script_path):
    """Determine if script is implemented or not"""
    try:
        content = script_path.read_text(encoding='utf-8', errors='ignore')
        
        # Check for various unimplemented patterns
        if 'exit 3' in content:
            # Check if it's in the main implementation (not just comments)
            if 'echo "TODO:' in content or 'echo "ERROR: Not yet implemented"' in content:
                return 'unimplemented'
        
        # Check for implemented patterns
        if 'exit 0' in content or 'exit 1' in content or 'exit 2' in content:
            return 'implemented'
        
        return 'unknown'
    except:
        return 'error'

platforms = [
    ('Oracle Linux 9 v1r2', Path('checks/os/oracle_linux_9_v1r2')),
    ('RHEL 9 v2r5', Path('checks/os/rhel_9_v2r5')),
    ('Oracle Linux 8 v1r7', Path('checks/os/oracle_linux_8_v1r7')),
    ('Oracle Linux 8 v2r2', Path('checks/os/oracle_linux_8_v2r2')),
    ('RHEL 8 v2r4', Path('checks/os/rhel_8_v2r4')),
    ('Ubuntu 20.04 LTS', Path('checks/os/ubuntu_20.04_lts_v1r9')),
]

print("=" * 100)
print("DETAILED IMPLEMENTATION STATUS ANALYSIS")
print("=" * 100)
print(f"{'Platform':<30} {'Total':>8} {'Impl':>8} {'Unimpl':>8} {'Unknown':>8} {'%':>8}")
print("-" * 100)

total_unimpl = 0
for name, path in platforms:
    if not path.exists():
        continue
    
    scripts = list(path.glob('*.sh'))
    total = len(scripts)
    
    implemented = 0
    unimplemented = 0
    unknown = 0
    
    for script in scripts:
        status = check_implementation_status(script)
        if status == 'implemented':
            implemented += 1
        elif status == 'unimplemented':
            unimplemented += 1
        else:
            unknown += 1
    
    pct = (implemented / total * 100) if total > 0 else 0
    print(f"{name:<30} {total:>8} {implemented:>8} {unimplemented:>8} {unknown:>8} {pct:>7.1f}%")
    total_unimpl += unimplemented

print("=" * 100)
print(f"\nTotal unimplemented: {total_unimpl}")
print(f"\nCurrent: 4,317/6,164 (70.04%)")
print(f"Target 80%: 4,931 scripts")
print(f"Need: 614 implementations")
print("=" * 100)
