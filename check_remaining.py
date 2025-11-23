#!/usr/bin/env python3
"""Check remaining unimplemented checks across platforms"""

from pathlib import Path

def count_unimplemented(dir_path, pattern="TODO: Implement actual STIG check logic"):
    """Count files with TODO pattern"""
    if not dir_path.exists():
        return 0, 0
    
    scripts = list(dir_path.glob('*.sh')) + list(dir_path.glob('*.ps1'))
    total = len(scripts)
    
    unimplemented = 0
    for script in scripts:
        try:
            content = script.read_text(encoding='utf-8', errors='ignore')
            if pattern in content and 'exit 3' in content:
                unimplemented += 1
        except:
            pass
    
    return total, unimplemented

platforms = [
    ('Oracle Linux 9', Path('checks/os/oracle_linux_9_v1r2')),
    ('RHEL 9', Path('checks/os/rhel_9_v2r5')),
    ('Oracle Linux 8 v2r5', Path('checks/os/oracle_linux_8_v2r5')),
    ('Oracle Linux 8 v1r7', Path('checks/os/oracle_linux_8_v1r7')),
    ('RHEL 8', Path('checks/os/rhel_8_v2r4')),
]

print("=" * 90)
print("REMAINING UNIMPLEMENTED CHECKS BY PLATFORM")
print("=" * 90)
print(f"{'Platform':<30} {'Total':>10} {'Unimpl':>10} {'Done':>10} {'%':>8}")
print("-" * 90)

total_unimpl = 0
for name, path in platforms:
    total, unimpl = count_unimplemented(path)
    implemented = total - unimpl
    pct = (implemented / total * 100) if total > 0 else 0
    print(f"{name:<30} {total:>10} {unimpl:>10} {implemented:>10} {pct:>7.1f}%")
    total_unimpl += unimpl

print("=" * 90)
print(f"\nTotal unimplemented across these platforms: {total_unimpl:,}")
print(f"\nCurrent project: 3,706/6,164 (60.1%)")
print(f"Target 70%: 4,315 scripts")
print(f"Need for 70%: 609 implementations")
print("=" * 90)
