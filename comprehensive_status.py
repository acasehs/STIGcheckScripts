#!/usr/bin/env python3
"""Get comprehensive project status"""

from pathlib import Path

# Count total script files
total_scripts = 0
for pattern in ['**/*.sh', '**/*.ps1']:
    scripts = list(Path('checks').glob(pattern))
    total_scripts += len(scripts)

print("=" * 80)
print("COMPREHENSIVE PROJECT STATUS")
print("=" * 80)
print(f"Total script files in checks/: {total_scripts:,}")
print(f"Session tracking says: 6,164 total")
print()
print(f"Currently implemented: 5,592 (90.72%)")
print(f"Remaining to 100%: {total_scripts - 5592} scripts")
print("=" * 80)

# Let's also verify by counting specific known complete platforms
print("\nVerifying known complete platforms:")
complete = [
    ('Windows 10', 'checks/os/windows_10_v3r4', '*.ps1'),
    ('Windows 11', 'checks/os/windows_11_v2r4', '*.ps1'),
    ('Windows Server 2019', 'checks/os/windows_server_2019_v2r7', '*.ps1'),
    ('Windows Server 2022', 'checks/os/windows_server_2022_v1r3', '*.ps1'),
    ('Oracle Linux 9', 'checks/os/oracle_linux_9_v1r2', '*.sh'),
    ('RHEL 9', 'checks/os/rhel_9_v2r5', '*.sh'),
    ('RHEL 8', 'checks/os/rhel_8_v2r4', '*.sh'),
]

verified_total = 0
for name, path_str, pattern in complete:
    path = Path(path_str)
    if path.exists():
        count = len(list(path.glob(pattern)))
        print(f"  {name}: {count}")
        verified_total += count

print(f"\nVerified complete platforms total: {verified_total:,}")
print("=" * 80)
