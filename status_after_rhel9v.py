#!/usr/bin/env python3

previous = 4933
rhel_9_v_remaining = 290
new_total = previous + rhel_9_v_remaining

total_scripts = 6164
percentage = (new_total / total_scripts) * 100
target_90 = int(total_scripts * 0.90)
needed = target_90 - new_total

print("=" * 80)
print("STATUS AFTER RHEL 9 V-* COMPLETION")
print("=" * 80)
print(f"Previous: {previous:,} (80.03%)")
print(f"RHEL 9 V-* remaining: +{rhel_9_v_remaining}")
print(f"New total: {new_total:,}/{total_scripts:,} ({percentage:.1f}%)")
print()
print(f"90% Target: {target_90:,}")
print(f"Still needed: {needed}")
print("=" * 80)
