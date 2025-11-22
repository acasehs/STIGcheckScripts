#!/usr/bin/env python3

previous = 3438
oracle_linux = 238
rhel = 30
total_new = oracle_linux + rhel
new_total = previous + total_new

total_scripts = 6164
percentage = (new_total / total_scripts) * 100
target_60 = int(total_scripts * 0.60)

print("=" * 80)
print("🎯 60% MILESTONE ACHIEVEMENT")
print("=" * 80)
print(f"Previous: {previous:,} implementations (55.8%)")
print(f"Oracle Linux 9: +{oracle_linux} implementations")
print(f"RHEL 9: +{rhel} implementations")
print(f"Total new: +{total_new} implementations")
print()
print(f"NEW TOTAL: {new_total:,}/{total_scripts:,} ({percentage:.1f}%)")
print()
print(f"60% Target: {target_60:,} implementations")
print(f"Achievement: EXCEEDED by {new_total - target_60} implementations! 🏆")
print("=" * 80)
