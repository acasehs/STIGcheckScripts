#!/usr/bin/env python3

previous = 4317
oracle_linux_9_v = 456
new_total = previous + oracle_linux_9_v

total_scripts = 6164
percentage = (new_total / total_scripts) * 100
target_80 = int(total_scripts * 0.80)
needed = target_80 - new_total

print("=" * 80)
print("STATUS AFTER ORACLE LINUX 9 V-* IMPLEMENTATION")
print("=" * 80)
print(f"Previous: {previous:,} (70.04%)")
print(f"Oracle Linux 9 V-*: +{oracle_linux_9_v}")
print(f"New total: {new_total:,}/{total_scripts:,} ({percentage:.1f}%)")
print()
print(f"80% Target: {target_80:,}")
print(f"Still needed: {needed}")
print("=" * 80)
