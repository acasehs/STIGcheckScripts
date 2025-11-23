#!/usr/bin/env python3

current = 3438
oracle_linux = 238
new_total = current + oracle_linux

target_60 = 3698
needed = target_60 - new_total

print("=" * 80)
print("PROJECT STATUS AFTER ORACLE LINUX 9")
print("=" * 80)
print(f"Previous: {current:,} implementations (55.8%)")
print(f"Oracle Linux 9: +{oracle_linux} implementations")
print(f"New total: {new_total:,}/{6164} ({new_total/6164*100:.1f}%)")
print()
print(f"60% Target: {target_60:,} implementations")
print(f"Still needed: {needed} more implementations")
print("=" * 80)
