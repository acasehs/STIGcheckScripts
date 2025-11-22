#!/usr/bin/env python3
"""Quick status calculation"""

# Previous milestone: 3,224/6,164 (52.3%)
previous = 3224
total_scripts = 6164
new_implementations = 214

current = previous + new_implementations
percentage = (current / total_scripts) * 100

target_60 = int(total_scripts * 0.60)
needed_for_60 = target_60 - current

print("=" * 80)
print("PROJECT STATUS UPDATE")
print("=" * 80)
print(f"Previous: {previous:,}/{total_scripts:,} scripts (52.3%)")
print(f"New implementations: {new_implementations:,} Windows Server checks")
print(f"Current: {current:,}/{total_scripts:,} scripts ({percentage:.1f}%)")
print()
print(f"60% Milestone Target: {target_60:,} scripts")
print(f"Remaining needed: {needed_for_60:,} implementations")
print("=" * 80)
