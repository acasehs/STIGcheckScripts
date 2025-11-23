#!/usr/bin/env python3
"""Verify the implementation count matches our tracking"""

from pathlib import Path

def is_implemented(file_path):
    """Check if file is implemented (has exit 0, 1, or 2 with proper implementation)"""
    try:
        content = file_path.read_text(encoding='utf-8', errors='ignore')
        
        # Check for manual review implementation (exit 2)
        if 'exit 2  # Manual review required' in content or \
           ('Manual review required' in content and 'exit 2' in content) or \
           ('Not_Reviewed' in content and 'EXIT_CODE=2' in content):
            return True
        
        # Check for actual implementation (exit 0 or 1)
        if ('exit 0' in content or 'exit 1' in content) and \
           'TODO: Implement' not in content:
            return True
        
        return False
    except:
        return False

# Count all scripts
all_scripts = []
for pattern in ['**/*.sh', '**/*.ps1']:
    scripts = list(Path('checks').glob(pattern))
    all_scripts.extend(scripts)

print("=" * 80)
print("IMPLEMENTATION VERIFICATION")
print("=" * 80)

implemented = sum(1 for s in all_scripts if is_implemented(s))
total = len(all_scripts)

print(f"Total scripts in checks/: {total:,}")
print(f"Implemented scripts: {implemented:,}")
print(f"Not implemented: {total - implemented:,}")
print()
print(f"Session tracking:")
print(f"  Baseline: 6,164 total")
print(f"  Current: 5,966 implemented")
print(f"  Remaining: 198")
print()
print(f"Verification shows:")
print(f"  Difference in total: {total - 6164:,} scripts")
print(f"  Difference in implemented: {implemented - 5966:,} scripts")
print("=" * 80)
