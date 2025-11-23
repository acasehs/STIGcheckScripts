#!/usr/bin/env python3
"""Find all remaining TODO patterns across all platforms"""

from pathlib import Path
from collections import defaultdict

def has_todo_pattern(file_path):
    """Check if file has unimplemented TODO pattern"""
    try:
        content = file_path.read_text(encoding='utf-8', errors='ignore')
        
        # Various TODO patterns
        patterns = [
            '# TODO: Implement actual STIG check logic',
            '# TODO: Implement the actual check logic',
            'echo "TODO: Implement',
            'TODO: Implement check logic',
            'exit 3  # Not implemented',
        ]
        
        for pattern in patterns:
            if pattern in content:
                # But exclude if it's already implemented with exit 2 manual review
                if 'exit 2  # Manual review required' not in content and \
                   'Manual review required' not in content and \
                   'Not_Reviewed' not in content:
                    return True
        
        return False
    except:
        return False

# Search all platform directories
platforms_with_todos = defaultdict(list)

for platform_dir in Path('checks').rglob('*'):
    if not platform_dir.is_dir():
        continue
    
    # Skip hidden directories and git
    if any(part.startswith('.') for part in platform_dir.parts):
        continue
    
    for script in platform_dir.glob('*'):
        if script.suffix in ['.sh', '.ps1'] and script.is_file():
            if has_todo_pattern(script):
                platform_name = platform_dir.name
                platforms_with_todos[platform_name].append(script.name)

print("=" * 80)
print("REMAINING UNIMPLEMENTED FILES BY PLATFORM")
print("=" * 80)

total_remaining = 0
for platform, files in sorted(platforms_with_todos.items(), key=lambda x: len(x[1]), reverse=True):
    count = len(files)
    total_remaining += count
    print(f"\n{platform}: {count} files")
    if count <= 10:
        for f in files[:10]:
            print(f"  - {f}")
    else:
        print(f"  (showing first 5)")
        for f in files[:5]:
            print(f"  - {f}")

print("\n" + "=" * 80)
print(f"Total remaining TODO files: {total_remaining}")
print(f"Session tracking says: 198 remaining")
print("=" * 80)
