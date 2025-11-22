#!/usr/bin/env python3
"""Find platforms with unimplemented checks for 60% milestone"""

from pathlib import Path
import re

def count_todos_in_directory(dir_path):
    """Count files with TODO markers in a directory"""
    todo_count = 0
    total_count = 0
    
    # Look for common script extensions
    for ext in ['*.ps1', '*.sh', '*.py', '*.pl']:
        for script in dir_path.glob(ext):
            total_count += 1
            content = script.read_text(encoding='utf-8', errors='ignore')
            
            # Check for common TODO patterns
            if ('# TODO:' in content or 
                'TODO:' in content or
                'Not yet implemented' in content or
                'exit 3  # Not implemented' in content):
                todo_count += 1
    
    return total_count, todo_count

# Check all platform directories
platforms = []

base_dirs = [
    ('OS', Path('checks/os')),
    ('Application', Path('checks/application')),
    ('Database', Path('checks/database')),
    ('Network', Path('checks/network')),
]

for category, base_path in base_dirs:
    if not base_path.exists():
        continue
    
    for platform_dir in sorted(base_path.iterdir()):
        if not platform_dir.is_dir():
            continue
        
        total, todos = count_todos_in_directory(platform_dir)
        
        if total > 0 and todos > 0:
            implemented = total - todos
            pct = (implemented / total * 100) if total > 0 else 0
            
            platforms.append({
                'name': platform_dir.name,
                'category': category,
                'total': total,
                'implemented': implemented,
                'remaining': todos,
                'percent': pct
            })

# Sort by number of remaining checks (descending)
platforms.sort(key=lambda x: x['remaining'], reverse=True)

print("=" * 100)
print("PLATFORMS WITH UNIMPLEMENTED CHECKS (Sorted by Remaining Count)")
print("=" * 100)
print(f"{'Platform':<40} {'Category':<15} {'Total':>6} {'Done':>6} {'TODO':>6} {'%':>6}")
print("-" * 100)

for p in platforms[:30]:  # Show top 30
    print(f"{p['name']:<40} {p['category']:<15} {p['total']:>6} {p['implemented']:>6} {p['remaining']:>6} {p['percent']:>6.1f}%")

print("=" * 100)
print(f"\nNeed 260 implementations to reach 60% milestone")
print("=" * 100)
