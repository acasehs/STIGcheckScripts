#!/usr/bin/env python3
"""Check what patterns exist in unimplemented Oracle Linux 9 scripts"""

from pathlib import Path

ol9_dir = Path('checks/os/oracle_linux_9_v1r2')
scripts = list(ol9_dir.glob('*.sh'))

unimpl_patterns = {}

for script in scripts[:50]:  # Sample first 50
    try:
        content = script.read_text(encoding='utf-8')
        
        if 'exit 3' in content and ('echo "TODO:' in content or 'echo "ERROR:' in content):
            # Find the main() function area
            if 'main()' in content:
                # Extract main function
                import re
                match = re.search(r'main\(\) \{(.*?)\n\}', content, re.DOTALL)
                if match:
                    main_func = match.group(1)[:500]  # First 500 chars
                    
                    # Categorize pattern
                    if '# TODO: Implement actual STIG check logic' in main_func:
                        pattern_key = 'TODO: Implement actual'
                    elif 'echo "TODO:' in main_func:
                        pattern_key = 'echo TODO'
                    elif 'echo "ERROR:' in main_func:
                        pattern_key = 'echo ERROR'
                    else:
                        pattern_key = 'other_exit3'
                    
                    if pattern_key not in unimpl_patterns:
                        unimpl_patterns[pattern_key] = []
                    unimpl_patterns[pattern_key].append(script.name)
    except:
        pass

print("=" * 80)
print("ORACLE LINUX 9 UNIMPLEMENTED PATTERNS")
print("=" * 80)
for pattern, files in unimpl_patterns.items():
    print(f"\n{pattern}: {len(files)} files")
    print(f"  Example: {files[0]}")

# Check one sample file
if scripts:
    sample = None
    for s in scripts:
        content = s.read_text(encoding='utf-8')
        if 'exit 3' in content:
            sample = s
            break
    
    if sample:
        print(f"\n\nSample unimplemented file: {sample.name}")
        print("=" * 80)
        # Show last 30 lines
        lines = content.split('\n')
        print('\n'.join(lines[-30:]))
