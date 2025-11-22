#!/usr/bin/env python3
"""
Fix corrupted Windows PowerShell scripts that have bash code mixed in
"""

from pathlib import Path
import re

# Read list of corrupted files
with open('/tmp/corrupted_windows_files.txt', 'r') as f:
    corrupted_files = [line.strip() for line in f if line.strip()]

print(f"Fixing {len(corrupted_files)} corrupted Windows PowerShell scripts...")
print()

fixed = 0
errors = 0

for file_path in corrupted_files:
    script_path = Path(file_path)

    if not script_path.exists():
        print(f"  ✗ File not found: {file_path}")
        errors += 1
        continue

    try:
        # Read the file
        content = script_path.read_text(encoding='utf-8')

        # Find where the corruption starts (bash code begins)
        # Look for patterns like "try {" followed by bash commands
        match = re.search(r'(try \{\s*\n)(if ! command -v|#!/usr/bin/env bash)', content, re.MULTILINE)

        if not match:
            print(f"  ⚠ No corruption pattern found in {script_path.name}")
            continue

        corruption_start = match.start(2)

        # Find the proper PowerShell close - look for the catch block or end of try
        # Take everything before the corruption
        clean_start = content[:corruption_start]

        # Generate proper PowerShell placeholder
        placeholder = '''    # TODO: Implement Windows STIG check logic
    # This check requires implementation based on STIG requirements
    Write-Host "INFO: Check not yet implemented"
    Write-Host "MANUAL REVIEW REQUIRED"

    if ($OutputJson) {
        $output = @{
            vuln_id = $VULN_ID
            stig_id = $STIG_ID
            severity = $SEVERITY
            status = "Not_Reviewed"
            finding_details = "Check logic not yet implemented"
        }
        Write-Host ($output | ConvertTo-Json -Depth 10)
    }

    exit 2  # Manual review required
'''

        # Find the catch block or script end from the original clean version
        # We need to close the try block and add catch
        catch_block = '''} catch {
    if ($OutputJson) {
        $output = @{
            vuln_id = $VULN_ID
            stig_id = $STIG_ID
            severity = $SEVERITY
            status = "Error"
            finding_details = $_.Exception.Message
        }
        Write-Host ($output | ConvertTo-Json -Depth 10)
    } else {
        Write-Host "ERROR: $($_.Exception.Message)"
    }

    exit 3
}
'''

        # Construct the fixed content
        fixed_content = clean_start + placeholder + '\n' + catch_block

        # Write the fixed content
        script_path.write_text(fixed_content, encoding='utf-8')
        fixed += 1
        print(f"  ✓ Fixed {script_path.name}")

    except Exception as e:
        print(f"  ✗ Error fixing {script_path.name}: {e}")
        errors += 1

print()
print(f"Fixed: {fixed}/{len(corrupted_files)}")
print(f"Errors: {errors}")
