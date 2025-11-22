# Ubuntu 22.04 LTS STIG Automation Framework

Automated Security Technical Implementation Guide (STIG) compliance checks for Canonical Ubuntu 22.04 LTS.

## Overview

- **Benchmark**: Canonical Ubuntu 22.04 LTS
- **Benchmark ID**: CAN_Ubuntu_22-04_LTS_STIG
- **Version**: 2
- **Release**: Release: 5 Benchmark Date: 02 Jul 2025
- **Total Checks**: 187 (182 automated, 5 manual review)
- **Generated Scripts**: 364 files (182 bash + 182 python)

## Tool Priority

The framework follows this tool priority hierarchy:
1. **Bash** (Primary) - Native Linux shell scripting
2. **Python** (Fallback) - Cross-platform compatibility
3. **Third-party** (If required) - Specialized tools when needed

## Exit Codes

All scripts follow standardized exit codes:
- `0` = PASS (Not a Finding)
- `1` = FAIL (Finding)
- `2` = N/A (Not Applicable)
- `3` = ERROR (Check failed to execute)

## Usage

### Basic Usage

Run a single check:
```bash
./V-260469.sh
```

### Configuration File Support

Load configuration from a file:
```bash
./V-260469.sh --config /path/to/config.json
```

### JSON Output

Output results in JSON format:
```bash
./V-260469.sh --output-json
```

Example JSON output:
```json
{
  "vuln_id": "V-260469",
  "stig_id": "UBTU-22-211015",
  "severity": "high",
  "status": "NotAFinding",
  "finding_details": "",
  "comments": "Check passed",
  "evidence": {}
}
```

### Help

Display usage information:
```bash
./V-260469.sh --help
```

## Running Multiple Checks

### Run all checks
```bash
for script in *.sh; do
    echo "Running $script..."
    ./"$script"
done
```

### Run all checks with JSON output
```bash
for script in *.sh; do
    ./"$script" --output-json
done | jq -s '.'
```

### Run specific severity checks
```bash
# Run only high severity checks
grep -l "SEVERITY=\"high\"" *.sh | while read script; do
    ./"$script"
done
```

## Script Structure

Each check includes:
- **Bash Script** (`.sh`) - Primary implementation
- **Python Script** (`.py`) - Fallback implementation

Both scripts support the same command-line options and output formats.

## Customization

The generated scripts are templates with placeholder logic:
```bash
# TODO: Implement specific check logic
# This is a placeholder - customize based on check requirements
```

To customize a check:
1. Open the script file (bash or python)
2. Locate the `TODO` comment in the main check logic
3. Replace the placeholder with actual check implementation
4. Test the script to ensure proper exit codes

## Manual Review Checks

The following checks were skipped during generation and require manual review:
- V-260473 - Requires organizational policy review
- V-260484 - Requires site security plan review
- V-260529 - Requires documented procedures
- V-260541 - Requires organization-defined values
- V-274860 - Requires manual verification

## File Permissions

All scripts are executable (755 permissions):
```bash
ls -l *.sh *.py | head -5
```

## Integration

### CI/CD Pipeline
```yaml
# Example GitLab CI/CD job
stig_compliance:
  script:
    - cd checks/os/ubuntu_22.04_lts_v2r5
    - for script in *.sh; do ./"$script" --output-json; done > results.json
  artifacts:
    paths:
      - results.json
```

### Ansible Integration
```yaml
---
- name: Run STIG checks
  command: "{{ item }}"
  loop: "{{ lookup('fileglob', 'checks/os/ubuntu_22.04_lts_v2r5/*.sh', wantlist=True) }}"
  register: stig_results
  ignore_errors: yes
```

## Directory Structure

```
ubuntu_22.04_lts_v2r5/
├── README.md              # This file
├── V-260469.sh           # Bash check scripts
├── V-260469.py           # Python fallback scripts
├── V-260470.sh
├── V-260470.py
├── ...
└── V-274879.py
```

## Support

For issues, questions, or contributions:
1. Review the script comments for check-specific requirements
2. Verify the check content against the official STIG documentation
3. Test scripts in a non-production environment first

## Generation

This framework was generated using:
```bash
python3 generate_oracle_stigs.py \
  --benchmark "Canonical Ubuntu 22.04 LTS" \
  --output-dir checks/os/ubuntu_22.04_lts_v2r5
```

## License

These scripts are provided as-is for STIG compliance automation.
