#!/usr/bin/env python3
"""
Generate comprehensive STIG implementation report in HTML format
Shows all scripts grouped by checklist with automation status
"""

from pathlib import Path
from collections import defaultdict
import re
import json
from datetime import datetime

def parse_script_metadata(script_path):
    """Extract metadata from a script file"""
    try:
        content = script_path.read_text(encoding='utf-8', errors='ignore')

        metadata = {
            'file': script_path.name,
            'path': str(script_path),
            'vuln_id': None,
            'stig_id': None,
            'severity': None,
            'rule_title': None,
            'automation_status': 'unknown',
            'requires_params': False,
            'manual_review': False,
            'notes': []
        }

        # Extract VULN ID
        vuln_match = re.search(r'(?:VULN_ID|vuln_id|STIG Check:|V-)[\s=:"\']*(V-\d+)', content, re.IGNORECASE)
        if vuln_match:
            metadata['vuln_id'] = vuln_match.group(1)

        # Extract STIG ID
        stig_match = re.search(r'(?:STIG_ID|stig_id|STIG ID:)[\s=:"\']*([\w-]+)', content, re.IGNORECASE)
        if stig_match:
            metadata['stig_id'] = stig_match.group(1)

        # Extract severity
        sev_match = re.search(r'(?:SEVERITY|severity|Severity:)[\s=:"\']*(high|medium|low)', content, re.IGNORECASE)
        if sev_match:
            metadata['severity'] = sev_match.group(1).lower()

        # Extract rule title
        title_match = re.search(r'(?:Rule Title|rule_title|RULE_TITLE)[\s=:"\']*(.*?)(?:"|\'|\n)', content, re.IGNORECASE)
        if title_match:
            metadata['rule_title'] = title_match.group(1).strip()[:100]

        # Determine automation status
        if 'exit 2  # Manual review required' in content or \
           ('Manual review required' in content and 'exit 2' in content) or \
           ('Not_Reviewed' in content and 'EXIT_CODE=2' in content):
            metadata['automation_status'] = 'manual_review'
            metadata['manual_review'] = True
            metadata['notes'].append('Requires manual verification against STIG requirements')
        elif '# TODO: Implement' in content or 'TODO: Implement' in content:
            if 'exit 3' in content:
                metadata['automation_status'] = 'not_implemented'
                metadata['notes'].append('Not yet implemented - placeholder only')
        elif 'exit 0' in content or 'exit 1' in content:
            metadata['automation_status'] = 'automated'
            metadata['notes'].append('Fully automated check')

        # Check for parameter requirements
        if '# TODO: Extract' in content or 'TODO: Extract' in content:
            metadata['requires_params'] = True
            metadata['notes'].append('Requires parameter configuration')

        if '--config' in content or 'CONFIG_FILE' in content or '$ConfigFile' in content:
            metadata['requires_params'] = True
            if 'Requires configuration file' not in ' '.join(metadata['notes']):
                metadata['notes'].append('Supports optional configuration file')

        return metadata

    except Exception as e:
        return {
            'file': script_path.name,
            'path': str(script_path),
            'vuln_id': None,
            'stig_id': None,
            'severity': None,
            'rule_title': f'Error parsing: {e}',
            'automation_status': 'error',
            'requires_params': False,
            'manual_review': False,
            'notes': ['Error parsing script']
        }

def scan_stig_checks():
    """Scan all STIG check directories"""
    checks_dir = Path('checks')
    platforms = defaultdict(lambda: defaultdict(list))

    for category_dir in checks_dir.iterdir():
        if not category_dir.is_dir() or category_dir.name.startswith('.'):
            continue

        category = category_dir.name  # os, application, database, network

        for platform_dir in category_dir.iterdir():
            if not platform_dir.is_dir() or platform_dir.name.startswith('.'):
                continue

            platform_name = platform_dir.name

            # Find all scripts
            scripts = list(platform_dir.glob('*.sh')) + list(platform_dir.glob('*.ps1'))

            for script in sorted(scripts):
                metadata = parse_script_metadata(script)
                platforms[category][platform_name].append(metadata)

    return platforms

def generate_html_report(platforms):
    """Generate comprehensive HTML report"""

    html = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>STIG Implementation Report - Complete Inventory</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #f5f5f5;
            color: #333;
            line-height: 1.6;
        }

        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 2rem;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }

        .header h1 {
            font-size: 2.5rem;
            margin-bottom: 0.5rem;
        }

        .header .subtitle {
            font-size: 1.2rem;
            opacity: 0.9;
        }

        .stats {
            background: white;
            padding: 1.5rem;
            margin: 2rem;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
        }

        .stat-box {
            text-align: center;
            padding: 1rem;
            border-left: 4px solid #667eea;
        }

        .stat-box .number {
            font-size: 2rem;
            font-weight: bold;
            color: #667eea;
        }

        .stat-box .label {
            color: #666;
            font-size: 0.9rem;
        }

        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 2rem;
        }

        .category {
            background: white;
            margin-bottom: 2rem;
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }

        .category-header {
            background: #667eea;
            color: white;
            padding: 1.5rem;
            font-size: 1.5rem;
            font-weight: bold;
            cursor: pointer;
            user-select: none;
        }

        .category-header:hover {
            background: #5568d3;
        }

        .platform {
            border-bottom: 1px solid #eee;
        }

        .platform:last-child {
            border-bottom: none;
        }

        .platform-header {
            background: #f8f9fa;
            padding: 1rem 1.5rem;
            font-size: 1.2rem;
            font-weight: 600;
            color: #495057;
            cursor: pointer;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .platform-header:hover {
            background: #e9ecef;
        }

        .platform-badge {
            display: inline-block;
            padding: 0.25rem 0.75rem;
            border-radius: 12px;
            font-size: 0.85rem;
            font-weight: 600;
            margin-left: 0.5rem;
        }

        .badge-complete {
            background: #28a745;
            color: white;
        }

        .badge-partial {
            background: #ffc107;
            color: #333;
        }

        .checks-table {
            width: 100%;
            border-collapse: collapse;
        }

        .checks-table th {
            background: #f1f3f5;
            padding: 0.75rem;
            text-align: left;
            font-weight: 600;
            color: #495057;
            border-bottom: 2px solid #dee2e6;
            position: sticky;
            top: 0;
        }

        .checks-table td {
            padding: 0.75rem;
            border-bottom: 1px solid #dee2e6;
        }

        .checks-table tr:hover {
            background: #f8f9fa;
        }

        .vuln-id {
            font-family: 'Courier New', monospace;
            font-weight: 600;
            color: #667eea;
        }

        .stig-id {
            font-family: 'Courier New', monospace;
            color: #6c757d;
            font-size: 0.9rem;
        }

        .severity {
            display: inline-block;
            padding: 0.25rem 0.5rem;
            border-radius: 4px;
            font-size: 0.85rem;
            font-weight: 600;
            text-transform: uppercase;
        }

        .severity-high {
            background: #dc3545;
            color: white;
        }

        .severity-medium {
            background: #ffc107;
            color: #333;
        }

        .severity-low {
            background: #17a2b8;
            color: white;
        }

        .status {
            display: inline-block;
            padding: 0.25rem 0.75rem;
            border-radius: 12px;
            font-size: 0.85rem;
            font-weight: 600;
        }

        .status-automated {
            background: #28a745;
            color: white;
        }

        .status-manual {
            background: #17a2b8;
            color: white;
        }

        .status-not-implemented {
            background: #6c757d;
            color: white;
        }

        .status-error {
            background: #dc3545;
            color: white;
        }

        .notes {
            font-size: 0.85rem;
            color: #6c757d;
        }

        .note-item {
            display: flex;
            align-items: center;
            margin: 0.25rem 0;
        }

        .note-item::before {
            content: "•";
            margin-right: 0.5rem;
            color: #667eea;
        }

        .file-link {
            color: #667eea;
            text-decoration: none;
            font-family: 'Courier New', monospace;
            font-size: 0.9rem;
        }

        .file-link:hover {
            text-decoration: underline;
        }

        .legend {
            background: white;
            padding: 1.5rem;
            margin: 2rem;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }

        .legend h3 {
            margin-bottom: 1rem;
            color: #495057;
        }

        .legend-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 1rem;
        }

        .legend-item {
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }

        .collapsible-content {
            max-height: 0;
            overflow: hidden;
            transition: max-height 0.3s ease;
        }

        .collapsible-content.active {
            max-height: none;
        }

        .toggle-icon {
            transition: transform 0.3s ease;
        }

        .toggle-icon.active {
            transform: rotate(90deg);
        }

        @media print {
            .collapsible-content {
                max-height: none !important;
            }
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>🔒 STIG Implementation Report</h1>
        <div class="subtitle">Comprehensive Security Technical Implementation Guide Automation Status</div>
        <div class="subtitle">Generated: """ + datetime.now().strftime("%Y-%m-%d %H:%M:%S") + """</div>
    </div>
"""

    # Calculate statistics
    total_scripts = 0
    automated_count = 0
    manual_review_count = 0
    not_implemented_count = 0
    requires_params_count = 0

    for category in platforms.values():
        for platform_checks in category.values():
            for check in platform_checks:
                total_scripts += 1
                if check['automation_status'] == 'automated':
                    automated_count += 1
                elif check['automation_status'] == 'manual_review':
                    manual_review_count += 1
                elif check['automation_status'] == 'not_implemented':
                    not_implemented_count += 1
                if check['requires_params']:
                    requires_params_count += 1

    # Statistics section
    html += f"""
    <div class="stats">
        <div class="stat-box">
            <div class="number">{total_scripts:,}</div>
            <div class="label">Total Checks</div>
        </div>
        <div class="stat-box">
            <div class="number">{automated_count:,}</div>
            <div class="label">Fully Automated</div>
        </div>
        <div class="stat-box">
            <div class="number">{manual_review_count:,}</div>
            <div class="label">Manual Review</div>
        </div>
        <div class="stat-box">
            <div class="number">{not_implemented_count:,}</div>
            <div class="label">Not Implemented</div>
        </div>
        <div class="stat-box">
            <div class="number">{requires_params_count:,}</div>
            <div class="label">Requires Parameters</div>
        </div>
    </div>

    <div class="legend">
        <h3>Legend</h3>
        <div class="legend-grid">
            <div class="legend-item">
                <span class="status status-automated">Automated</span>
                <span>Fully automated check with exit 0/1</span>
            </div>
            <div class="legend-item">
                <span class="status status-manual">Manual Review</span>
                <span>Framework implemented, requires manual verification</span>
            </div>
            <div class="legend-item">
                <span class="status status-not-implemented">Not Implemented</span>
                <span>Placeholder only, no automation</span>
            </div>
            <div class="legend-item">
                <span class="severity severity-high">High</span>
                <span>High severity finding</span>
            </div>
            <div class="legend-item">
                <span class="severity severity-medium">Medium</span>
                <span>Medium severity finding</span>
            </div>
            <div class="legend-item">
                <span class="severity severity-low">Low</span>
                <span>Low severity finding</span>
            </div>
        </div>
    </div>

    <div class="container">
"""

    # Categories
    category_names = {
        'os': '💻 Operating Systems',
        'application': '📦 Applications',
        'database': '🗄️ Databases',
        'network': '🌐 Network Devices'
    }

    for category_key in sorted(platforms.keys()):
        category_title = category_names.get(category_key, category_key.title())
        category_data = platforms[category_key]

        html += f"""
        <div class="category">
            <div class="category-header" onclick="toggleCategory('{category_key}')">
                <span class="toggle-icon" id="icon-{category_key}">▶</span> {category_title}
            </div>
            <div class="collapsible-content" id="content-{category_key}">
"""

        for platform_name in sorted(category_data.keys()):
            checks = category_data[platform_name]

            # Calculate platform stats
            platform_total = len(checks)
            platform_manual = sum(1 for c in checks if c['automation_status'] == 'manual_review')
            platform_automated = sum(1 for c in checks if c['automation_status'] == 'automated')
            platform_pct = int((platform_manual + platform_automated) / platform_total * 100) if platform_total > 0 else 0

            badge_class = 'badge-complete' if platform_pct == 100 else 'badge-partial'

            html += f"""
                <div class="platform">
                    <div class="platform-header" onclick="togglePlatform('{category_key}-{platform_name}')">
                        <div>
                            <span class="toggle-icon" id="icon-{category_key}-{platform_name}">▶</span>
                            {platform_name}
                            <span class="platform-badge {badge_class}">{platform_pct}% ({platform_manual + platform_automated}/{platform_total})</span>
                        </div>
                        <div style="font-size: 0.9rem; font-weight: normal;">
                            {platform_automated} Automated | {platform_manual} Manual Review | {platform_total - platform_automated - platform_manual} Not Implemented
                        </div>
                    </div>
                    <div class="collapsible-content" id="content-{category_key}-{platform_name}">
                        <table class="checks-table">
                            <thead>
                                <tr>
                                    <th>VULN ID</th>
                                    <th>STIG ID</th>
                                    <th>Severity</th>
                                    <th>Status</th>
                                    <th>Rule Title</th>
                                    <th>Notes</th>
                                    <th>File</th>
                                </tr>
                            </thead>
                            <tbody>
"""

            for check in checks:
                severity_class = f"severity-{check['severity']}" if check['severity'] else ""
                status_class = f"status-{check['automation_status'].replace('_', '-')}"
                status_text = check['automation_status'].replace('_', ' ').title()

                vuln_id = check['vuln_id'] or 'N/A'
                stig_id = check['stig_id'] or 'N/A'
                severity = f'<span class="severity {severity_class}">{check["severity"]}</span>' if check['severity'] else 'N/A'
                rule_title = check['rule_title'] or 'No title available'

                notes_html = ''
                if check['notes']:
                    notes_html = '<div class="notes">' + ''.join([f'<div class="note-item">{note}</div>' for note in check['notes']]) + '</div>'

                # Create relative path for link
                rel_path = check['path'].replace('\\', '/')

                html += f"""
                                <tr>
                                    <td><span class="vuln-id">{vuln_id}</span></td>
                                    <td><span class="stig-id">{stig_id}</span></td>
                                    <td>{severity}</td>
                                    <td><span class="status {status_class}">{status_text}</span></td>
                                    <td>{rule_title}</td>
                                    <td>{notes_html}</td>
                                    <td><a href="{rel_path}" class="file-link">{check['file']}</a></td>
                                </tr>
"""

            html += """
                            </tbody>
                        </table>
                    </div>
                </div>
"""

        html += """
            </div>
        </div>
"""

    html += """
    </div>

    <script>
        function toggleCategory(categoryId) {
            const content = document.getElementById('content-' + categoryId);
            const icon = document.getElementById('icon-' + categoryId);
            content.classList.toggle('active');
            icon.classList.toggle('active');
        }

        function togglePlatform(platformId) {
            const content = document.getElementById('content-' + platformId);
            const icon = document.getElementById('icon-' + platformId);
            content.classList.toggle('active');
            icon.classList.toggle('active');
        }

        // Expand first category and platform by default
        document.addEventListener('DOMContentLoaded', function() {
            const firstCategory = document.querySelector('.category-header');
            if (firstCategory) {
                firstCategory.click();

                const firstPlatform = document.querySelector('.platform-header');
                if (firstPlatform) {
                    firstPlatform.click();
                }
            }
        });
    </script>
</body>
</html>
"""

    return html

def main():
    print("=" * 80)
    print("GENERATING COMPREHENSIVE STIG IMPLEMENTATION REPORT")
    print("=" * 80)
    print()

    print("Scanning STIG check directories...")
    platforms = scan_stig_checks()

    total_categories = len(platforms)
    total_platforms = sum(len(cat) for cat in platforms.values())
    total_scripts = sum(len(checks) for cat in platforms.values() for checks in cat.values())

    print(f"Found: {total_categories} categories, {total_platforms} platforms, {total_scripts:,} scripts")
    print()

    print("Generating HTML report...")
    html = generate_html_report(platforms)

    output_file = Path('STIG_Implementation_Report.html')
    output_file.write_text(html, encoding='utf-8')

    print()
    print("=" * 80)
    print(f"✅ Report generated: {output_file}")
    print("=" * 80)
    print()
    print("Open the HTML file in your web browser to view the complete report.")
    print("The report includes:")
    print("  • All STIG checks organized by category and platform")
    print("  • VULN IDs, STIG IDs, and severity levels")
    print("  • Automation status (Automated, Manual Review, Not Implemented)")
    print("  • Parameter requirements and manual review annotations")
    print("  • Links to individual check scripts")
    print("  • Interactive collapsible sections for easy navigation")

if __name__ == '__main__':
    main()
