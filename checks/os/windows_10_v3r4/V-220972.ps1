# STIG Check: V-220972
# STIG ID: WN10-UR-000090
# Severity: medium
# Rule Title: The Deny log on through Remote Desktop Services user right on Windows 10 workstations must at a minimum be configured to prevent access from highly privileged domain accounts and local accounts on domain systems and unauthenticated access on all systems.
#
# Description:
# Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

The "Deny log on through Remote Desktop Services" right defines the accounts that are prevented from logging on using Remote Desktop Services.

If Remote Desktop Services is not used by the organization, the Everyone group must be assigned this right to prevent all access.

In an Active Directory Domain, denying logons to the Enterprise Admins and Domain Admins groups on lower trust syst
#
# Tool Priority: PowerShell (1st priority) > Python (fallback) > third-party (if required)
# Exit Codes: 0=PASS, 1=FAIL, 2=N/A, 3=ERROR

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$ConfigFile,

    [Parameter(Mandatory=$false)]
    [switch]$OutputJson,

    [Parameter(Mandatory=$false)]
    [switch]$Help
)

# Configuration
$VulnID = "V-220972"
$StigID = "WN10-UR-000090"
$Severity = "medium"
$Status = "Open"

# Show help
if ($Help) {
    Write-Host "Usage: .\V-220972.ps1 [-ConfigFile FILE] [-OutputJson] [-Help]"
    Write-Host "  -ConfigFile FILE : Load configuration from FILE"
    Write-Host "  -OutputJson      : Output results in JSON format"
    Write-Host "  -Help            : Show this help message"
    exit 0
}

# Load configuration if provided
if ($ConfigFile -and (Test-Path $ConfigFile)) {
    # TODO: Load config values from JSON file
    $config = Get-Content $ConfigFile | ConvertFrom-Json
}

# Main check logic
function Invoke-Check {
    # Windows Security Check
    Write-Host "INFO: Checking Windows configuration"
    Write-Host ""

    Write-Host "MANUAL REVIEW REQUIRED: This check requires manual examination"
    Write-Host "Refer to STIG documentation for specific validation steps"
    Write-Host ""

    if ($OutputJson) {
        $output = @{
            vuln_id = $VulnID
            stig_id = $StigID
            severity = $Severity
            status = "Not_Reviewed"
            finding_details = "Manual review required"
        }
        Write-Host ($output | ConvertTo-Json -Depth 10)
    }

    exit 2  # Manual review required

}

# Execute check
try {
    $result = Invoke-Check

    if ($result) {
        if ($OutputJson) {
            $output = @{
                vuln_id = $VulnID
                stig_id = $StigID
                severity = $Severity
                status = "NotAFinding"
                finding_details = ""
                comments = "Check passed"
                evidence = @{}
            }
            Write-Host ($output | ConvertTo-Json -Depth 10)
        } else {
            Write-Host "[$VulnID] PASS - Not a Finding"
        }
        exit 0
    } else {
        if ($OutputJson) {
            $output = @{
                vuln_id = $VulnID
                stig_id = $StigID
                severity = $Severity
                status = "Open"
                finding_details = "Check failed"
                comments = ""
                compliance_issues = @()
            }
            Write-Host ($output | ConvertTo-Json -Depth 10)
        } else {
            Write-Host "[$VulnID] FAIL - Finding"
        }
        exit 1
    }
} catch {
    if ($OutputJson) {
        $output = @{
            vuln_id = $VulnID
            stig_id = $StigID
            severity = $Severity
            status = "Error"
            finding_details = $_.Exception.Message
            comments = "Error during check execution"
            compliance_issues = @()
        }
        Write-Host ($output | ConvertTo-Json -Depth 10)
    } else {
        Write-Host "[$VulnID] ERROR - $($_.Exception.Message)"
    }
    exit 3
}
