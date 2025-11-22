<#
.SYNOPSIS
    STIG Check: V-214380
    Severity: medium

.DESCRIPTION
    Rule Title: The Apache web server must augment re-creation to a stable and known baseline.
    STIG ID: AS24-W2-000540
    Rule ID: SV-214380r961122

    Making certain that the web server has not been updated by an unauthorized user is always a concern. Adding patches, functions, and modules that are untested and not part of the baseline opens the possibility for security risks. The web server must offer, and not hinder, a method that allows for the quick and easy reinstallation of a verified and patched baseline to guarantee the production web server is up-to-date and has not been modified to add functionality or expose security risks.

When th

.PARAMETER Config
    Configuration file path (JSON)

.PARAMETER OutputJson
    Output results in JSON format to specified file

.OUTPUTS
    Exit Codes:
        0 = Check Passed (Compliant)
        1 = Check Failed (Finding)
        2 = Check Not Applicable
        3 = Check Error
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$Config,

    [Parameter(Mandatory=$false)]
    [string]$OutputJson
)

# Configuration
$VULN_ID = "V-214380"
$STIG_ID = "AS24-W2-000540"
$SEVERITY = "medium"
$TIMESTAMP = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")

# Load configuration if provided
if ($Config -and (Test-Path $Config)) {
    $ConfigData = Get-Content $Config | ConvertFrom-Json
}

################################################################################
# MAIN CHECK LOGIC
################################################################################

try {
    # Windows Apache Configuration Check
    $apacheService = Get-Service -Name "Apache*" -ErrorAction SilentlyContinue

    if (-not $apacheService) {
        Write-Output "ERROR: Apache service not found on this system"
        if ($OutputJson) {
            @{
                vuln_id = $VULN_ID
                stig_id = $STIG_ID
                severity = $SEVERITY
                status = "ERROR"
                message = "Apache not installed"
                timestamp = $TIMESTAMP
            } | ConvertTo-Json | Out-File $OutputJson
        }
        exit 3
    }

    Write-Output "INFO: Apache service found: $($apacheService.DisplayName)"
    Write-Output "Service Status: $($apacheService.Status)"
    Write-Output ""
    Write-Output "MANUAL REVIEW REQUIRED: Review Apache configuration for STIG compliance"
    Write-Output "This check requires manual examination of Apache settings on Windows"

    if ($OutputJson) {
        @{
            vuln_id = $VULN_ID
            stig_id = $STIG_ID
            severity = $SEVERITY
            status = "MANUAL"
            message = "Manual review required"
            details = "Apache service: $($apacheService.DisplayName)"
            timestamp = $TIMESTAMP
        } | ConvertTo-Json | Out-File $OutputJson
    }

    exit 2  # Not Applicable - requires manual review

    exit 3

} catch {
    Write-Error $_.Exception.Message

    if ($OutputJson) {
        @{
            vuln_id = $VULN_ID
            stig_id = $STIG_ID
            severity = $SEVERITY
            status = "ERROR"
            message = $_.Exception.Message
            timestamp = $TIMESTAMP
        } | ConvertTo-Json | Out-File $OutputJson
    }

    exit 3
}
