<#
.SYNOPSIS
    STIG Check: V-214343
    Severity: medium

.DESCRIPTION
    Rule Title: The Apache web server must restrict inbound connections from nonsecure zones.
    STIG ID: AS24-W1-000670
    Rule ID: SV-214343r961278

    Remote access to the Apache web server is any access that communicates through an external, non-organization-controlled network. Remote access can be used to access hosted applications or to perform management functions.

A web server can be accessed remotely and must be capable of restricting access from what the DoD defines as nonsecure zones. Nonsecure zones are defined as any IP, subnet, or region that is defined as a threat to the organization. The nonsecure zones must be defined for public

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
$VULN_ID = "V-214343"
$STIG_ID = "AS24-W1-000670"
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
