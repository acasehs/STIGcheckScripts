<#
.SYNOPSIS
    STIG Check: V-220958
    Severity: high

.DESCRIPTION
    Rule Title: The Act as part of the operating system user right must not be assigned to any groups or accounts.
    STIG ID: WN10-UR-000015
    Rule ID: SV-220958r958726

    Inappropriate granting of user rights can provide system, administrative, and other high level capabilities.

Accounts with the \"Act as part of the operating system\" user right can assume the identity of any user and gain access to resources that user is authorized to access.  Any accounts with this right can take complete control of a system.

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
$VULN_ID = "V-220958"
$STIG_ID = "WN10-UR-000015"
$SEVERITY = "high"
$TIMESTAMP = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")

# Load configuration if provided
if ($Config -and (Test-Path $Config)) {
    $ConfigData = Get-Content $Config | ConvertFrom-Json
}

################################################################################
# MAIN CHECK LOGIC
################################################################################

try {
    # STIG Check Implementation - Manual Review Required
    Write-Output "================================================================================"
    Write-Output "STIG Check: $VULN_ID"
    Write-Output "STIG ID: $STIG_ID"
    Write-Output "Severity: $SEVERITY"
    Write-Output "Timestamp: $TIMESTAMP"
    Write-Output "================================================================================"
    Write-Output ""
    Write-Output "MANUAL REVIEW REQUIRED"
    Write-Output "This STIG check requires manual verification of Windows configuration."
    Write-Output "Please consult the STIG documentation for specific compliance requirements."
    Write-Output ""
    Write-Output "Status: Not_Reviewed"
    Write-Output "================================================================================"

    if ($OutputJson) {
        @{
            vuln_id = $VULN_ID
            stig_id = $STIG_ID
            severity = $SEVERITY
            status = "Not_Reviewed"
            finding_details = "Manual review required"
            comments = "Consult STIG documentation for Windows compliance verification"
            timestamp = $TIMESTAMP
            requires_manual_review = $true
        } | ConvertTo-Json | Out-File $OutputJson
    }

    exit 2  # Manual review required


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
