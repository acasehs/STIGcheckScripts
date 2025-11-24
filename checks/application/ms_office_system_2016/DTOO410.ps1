<#
.SYNOPSIS
    STIG Check: V-238040

.DESCRIPTION
    STIG ID: DTOO410
    Severity: medium
    Rule Title: When using the Office Feedback tool, the ability to include a screensh...

    Automated Check: Registry Value Validation
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$Config,

    [Parameter(Mandatory=$false)]
    [string]$OutputJson
)

# Configuration
$VulnID = "V-238040"
$StigID = "DTOO410"
$Severity = "medium"
$Timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")

# Output function
function Output-Json {
    param(
        [string]$Status,
        [string]$FindingDetails
    )

    if ($OutputJson) {
        @{
            vuln_id = $VulnID
            stig_id = $StigID
            severity = $Severity
            status = $Status
            finding_details = $FindingDetails
            timestamp = $Timestamp
        } | ConvertTo-Json | Out-File -FilePath $OutputJson -Encoding UTF8
    }
}

# Automated registry check
$RegPath = "HKCU\software\policies\Microsoft\office\16.0\common\feedback"
$RegValue = "for User Configuration >> Administrative Templates >> Microsoft Office 2016 >> Privacy >> Trust Center >> "Allow users to include screenshots and attachments when they submit feedback to Microsoft" is set to "Disabled"."
$ExpectedValue = "1"

try {
    # Check if registry path exists
    if (-not (Test-Path $RegPath)) {
        Output-Json "Open" "Registry path does not exist: $RegPath"
        Write-Host "[$VulnID] FAIL - Registry path not found"
        exit 1
    }

    # Get actual value
    $ActualValue = Get-ItemProperty -Path $RegPath -Name $RegValue -ErrorAction SilentlyContinue

    if ($null -eq $ActualValue) {
        Output-Json "Open" "Registry value not set: $RegValue"
        Write-Host "[$VulnID] FAIL - Registry value not set"
        exit 1
    }

    $ActualValueData = $ActualValue.$RegValue

    # Compare values
    if ($ActualValueData -eq $ExpectedValue) {
        Output-Json "NotAFinding" "Registry value is compliant: $ActualValueData"
        Write-Host "[$VulnID] PASS - Value: $ActualValueData"
        exit 0
    } else {
        Output-Json "Open" "Registry value not compliant: $ActualValueData (expected: $ExpectedValue)"
        Write-Host "[$VulnID] FAIL - Value: $ActualValueData (expected: $ExpectedValue)"
        exit 1
    }

} catch {
    Output-Json "ERROR" "Error checking registry: $($_.Exception.Message)"
    Write-Host "[$VulnID] ERROR - $($_.Exception.Message)"
    exit 3
}
