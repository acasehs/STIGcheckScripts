<#
.SYNOPSIS
    STIG Check: V-223311

.DESCRIPTION
    STIG ID: O365-EX-000002
    Severity: medium
    Rule Title: VBA Macros not digitally signed must be blocked in Excel....

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
$VulnID = "V-223311"
$StigID = "O365-EX-000002"
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
$RegPath = "HKCU\software\policies\Microsoft\office\16.0\excel\security"
$RegValue = "for User Configuration >> Administrative Templates >> Microsoft Excel 2016 >> Excel Options >> Security >> Trust Center >> "Macro Notification Settings" is set to "Enabled" and "Disable VBA macros except digitally signed macros" from the Options is selected."
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
