<#
.SYNOPSIS
    STIG Check: V-223284

.DESCRIPTION
    STIG ID: O365-CO-000001
    Severity: medium
    Rule Title: The Macro Runtime Scan Scope must be enabled for all documents....

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
$VulnID = "V-223284"
$StigID = "O365-CO-000001"
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
$RegPath = "HKCU\software\policies\microsoft\office\16.0\common\security_x000D_"
$RegValue = "for User Configuration >> Administrative Templates >> Microsoft Office 2016>> Security Settings "Macro Runtime Scan Scope" is set to "Enable for all documents"._x000D_"
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
