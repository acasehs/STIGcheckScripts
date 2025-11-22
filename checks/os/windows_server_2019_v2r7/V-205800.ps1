<#
.SYNOPSIS
    STIG Check: V-205800

.DESCRIPTION
    Severity: low
    Rule Title: The Windows Server 2019 time service must synchronize with an appropriate DoD time source.
    STIG ID: WN19-00-000440
    STIG Version: Windows Server 2019 v2r7

.NOTES
    AUTO-GENERATED: 2025-11-22 04:41:54
    Based on template: service check
#>

[CmdletBinding()]
param(
    [string]$ConfigFile,
    [string]$OutputJson
)

$VulnID = "V-205800"
$Severity = "low"
$StigID = "WN19-00-000440"
$Status = "Not Checked"

# TODO: Extract actual service name
$ServiceName = "SERVICE_NAME"

try {
    $service = Get-Service -Name $ServiceName -ErrorAction Stop

    if ($service.Status -eq 'Running') {
        $Status = "NotAFinding"
        Write-Host "PASS: Service $ServiceName is running"
        exit 0
    } else {
        $Status = "Open"
        Write-Host "FAIL: Service $ServiceName is not running (Status: $($service.Status))"
        exit 1
    }
} catch {
    Write-Host "ERROR: Could not check service $ServiceName : $_"
    exit 3
}
