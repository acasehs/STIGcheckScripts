<#
.SYNOPSIS
    STIG Check: V-254408

.DESCRIPTION
    Severity: medium
    Rule Title: Windows Server 2022 must be configured to audit DS Access - Directory Service Access successes.
    STIG ID: WN22-DC-000240
    STIG Version: Windows Server 2022 v1r3

.NOTES
    AUTO-GENERATED: 2025-11-22 04:39:42
    Based on template: service check
#>

[CmdletBinding()]
param(
    [string]$ConfigFile,
    [string]$OutputJson
)

$VulnID = "V-254408"
$Severity = "medium"
$StigID = "WN22-DC-000240"
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
