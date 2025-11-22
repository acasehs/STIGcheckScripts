<#
.SYNOPSIS
    STIG Check: V-205914

.DESCRIPTION
    Severity: high
    Rule Title: Windows Server 2019 must not allow anonymous enumeration of Security Account Manager (SAM) accounts.
    STIG ID: WN19-SO-000220
    STIG Version: Windows Server 2019 v2r7
    Requires Elevation: Yes (registry read may require admin)
    Third-Party Tools: None (uses PowerShell Get-ItemProperty)

.NOTES
    AUTO-GENERATED: 2025-11-22 04:41:55
    Based on template: registry check

.PARAMETER ConfigFile
    Path to JSON configuration file

.PARAMETER OutputJson
    Path to output JSON results file

.EXAMPLE
    .\V-205914.ps1
    .\V-205914.ps1 -ConfigFile stig-config.json
    .\V-205914.ps1 -ConfigFile stig-config.json -OutputJson results.json
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$ConfigFile,

    [Parameter(Mandatory=$false)]
    [string]$OutputJson,

    [Parameter(Mandatory=$false)]
    [switch]$Force
)

# Global variables
$VulnID = "V-205914"
$Severity = "high"
$StigID = "WN19-SO-000220"
$RuleTitle = "Windows Server 2019 must not allow anonymous enumeration of Security Account Manager (SAM) accounts."
$StigVersion = "Windows Server 2019 v2r7"

# Registry check implementation - Manual review required
$RegistryPath = "HKLM:\SOFTWARE\Policies"  # Placeholder - verify against STIG
$ValueName = "RequiredSetting"  # Placeholder - verify against STIG
$ExpectedValue = 1  # Placeholder - verify against STIG
$Status = "Not_Reviewed"  # Manual review required
$FindingDetails = @("Registry check requires manual validation against STIG requirements")

$Status = "Not Checked"
$FindingDetails = @()
$Timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")

# Load configuration if provided
if ($ConfigFile -and (Test-Path $ConfigFile)) {
    try {
        $Config = Get-Content $ConfigFile | ConvertFrom-Json
        Write-Host "INFO: Loaded configuration from $ConfigFile"
    } catch {
        Write-Warning "Failed to load configuration file: $_"
    }
}

# Function to check registry value
function Test-RegistryValue {
    param(
        [string]$Path,
        [string]$Name
    )

    try {
        $value = Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop
        return @{
            Exists = $true
            Value = $value.$Name
        }
    } catch {
        return @{
            Exists = $false
            Value = $null
        }
    }
}

# Main check logic
try {
    $regCheck = Test-RegistryValue -Path $RegistryPath -Name $ValueName

    if ($regCheck.Exists) {
        if ($regCheck.Value -eq $ExpectedValue) {
            $Status = "NotAFinding"
            $FindingDetails += @{
                registry_path = $RegistryPath
                value_name = $ValueName
                actual_value = $regCheck.Value
                expected_value = $ExpectedValue
                status = "PASS"
                reason = "Registry value matches expected configuration"
            }
            $exitCode = 0
        } else {
            $Status = "Open"
            $FindingDetails += @{
                registry_path = $RegistryPath
                value_name = $ValueName
                actual_value = $regCheck.Value
                expected_value = $ExpectedValue
                status = "FAIL"
                reason = "Registry value does not match expected configuration"
            }
            $exitCode = 1
        }
    } else {
        $Status = "Open"
        $FindingDetails += @{
            registry_path = $RegistryPath
            value_name = $ValueName
            status = "FAIL"
            reason = "Registry value does not exist"
        }
        $exitCode = 1
    }
} catch {
    $Status = "Error"
    $FindingDetails += @{
        error = $_.Exception.Message
    }
    $exitCode = 3
}

# Output results
$result = @{
    vuln_id = $VulnID
    severity = $Severity
    stig_id = $StigID
    stig_version = $StigVersion
    rule_title = $RuleTitle
    status = $Status
    finding_details = $FindingDetails
    timestamp = $Timestamp
    requires_elevation = $true
    third_party_tools = "None (uses PowerShell)"
    check_method = "PowerShell - Get-ItemProperty"
    config_file = if ($ConfigFile) { $ConfigFile } else { "None (using defaults)" }
    exit_code = $exitCode
}

if ($OutputJson) {
    $result | ConvertTo-Json -Depth 10 | Out-File -FilePath $OutputJson -Encoding UTF8
    Write-Host "Results written to: $OutputJson"
}

# Print human-readable results
Write-Host ""
Write-Host "=" * 80
Write-Host "STIG Check: $VulnID - $StigID"
Write-Host "STIG Version: $StigVersion"
Write-Host "Severity: $($Severity.ToUpper())"
Write-Host "=" * 80
Write-Host "Rule: $RuleTitle"
Write-Host "Status: $Status"
Write-Host "Timestamp: $Timestamp"
Write-Host ""

exit $exitCode
