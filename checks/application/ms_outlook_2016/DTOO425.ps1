<#
.SYNOPSIS
    DTOO425 - Text in Outlook that represents internet and network paths must not be automatically turned into hyperlinks.

.DESCRIPTION
    STIG ID: DTOO425
    Rule Title: Text in Outlook that represents internet and network paths must not be automatically turned into hyperlinks.
    Severity: medium
    Vuln ID: V-251872
    Rule ID: SV-251872r812968

    This script checks Microsoft Outlook 2016 configuration compliance.

.PARAMETER Config
    Path to JSON configuration file for customized check parameters.

.PARAMETER OutputJson
    Output results in JSON format.

.PARAMETER Help
    Display this help message.

.EXAMPLE
    .\DTOO425.ps1
    Run the check with default parameters

.EXAMPLE
    .\DTOO425.ps1 -Config custom_config.json
    Run the check with custom configuration

.EXAMPLE
    .\DTOO425.ps1 -OutputJson
    Run the check and output results in JSON format

.NOTES
    Exit Codes:
    0 = PASS (Compliant)
    1 = FAIL (Non-Compliant)
    2 = N/A (Not Applicable)
    3 = ERROR (Script execution error)

    Registry Check:
    Key: HKCU\software\policies\Microsoft\office\16.0\outlook\options\autoformat_x000D_
    Value: pgrfafo_25_1
    Type: REG_DWORD
    Expected: 0
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$Config,

    [Parameter(Mandatory=$false)]
    [switch]$OutputJson,

    [Parameter(Mandatory=$false)]
    [switch]$Help
)

# Display help if requested
if ($Help) {
    Get-Help $MyInvocation.MyCommand.Path -Detailed
    exit 0
}

# Initialize result object
$result = @{
    STIG_ID = "DTOO425"
    Rule_Title = "Text in Outlook that represents internet and network paths must not be automatically turned into hyperlinks."
    Severity = "medium"
    Status = "Not_Reviewed"
    Finding_Details = ""
    Comments = ""
}

try {
    # Load custom configuration if provided
    $customConfig = $null
    if ($Config -and (Test-Path $Config)) {
        try {
            $customConfig = Get-Content $Config -Raw | ConvertFrom-Json
            Write-Verbose "Loaded custom configuration from $Config"
        }
        catch {
            Write-Warning "Failed to load configuration file: $_"
        }
    }

    # Check registry setting
    $regPath = "HKCU:\software\policies\Microsoft\office\16.0\outlook\options\autoformat_x000D_"
    $regValueName = "pgrfafo_25_1"
    $expectedValue = 0

    # TODO: Implement registry check logic
    # Example implementation:
    # if (Test-Path $regPath) {
    #     $regValue = Get-ItemProperty -Path $regPath -Name $regValueName -ErrorAction SilentlyContinue
    #     if ($regValue -and $regValue.$regValueName -eq $expectedValue) {
    #         $result.Status = "PASS"
    #         $result.Finding_Details = "Registry setting is compliant."
    #     }
    #     else {
    #         $result.Status = "FAIL"
    #         $result.Finding_Details = "Registry setting is not compliant."
    #     }
    # }
    # else {
    #     $result.Status = "FAIL"
    #     $result.Finding_Details = "Registry key not found."
    # }

    # Placeholder - Mark as Not Reviewed until implementation is complete
    $result.Status = "Not_Reviewed"
    $result.Comments = "Automated check not yet implemented - requires Office domain expertise"
    $result.Finding_Details = "This check requires registry validation"

}
catch {
    $result.Status = "ERROR"
    $result.Finding_Details = "Error: $($_.Exception.Message)"
    $result.Comments = "Script execution failed"
}

# Output results
if ($OutputJson) {
    $result | ConvertTo-Json
}
else {
    Write-Host "STIG ID: $($result.STIG_ID)"
    Write-Host "Status: $($result.Status)"
    Write-Host "Finding Details: $($result.Finding_Details)"
    if ($result.Comments) {
        Write-Host "Comments: $($result.Comments)"
    }
}

# Exit with appropriate code
switch ($result.Status) {
    "PASS" { exit 0 }
    "FAIL" { exit 1 }
    "Not_Reviewed" { exit 2 }
    "N/A" { exit 2 }
    "ERROR" { exit 3 }
    default { exit 3 }
}
