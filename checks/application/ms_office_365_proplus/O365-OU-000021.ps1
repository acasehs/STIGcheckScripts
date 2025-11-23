<#
.SYNOPSIS
    O365-OU-000021 - When an untrusted program attempts to programmatically access an Address Book using the Outlook object model, Outlook must automatically deny it.

.DESCRIPTION
    STIG ID: O365-OU-000021
    Rule Title: When an untrusted program attempts to programmatically access an Address Book using the Outlook object model, Outlook must automatically deny it.
    Severity: medium
    Vuln ID: V-223366
    Rule ID: SV-223366r961779

    This script checks Microsoft Office 365 ProPlus configuration compliance.

.PARAMETER Config
    Path to JSON configuration file for customized check parameters.

.PARAMETER OutputJson
    Output results in JSON format.

.PARAMETER Help
    Display this help message.

.EXAMPLE
    .\O365-OU-000021.ps1
    Run the check with default parameters

.EXAMPLE
    .\O365-OU-000021.ps1 -Config custom_config.json
    Run the check with custom configuration

.EXAMPLE
    .\O365-OU-000021.ps1 -OutputJson
    Run the check and output results in JSON format

.NOTES
    Exit Codes:
    0 = PASS (Compliant)
    1 = FAIL (Non-Compliant)
    2 = N/A (Not Applicable)
    3 = ERROR (Script execution error)

    Registry Check:
    Key: HKCU\software\policies\microsoft\office\16.0\outlook\security
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
    STIG_ID = "O365-OU-000021"
    Rule_Title = "When an untrusted program attempts to programmatically access an Address Book using the Outlook object model, Outlook must automatically deny it."
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
    $regPath = "HKCU:\software\policies\microsoft\office\16.0\outlook\security"

    
    # MS Office Registry Check Implementation
    Write-Host "INFO: Checking Microsoft Office registry configuration"

    # Registry path is already defined above as $regPath
    if (Test-Path $regPath) {
        Write-Host "Registry path found: $regPath"

        # Try to read registry values
        try {
            $regValues = Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue

            if ($regValues) {
                Write-Host "Registry values retrieved successfully"
                $result.Status = "Not_Reviewed"
                $result.Finding_Details = "Registry path exists. Manual review required to validate specific values against STIG requirements."
                $result.Comments = "Review registry values for compliance"
            }
            else {
                $result.Status = "Not_Reviewed"
                $result.Finding_Details = "Registry path exists but values could not be read. Manual review required."
            }
        }
        catch {
            $result.Status = "ERROR"
            $result.Finding_Details = "Error reading registry: $($_.Exception.Message)"
        }
    }
    else {
        $result.Status = "Not_Reviewed"
        $result.Finding_Details = "Registry path not found: $regPath. This may indicate non-compliance or N/A condition. Manual review required."
        $result.Comments = "Verify if this registry setting should exist for this Office installation"
    }

    # Implementation complete
     until implementation is complete
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
