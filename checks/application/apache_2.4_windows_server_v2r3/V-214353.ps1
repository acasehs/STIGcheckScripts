# STIG Check: V-214353
# STIG ID: AS24-W1-000820
# Severity: medium
# Rule Title: The Apache web server must be protected from being stopped by a non-privileged user.
#
# Description:
# An attacker has at least two reasons to stop a web server. The first is to cause a denial of service (DoS), and the second is to put in place changes the attacker made to the web server configuration.  To prohibit an attacker from stopping the Apache web server, the process ID (pid) of the web serve...
#
# Tool Priority: PowerShell (1st priority) > Python (fallback)
# Exit Codes: 0=PASS, 1=FAIL, 2=N/A, 3=ERROR

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$ConfigFile,

    [Parameter(Mandatory=$false)]
    [string]$OutputJson,

    [Parameter(Mandatory=$false)]
    [switch]$Help
)

# Configuration
$VulnID = "V-214353"
$StigID = "AS24-W1-000820"
$Severity = "medium"
$RuleTitle = "The Apache web server must be protected from being stopped by a non-privileged user."

# Show help
if ($Help) {
    Write-Host "Usage: .\V-214353.ps1 [-ConfigFile FILE] [-OutputJson FILE] [-Help]"
    Write-Host ""
    Write-Host "Options:"
    Write-Host "  -ConfigFile FILE : Load configuration from FILE (JSON)"
    Write-Host "  -OutputJson FILE : Output results in JSON format to FILE"
    Write-Host "  -Help            : Show this help message"
    Write-Host ""
    Write-Host "Exit Codes:"
    Write-Host "  0 = PASS (Compliant)"
    Write-Host "  1 = FAIL (Finding)"
    Write-Host "  2 = N/A (Not Applicable)"
    Write-Host "  3 = ERROR (Check execution error)"
    exit 0
}

# Load configuration if provided
$config = $null
if ($ConfigFile -and (Test-Path $ConfigFile)) {
    try {
        $config = Get-Content $ConfigFile | ConvertFrom-Json
    } catch {
        Write-Error "ERROR: Failed to load config file: $_"
        exit 3
    }
}

################################################################################
# APACHE HELPER FUNCTIONS
################################################################################

function Get-ApacheConfig {
    # Common Apache installation paths on Windows
    $apachePaths = @(
        "C:\Apache24\bin\httpd.exe",
        "C:\Apache22\bin\httpd.exe",
        "C:\Program Files\Apache Software Foundation\Apache2.4\bin\httpd.exe",
        "C:\Program Files\Apache Software Foundation\Apache2.2\bin\httpd.exe",
        "C:\xampp\apache\bin\httpd.exe"
    )

    foreach ($path in $apachePaths) {
        if (Test-Path $path) {
            try {
                $output = & $path -V 2>$null
                $httpdRoot = ($output | Select-String "HTTPD_ROOT").ToString().Split('"')[1]
                $serverConfig = ($output | Select-String "SERVER_CONFIG_FILE").ToString().Split('"')[1]

                if ($serverConfig -match "^[A-Z]:\\") {
                    return $serverConfig
                } else {
                    return Join-Path $httpdRoot $serverConfig
                }
            } catch {
                continue
            }
        }
    }

    return $null
}

################################################################################
# CHECK IMPLEMENTATION
################################################################################

function Invoke-StigCheck {
    # TODO: Implement Apache check logic based on:
    # Right-click <'Install Path'>\bin\httpd.exe.  Click `"Properties`" from the `"Context`" menu.  Select the `"Security`" tab.  Review the groups and user names.  The following account may have Full control privileges:  TrustedInstaller Web Managers Web Manager designees  The following accounts may have read and execute, or read permissions:  Non Web Manager Administrators ALL APPLICATION PACKAGES (built-in security group) SYSTEM Users  Specific users may be granted read and execute and read permissions. ...
    #
    # Fix Text:
    # Restrict access to the web administration tool to only the Web Manager and the Web Manager's designees.

    Write-Warning "Check not yet implemented - requires Apache domain expertise"
    return @{
        Status = "Not Implemented"
        ExitCode = 2
        FindingDetails = "Check logic not yet implemented - requires Apache domain expertise"
    }
}

################################################################################
# EXECUTE CHECK
################################################################################

try {
    $result = Invoke-StigCheck

    $timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")

    # Prepare output
    $output = @{
        vuln_id = $VulnID
        stig_id = $StigID
        severity = $Severity
        rule_title = $RuleTitle
        status = $result.Status
        finding_details = $result.FindingDetails
        timestamp = $timestamp
        exit_code = $result.ExitCode
    }

    # JSON output if requested
    if ($OutputJson) {
        $output | ConvertTo-Json -Depth 10 | Out-File -FilePath $OutputJson -Encoding UTF8
    }

    # Human-readable output
    Write-Host ""
    Write-Host ("=" * 80)
    Write-Host "STIG Check: $VulnID - $StigID"
    Write-Host "Severity: $($Severity.ToUpper())"
    Write-Host ("=" * 80)
    Write-Host "Rule: $RuleTitle"
    Write-Host "Status: $($result.Status)"
    Write-Host "Timestamp: $timestamp"
    Write-Host ""
    Write-Host ("-" * 80)
    Write-Host "Finding Details:"
    Write-Host ("-" * 80)
    Write-Host $result.FindingDetails
    Write-Host ""
    Write-Host ("=" * 80)
    Write-Host ""

    exit $result.ExitCode

} catch {
    Write-Error "ERROR: $($_.Exception.Message)"

    if ($OutputJson) {
        $errorOutput = @{
            vuln_id = $VulnID
            stig_id = $StigID
            severity = $Severity
            status = "Error"
            finding_details = $_.Exception.Message
            timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
            exit_code = 3
        }
        $errorOutput | ConvertTo-Json -Depth 10 | Out-File -FilePath $OutputJson -Encoding UTF8
    }

    exit 3
}
