# STIG Check: V-214312
# STIG ID: AS24-W1-000130
# Severity: medium
# Rule Title: An Apache web server, behind a load balancer or proxy server, must produce log records containing the client IP information as the source and destination and not the load balancer or proxy IP information with each event.
#
# Description:
# Apache web server logging capability is critical for accurate forensic analysis. Without sufficient and accurate information, a correct replay of the events cannot be determined.  Ascertaining the correct source, e.g., source IP, of the events is important during forensic analysis. Correctly determi...
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
$VulnID = "V-214312"
$StigID = "AS24-W1-000130"
$Severity = "medium"
$RuleTitle = "An Apache web server, behind a load balancer or proxy server, must produce log records containing the client IP information as the source and destination and not the load balancer or proxy IP information with each event."

# Show help
if ($Help) {
    Write-Host "Usage: .\V-214312.ps1 [-ConfigFile FILE] [-OutputJson FILE] [-Help]"
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
    # Interview the System Administrator to review the configuration of the Apache web server architecture and determine if inbound web traffic is passed through a proxy.  If the Apache web server is receiving inbound web traffic through a proxy, the audit logs must be reviewed to determine if correct source information is being passed through by the proxy server.  View Apache log files as configured in `"httpd.conf`" files.  When the log file is displayed, review source IP information in log entries an...
    #
    # Fix Text:
    # Access the proxy server through which inbound web traffic is passed and configure settings to pass web traffic to the Apache web server transparently.

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
