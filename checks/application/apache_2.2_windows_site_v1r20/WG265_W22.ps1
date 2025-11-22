<#
.SYNOPSIS
    STIG Check: V-6373
    Severity: low

.DESCRIPTION
    Rule Title: The required DoD banner page must be displayed to authenticated users accessing a DoD private website.
    STIG ID: WG265 W22
    Rule ID: SV-33137r2

    A consent banner will be in place to make prospective entrants aware that the website they are about to enter is a DoD web site and their activity is subject to monitoring. The document, DoDI 8500.01, establishes the policy on the use of DoD information systems. It requires the use of a standard Notice and Consent Banner and standard text to be included in user agreements. The requirement for the banner is for websites with security and access controls. These are restricted and not publicly acce

.PARAMETER Config
    Configuration file path (JSON)

.PARAMETER OutputJson
    Output results in JSON format to specified file

.OUTPUTS
    Exit Codes:
        0 = Check Passed (Compliant)
        1 = Check Failed (Finding)
        2 = Check Not Applicable
        3 = Check Error
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$Config,

    [Parameter(Mandatory=$false)]
    [string]$OutputJson
)

# Configuration
$VULN_ID = "V-6373"
$STIG_ID = "WG265 W22"
$SEVERITY = "low"
$TIMESTAMP = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")

# Load configuration if provided
if ($Config -and (Test-Path $Config)) {
    $ConfigData = Get-Content $Config | ConvertFrom-Json
}

################################################################################
# MAIN CHECK LOGIC
################################################################################

try {
SVC="or"

    running=$(systemctl is-active "$SVC" 2>/dev/null)
    enabled=$(systemctl is-enabled "$SVC" 2>/dev/null)

    if [[ "$running" == "active" ]] && [[ "$enabled" == "enabled" ]]; then
        echo "FAIL: Service should not be running"
        [[ -n "$OUTPUT_JSON" ]] && output_json "FAIL" "Should not run" "$SVC"
        exit 1
    else
        echo "PASS: Service disabled (compliant)"
        [[ -n "$OUTPUT_JSON" ]] && output_json "PASS" "Disabled" "$SVC"
        exit 0
    fi


} catch {
    Write-Error $_.Exception.Message

    if ($OutputJson) {
        @{
            vuln_id = $VULN_ID
            stig_id = $STIG_ID
            severity = $SEVERITY
            status = "ERROR"
            message = $_.Exception.Message
            timestamp = $TIMESTAMP
        } | ConvertTo-Json | Out-File $OutputJson
    }

    exit 3
}
