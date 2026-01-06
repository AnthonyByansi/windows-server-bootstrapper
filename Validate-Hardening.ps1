<#
.SYNOPSIS
    Validate Server Hardening

.DESCRIPTION
    Validates current hardening status against a profile

.PARAMETER Profile
    Profile to validate against (Basic, Moderate, Strict)

.EXAMPLE
    .\Validate-Hardening.ps1 -Profile Moderate
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [ValidateSet('Basic', 'Moderate', 'Strict')]
    [string]$Profile = 'Moderate'
)

#Requires -Version 5.1
#Requires -RunAsAdministrator

$ScriptRoot = $PSScriptRoot
$ModulePath = Join-Path $ScriptRoot "Modules"

# Import modules
Import-Module (Join-Path $ModulePath "Validation.psm1") -Force
Import-Module (Join-Path $ModulePath "Reporting.psm1") -Force

# Create simple logging function
function Write-Log {
    param(
        [string]$Message,
        [string]$Level = 'Info'
    )
    
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $color = switch ($Level) {
        'Info' { 'Cyan' }
        'Success' { 'Green' }
        'Warning' { 'Yellow' }
        'Error' { 'Red' }
        default { 'White' }
    }
    
    Write-Host "[$timestamp] $Message" -ForegroundColor $color
}

Write-Host ""
Write-Host "╔════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║          HARDENING VALIDATION UTILITY                         ║" -ForegroundColor Cyan
Write-Host "╚════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

Write-Log "Validating against profile: $Profile" -Level Info
Write-Host ""

# Run validation
$results = Invoke-ValidationChecks -Profile $Profile

# Display results
Write-Host ""
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "                    VALIDATION RESULTS                          " -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""

$totalChecks = 0
$passedChecks = 0
$failedChecks = 0
$warningChecks = 0

foreach ($category in $results.Categories.Values) {
    Write-Host "$($category.Category):" -ForegroundColor Yellow
    
    foreach ($check in $category.Checks) {
        $totalChecks++
        
        $symbol = switch ($check.Status) {
            'Pass' { '✓'; $passedChecks++ }
            'Fail' { '✗'; $failedChecks++ }
            'Warning' { '⚠'; $warningChecks++ }
            default { '?'; $warningChecks++ }
        }
        
        $color = switch ($check.Status) {
            'Pass' { 'Green' }
            'Fail' { 'Red' }
            'Warning' { 'Yellow' }
            default { 'Gray' }
        }
        
        Write-Host "  $symbol " -ForegroundColor $color -NoNewline
        Write-Host "$($check.Name): " -NoNewline
        Write-Host "$($check.Actual)" -ForegroundColor $color
    }
    
    Write-Host ""
}

Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "                        SUMMARY                                 " -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""
Write-Host "Total Checks:   $totalChecks" -ForegroundColor White
Write-Host "Passed:         $passedChecks" -ForegroundColor Green
Write-Host "Failed:         $failedChecks" -ForegroundColor Red
Write-Host "Warnings:       $warningChecks" -ForegroundColor Yellow
Write-Host ""

$compliancePercent = if ($totalChecks -gt 0) {
    [math]::Round(($passedChecks / $totalChecks) * 100, 1)
} else { 0 }

Write-Host "Compliance:     $compliancePercent%" -ForegroundColor $(if ($compliancePercent -ge 80) { 'Green' } elseif ($compliancePercent -ge 60) { 'Yellow' } else { 'Red' })
Write-Host "Overall Status: $($results.OverallStatus)" -ForegroundColor $(if ($results.OverallStatus -eq 'Pass') { 'Green' } elseif ($results.OverallStatus -eq 'Warning') { 'Yellow' } else { 'Red' })
Write-Host ""

# Generate report
$reportPath = Join-Path $ScriptRoot "Reports\Validation-$(Get-Date -Format 'yyyy-MM-dd-HHmm').html"
if (-not (Test-Path (Join-Path $ScriptRoot "Reports"))) {
    New-Item -Path (Join-Path $ScriptRoot "Reports") -ItemType Directory -Force | Out-Null
}

New-ComplianceReport -Results $results -ReportPath $reportPath -ChangesMade @()
Write-Log "Detailed report saved to: $reportPath" -Level Success

# Open report
Start-Process $reportPath

Write-Host ""
