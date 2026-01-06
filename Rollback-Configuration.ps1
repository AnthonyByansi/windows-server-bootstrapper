<#
.SYNOPSIS
    Rollback Configuration Script

.DESCRIPTION
    Restores previous configuration from a backup

.PARAMETER BackupPath
    Path to the backup directory to restore

.EXAMPLE
    .\Rollback-Configuration.ps1 -BackupPath ".\Backups\Backup-2026-01-06-1430"
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory = $true)]
    [string]$BackupPath
)

#Requires -Version 5.1
#Requires -RunAsAdministrator

$ErrorActionPreference = "Stop"

Write-Host ""
Write-Host "╔════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║          CONFIGURATION ROLLBACK UTILITY                       ║" -ForegroundColor Cyan
Write-Host "╚════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

if (-not (Test-Path $BackupPath)) {
    Write-Host "✗ Backup path not found: $BackupPath" -ForegroundColor Red
    exit 1
}

Write-Host "Backup location: $BackupPath" -ForegroundColor Cyan
Write-Host ""

# Show backup contents
Write-Host "Backup contains:" -ForegroundColor Yellow
Get-ChildItem -Path $BackupPath | ForEach-Object {
    Write-Host "  - $($_.Name)" -ForegroundColor Gray
}
Write-Host ""

# Confirm rollback
$confirmation = Read-Host "Are you sure you want to rollback to this configuration? (yes/no)"
if ($confirmation -ne "yes") {
    Write-Host "Rollback cancelled." -ForegroundColor Yellow
    exit 0
}

Write-Host ""
Write-Host "Starting rollback..." -ForegroundColor Cyan

try {
    # Restore security policy
    $secpol = Join-Path $BackupPath "SecurityPolicy.inf"
    if (Test-Path $secpol) {
        Write-Host "  Restoring security policy..." -ForegroundColor Gray
        secedit /configure /db secedit.sdb /cfg $secpol /quiet
        Write-Host "  ✓ Security policy restored" -ForegroundColor Green
    }
    
    # Restore firewall rules
    $firewall = Join-Path $BackupPath "FirewallRules.wfw"
    if (Test-Path $firewall) {
        Write-Host "  Restoring firewall rules..." -ForegroundColor Gray
        netsh advfirewall import $firewall | Out-Null
        Write-Host "  ✓ Firewall rules restored" -ForegroundColor Green
    }
    
    # Restore registry keys
    Get-ChildItem -Path $BackupPath -Filter "*.reg" | ForEach-Object {
        Write-Host "  Restoring registry: $($_.Name)..." -ForegroundColor Gray
        reg import $_.FullName /y | Out-Null
        Write-Host "  ✓ Registry key restored" -ForegroundColor Green
    }
    
    # Restore services
    $services = Join-Path $BackupPath "Services.csv"
    if (Test-Path $services) {
        Write-Host "  Restoring service states..." -ForegroundColor Gray
        $serviceList = Import-Csv $services
        foreach ($svc in $serviceList) {
            try {
                $service = Get-Service -Name $svc.Name -ErrorAction SilentlyContinue
                if ($service) {
                    Set-Service -Name $svc.Name -StartupType $svc.StartType -ErrorAction SilentlyContinue
                }
            } catch {
                # Continue on service restore errors
            }
        }
        Write-Host "  ✓ Service states restored" -ForegroundColor Green
    }
    
    Write-Host ""
    Write-Host "✓ Rollback completed successfully!" -ForegroundColor Green
    Write-Host ""
    Write-Host "⚠ A system reboot is recommended to ensure all changes take effect." -ForegroundColor Yellow
    Write-Host ""
    
} catch {
    Write-Host ""
    Write-Host "✗ Rollback failed: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host ""
    exit 1
}
