<#
.SYNOPSIS
    Windows Server Bootstrap & Hardening Automation

.DESCRIPTION
    Comprehensive automation framework for bootstrapping and hardening Windows Server
    environments with CIS-inspired security baselines.

.PARAMETER HardeningProfile
    Security hardening profile to apply: Basic, Moderate, or Strict

.PARAMETER Roles
    Array of server roles to install: IIS, DNS, ADDS, HyperV, Clustering

.PARAMETER SkipHardening
    Skip security hardening and only install roles

.PARAMETER SkipFirewall
    Skip firewall configuration

.PARAMETER SkipAuditPolicy
    Skip audit policy configuration

.PARAMETER ReportOnly
    Generate compliance report without making changes

.PARAMETER WhatIf
    Show what would be done without making changes

.PARAMETER BackupOnly
    Only create backup of current configuration

.EXAMPLE
    .\Bootstrap-Server.ps1
    Run with default moderate hardening profile

.EXAMPLE
    .\Bootstrap-Server.ps1 -HardeningProfile Strict -Roles IIS,DNS
    Install IIS and DNS with strict hardening

.EXAMPLE
    .\Bootstrap-Server.ps1 -ReportOnly
    Generate compliance report only

.NOTES
    Author: Server Bootstrap Project
    Version: 1.0.0
    Requires: PowerShell 5.1+, Administrator privileges
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory = $false)]
    [ValidateSet('Basic', 'Moderate', 'Strict')]
    [string]$HardeningProfile = 'Moderate',

    [Parameter(Mandatory = $false)]
    [ValidateSet('IIS', 'DNS', 'ADDS', 'HyperV', 'Clustering')]
    [string[]]$Roles,

    [Parameter(Mandatory = $false)]
    [switch]$SkipHardening,

    [Parameter(Mandatory = $false)]
    [switch]$SkipFirewall,

    [Parameter(Mandatory = $false)]
    [switch]$SkipAuditPolicy,

    [Parameter(Mandatory = $false)]
    [switch]$ReportOnly,

    [Parameter(Mandatory = $false)]
    [switch]$BackupOnly
)

#Requires -Version 5.1
#Requires -RunAsAdministrator

# Script variables
$Script:ScriptRoot = $PSScriptRoot
$Script:StartTime = Get-Date
$Script:LogFile = Join-Path $ScriptRoot "Logs\Bootstrap-$(Get-Date -Format 'yyyy-MM-dd-HHmm').log"
$Script:BackupPath = Join-Path $ScriptRoot "Backups\Backup-$(Get-Date -Format 'yyyy-MM-dd-HHmm')"
$Script:ReportPath = Join-Path $ScriptRoot "Reports\Report-$(Get-Date -Format 'yyyy-MM-dd-HHmm').html"
$Script:ErrorCount = 0
$Script:WarningCount = 0
$Script:ChangesMade = @()

# Initialize directories
$Directories = @('Logs', 'Backups', 'Reports', 'Config', 'Modules')
foreach ($dir in $Directories) {
    $path = Join-Path $ScriptRoot $dir
    if (-not (Test-Path $path)) {
        New-Item -Path $path -ItemType Directory -Force | Out-Null
    }
}

# Import modules
$ModulePath = Join-Path $ScriptRoot "Modules"
$Modules = @('ServerRoles', 'SecurityHardening', 'FirewallConfig', 'AuditConfig', 'RemoteAccess', 'Validation', 'Reporting')

foreach ($module in $Modules) {
    $modulePath = Join-Path $ModulePath "$module.psm1"
    if (Test-Path $modulePath) {
        Import-Module $modulePath -Force -ErrorAction Stop
    }
}

#region Logging Functions

function Write-Log {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet('Info', 'Warning', 'Error', 'Success')]
        [string]$Level = 'Info'
    )
    
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $logMessage = "[$timestamp] [$Level] $Message"
    
    # Console output with colors
    switch ($Level) {
        'Info'    { Write-Host $logMessage -ForegroundColor Cyan }
        'Warning' { Write-Host $logMessage -ForegroundColor Yellow; $Script:WarningCount++ }
        'Error'   { Write-Host $logMessage -ForegroundColor Red; $Script:ErrorCount++ }
        'Success' { Write-Host $logMessage -ForegroundColor Green }
    }
    
    # File output
    Add-Content -Path $Script:LogFile -Value $logMessage
}

function Write-Banner {
    param([string]$Text)
    
    $banner = @"

╔════════════════════════════════════════════════════════════════╗
║  $($Text.PadRight(60))  ║
╚════════════════════════════════════════════════════════════════╝

"@
    Write-Host $banner -ForegroundColor Cyan
    Add-Content -Path $Script:LogFile -Value $banner
}

#endregion

#region Pre-Flight Checks

function Invoke-PreFlightChecks {
    Write-Banner "PRE-FLIGHT CHECKS"
    Write-Log "Starting pre-flight validation..." -Level Info
    
    $checks = @()
    
    # Check PowerShell version
    $psVersion = $PSVersionTable.PSVersion
    if ($psVersion.Major -ge 5) {
        Write-Log "✓ PowerShell version: $psVersion" -Level Success
        $checks += $true
    } else {
        Write-Log "✗ PowerShell version $psVersion is too old. Requires 5.1+" -Level Error
        $checks += $false
    }
    
    # Check administrator privileges
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if ($isAdmin) {
        Write-Log "✓ Running with Administrator privileges" -Level Success
        $checks += $true
    } else {
        Write-Log "✗ Must run as Administrator" -Level Error
        $checks += $false
    }
    
    # Check Windows Server OS
    $os = Get-CimInstance -ClassName Win32_OperatingSystem
    if ($os.ProductType -ne 1) {
        Write-Log "✓ Windows Server detected: $($os.Caption)" -Level Success
        $checks += $true
    } else {
        Write-Log "⚠ Running on client OS: $($os.Caption)" -Level Warning
        $checks += $true
    }
    
    # Check disk space
    $systemDrive = $env:SystemDrive
    $drive = Get-PSDrive -Name $systemDrive.Trim(':')
    $freeSpaceGB = [math]::Round($drive.Free / 1GB, 2)
    if ($freeSpaceGB -gt 10) {
        Write-Log "✓ Free disk space: $freeSpaceGB GB" -Level Success
        $checks += $true
    } else {
        Write-Log "⚠ Low disk space: $freeSpaceGB GB" -Level Warning
        $checks += $true
    }
    
    # Check network connectivity
    try {
        $connection = Test-NetConnection -ComputerName "microsoft.com" -Port 443 -InformationLevel Quiet -WarningAction SilentlyContinue
        if ($connection) {
            Write-Log "✓ Internet connectivity verified" -Level Success
            $checks += $true
        } else {
            Write-Log "⚠ No internet connectivity detected" -Level Warning
            $checks += $true
        }
    } catch {
        Write-Log "⚠ Could not verify internet connectivity" -Level Warning
        $checks += $true
    }
    
    # Check for pending reboot
    $rebootPending = Test-PendingReboot
    if (-not $rebootPending) {
        Write-Log "✓ No pending reboot detected" -Level Success
        $checks += $true
    } else {
        Write-Log "⚠ Pending reboot detected - recommend rebooting first" -Level Warning
        $checks += $true
    }
    
    if ($checks -contains $false) {
        Write-Log "Pre-flight checks failed. Please resolve errors before continuing." -Level Error
        return $false
    }
    
    Write-Log "All pre-flight checks passed!" -Level Success
    return $true
}

function Test-PendingReboot {
    $rebootPending = $false
    
    # Check CBS
    if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending") {
        $rebootPending = $true
    }
    
    # Check Windows Update
    if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired") {
        $rebootPending = $true
    }
    
    # Check PendingFileRenameOperations
    $fileRename = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name PendingFileRenameOperations -ErrorAction SilentlyContinue
    if ($fileRename) {
        $rebootPending = $true
    }
    
    return $rebootPending
}

#endregion

#region Main Execution

function Invoke-ServerBootstrap {
    Write-Banner "WINDOWS SERVER BOOTSTRAP & HARDENING AUTOMATION v1.0.0"
    Write-Log "Started at: $Script:StartTime" -Level Info
    Write-Log "Hardening Profile: $HardeningProfile" -Level Info
    Write-Log "Log file: $Script:LogFile" -Level Info
    
    # Pre-flight checks
    if (-not (Invoke-PreFlightChecks)) {
        Write-Log "Bootstrap aborted due to pre-flight check failures" -Level Error
        return
    }
    
    # Backup current configuration
    if (-not $ReportOnly) {
        Write-Banner "BACKUP CURRENT CONFIGURATION"
        Write-Log "Creating backup at: $Script:BackupPath" -Level Info
        Backup-CurrentConfiguration -BackupPath $Script:BackupPath
        
        if ($BackupOnly) {
            Write-Log "Backup completed. Exiting as BackupOnly was specified." -Level Info
            return
        }
    }
    
    # Install server roles
    if ($Roles -and -not $ReportOnly) {
        Write-Banner "INSTALLING SERVER ROLES & FEATURES"
        foreach ($role in $Roles) {
            Write-Log "Installing role: $role" -Level Info
            try {
                Install-ServerRole -Role $role -WhatIf:$WhatIfPreference
                $Script:ChangesMade += "Installed role: $role"
            } catch {
                Write-Log "Failed to install role $role : $($_.Exception.Message)" -Level Error
            }
        }
    }
    
    # Apply security hardening
    if (-not $SkipHardening -and -not $ReportOnly) {
        Write-Banner "APPLYING SECURITY HARDENING - $HardeningProfile Profile"
        try {
            Apply-SecurityHardening -Profile $HardeningProfile -WhatIf:$WhatIfPreference
            $Script:ChangesMade += "Applied $HardeningProfile security hardening"
        } catch {
            Write-Log "Failed to apply security hardening: $($_.Exception.Message)" -Level Error
        }
    }
    
    # Configure firewall
    if (-not $SkipFirewall -and -not $ReportOnly) {
        Write-Banner "CONFIGURING FIREWALL RULES"
        try {
            Set-FirewallConfiguration -Roles $Roles -WhatIf:$WhatIfPreference
            $Script:ChangesMade += "Configured firewall rules"
        } catch {
            Write-Log "Failed to configure firewall: $($_.Exception.Message)" -Level Error
        }
    }
    
    # Configure audit policies
    if (-not $SkipAuditPolicy -and -not $ReportOnly) {
        Write-Banner "CONFIGURING AUDIT POLICIES"
        try {
            Set-AuditConfiguration -Profile $HardeningProfile -WhatIf:$WhatIfPreference
            $Script:ChangesMade += "Configured audit policies"
        } catch {
            Write-Log "Failed to configure audit policies: $($_.Exception.Message)" -Level Error
        }
    }
    
    # Configure remote access (WinRM, RDP)
    if (-not $SkipHardening -and -not $ReportOnly) {
        Write-Banner "HARDENING REMOTE ACCESS (WinRM & RDP)"
        try {
            Set-RemoteAccessConfiguration -Profile $HardeningProfile -WhatIf:$WhatIfPreference
            $Script:ChangesMade += "Hardened remote access configuration"
        } catch {
            Write-Log "Failed to configure remote access: $($_.Exception.Message)" -Level Error
        }
    }
    
    # Post-installation validation
    Write-Banner "VALIDATION & REPORTING"
    $validationResults = Invoke-ValidationChecks -Profile $HardeningProfile
    
    # Generate report
    Write-Log "Generating compliance report..." -Level Info
    New-ComplianceReport -Results $validationResults -ReportPath $Script:ReportPath -ChangesMade $Script:ChangesMade
    Write-Log "Report generated: $Script:ReportPath" -Level Success
    
    # Summary
    Write-Banner "EXECUTION SUMMARY"
    $duration = (Get-Date) - $Script:StartTime
    Write-Log "Execution time: $($duration.ToString('hh\:mm\:ss'))" -Level Info
    Write-Log "Changes made: $($Script:ChangesMade.Count)" -Level Info
    Write-Log "Warnings: $Script:WarningCount" -Level $(if ($Script:WarningCount -gt 0) { 'Warning' } else { 'Info' })
    Write-Log "Errors: $Script:ErrorCount" -Level $(if ($Script:ErrorCount -gt 0) { 'Error' } else { 'Info' })
    
    if (-not $ReportOnly -and -not $WhatIfPreference) {
        Write-Log "" -Level Info
        Write-Log "Backup location: $Script:BackupPath" -Level Info
        Write-Log "To rollback changes, run: .\Rollback-Configuration.ps1 -BackupPath '$Script:BackupPath'" -Level Info
        
        $rebootNeeded = Test-PendingReboot
        if ($rebootNeeded) {
            Write-Log "" -Level Warning
            Write-Log "⚠ A system reboot is required to complete the configuration" -Level Warning
        }
    }
    
    Write-Log "Bootstrap completed!" -Level Success
    
    # Open report in browser
    if (Test-Path $Script:ReportPath) {
        Start-Process $Script:ReportPath
    }
}

#endregion

# Execute main function
try {
    Invoke-ServerBootstrap
} catch {
    Write-Log "Fatal error: $($_.Exception.Message)" -Level Error
    Write-Log $_.ScriptStackTrace -Level Error
    exit 1
}
