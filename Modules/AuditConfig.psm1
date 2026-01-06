<#
.SYNOPSIS
    Audit Configuration Module

.DESCRIPTION
    Configures advanced audit policies and event log settings
#>

function Set-AuditConfiguration {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('Basic', 'Moderate', 'Strict')]
        [string]$Profile
    )
    
    Write-Log "Configuring audit policies - $Profile profile..." -Level Info
    
    # Load audit configuration
    $configPath = Join-Path $PSScriptRoot "..\Config\audit-policies.json"
    if (-not (Test-Path $configPath)) {
        Write-Log "Audit configuration not found: $configPath" -Level Error
        throw "Configuration file not found"
    }
    
    $config = Get-Content $configPath -Raw | ConvertFrom-Json
    $profileConfig = $config.AuditPolicies.$Profile
    
    if (-not $profileConfig) {
        Write-Log "Audit profile $Profile not found in configuration" -Level Error
        throw "Invalid profile"
    }
    
    Write-Log "Profile Description: $($profileConfig.Description)" -Level Info
    
    # Apply audit policies
    Set-AdvancedAuditPolicies -Categories $profileConfig.Categories -WhatIf:$WhatIfPreference
    
    # Configure event logs
    Set-EventLogConfiguration -Config $config.EventLogSettings -WhatIf:$WhatIfPreference
    
    # Apply advanced audit settings
    Set-AdvancedAuditSettings -Config $config.AdvancedAuditSettings -WhatIf:$WhatIfPreference
    
    Write-Log "✓ Audit configuration completed" -Level Success
}

function Set-AdvancedAuditPolicies {
    [CmdletBinding(SupportsShouldProcess)]
    param($Categories)
    
    Write-Log "Applying advanced audit policies..." -Level Info
    
    if ($PSCmdlet.ShouldProcess("Audit Policies", "Configure")) {
        try {
            foreach ($category in $Categories.PSObject.Properties) {
                $categoryName = $category.Name
                Write-Log "  Configuring category: $categoryName" -Level Info
                
                foreach ($subcategory in $category.Value.PSObject.Properties) {
                    $subcategoryName = $subcategory.Name
                    $setting = $subcategory.Value
                    
                    # Build auditpol command
                    $auditSettings = @()
                    if ($setting -match "Success") { $auditSettings += "enable" }
                    if ($setting -match "Failure") { 
                        if ($auditSettings.Count -eq 0) {
                            $auditSettings += "enable"
                        }
                    }
                    
                    # Convert setting to auditpol format
                    $auditValue = switch ($setting) {
                        "Success" { "enable" }
                        "Failure" { "enable" }
                        "Success,Failure" { "enable" }
                        default { "disable" }
                    }
                    
                    try {
                        # Use auditpol to set the policy
                        $result = auditpol /set /subcategory:"$subcategoryName" /success:$auditValue /failure:$auditValue 2>&1
                        
                        if ($LASTEXITCODE -eq 0) {
                            Write-Log "    ✓ $subcategoryName : $setting" -Level Info
                        } else {
                            Write-Log "    ⚠ Failed to set $subcategoryName" -Level Warning
                        }
                        
                    } catch {
                        Write-Log "    ⚠ Error setting $subcategoryName : $($_.Exception.Message)" -Level Warning
                    }
                }
            }
            
            Write-Log "✓ Advanced audit policies applied" -Level Success
            
        } catch {
            Write-Log "Failed to apply audit policies: $($_.Exception.Message)" -Level Error
        }
    }
}

function Set-EventLogConfiguration {
    [CmdletBinding(SupportsShouldProcess)]
    param($Config)
    
    Write-Log "Configuring event logs..." -Level Info
    
    if ($PSCmdlet.ShouldProcess("Event Logs", "Configure")) {
        try {
            foreach ($logConfig in $Config.PSObject.Properties) {
                $logName = $logConfig.Name
                $settings = $logConfig.Value
                
                # Configure log size and retention
                $log = Get-WinEvent -ListLog $logName -ErrorAction SilentlyContinue
                if ($log) {
                    $log.MaximumSizeInBytes = $settings.MaximumSize
                    $log.IsEnabled = $true
                    
                    # Set retention
                    if ($settings.RetentionDays -eq 0) {
                        $log.LogMode = 'Circular'
                    } else {
                        $log.LogMode = 'AutoBackup'
                    }
                    
                    $log.SaveChanges()
                    Write-Log "  Configured $logName log: Size=$($settings.MaximumSize/1KB)KB, Retention=$($settings.RetentionDays) days" -Level Info
                }
                
                # Restrict guest access
                if ($settings.RestrictGuestAccess) {
                    $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\$logName"
                    if (Test-Path $registryPath) {
                        Set-ItemProperty -Path $registryPath -Name "RestrictGuestAccess" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
                    }
                }
            }
            
            Write-Log "✓ Event logs configured" -Level Success
            
        } catch {
            Write-Log "Failed to configure event logs: $($_.Exception.Message)" -Level Error
        }
    }
}

function Set-AdvancedAuditSettings {
    [CmdletBinding(SupportsShouldProcess)]
    param($Config)
    
    Write-Log "Applying advanced audit settings..." -Level Info
    
    if ($PSCmdlet.ShouldProcess("Advanced Audit Settings", "Configure")) {
        try {
            # Enable command line logging
            if ($Config.EnableCommandLineLogging) {
                $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
                if (-not (Test-Path $regPath)) {
                    New-Item -Path $regPath -Force | Out-Null
                }
                Set-ItemProperty -Path $regPath -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1 -Type DWord -Force
                Write-Log "  Enabled command line logging in process creation events" -Level Info
            }
            
            # Enable PowerShell script block logging
            if ($Config.EnablePowerShellScriptBlockLogging) {
                $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
                if (-not (Test-Path $regPath)) {
                    New-Item -Path $regPath -Force | Out-Null
                }
                Set-ItemProperty -Path $regPath -Name "EnableScriptBlockLogging" -Value 1 -Type DWord -Force
                Write-Log "  Enabled PowerShell script block logging" -Level Info
            }
            
            # Enable PowerShell module logging
            if ($Config.EnablePowerShellModuleLogging) {
                $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
                if (-not (Test-Path $regPath)) {
                    New-Item -Path $regPath -Force | Out-Null
                }
                Set-ItemProperty -Path $regPath -Name "EnableModuleLogging" -Value 1 -Type DWord -Force
                
                # Log all modules
                $moduleNamesPath = "$regPath\ModuleNames"
                if (-not (Test-Path $moduleNamesPath)) {
                    New-Item -Path $moduleNamesPath -Force | Out-Null
                }
                Set-ItemProperty -Path $moduleNamesPath -Name "*" -Value "*" -Type String -Force
                Write-Log "  Enabled PowerShell module logging" -Level Info
            }
            
            # Enable PowerShell transcription
            if ($Config.EnablePowerShellTranscription) {
                $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"
                if (-not (Test-Path $regPath)) {
                    New-Item -Path $regPath -Force | Out-Null
                }
                Set-ItemProperty -Path $regPath -Name "EnableTranscripting" -Value 1 -Type DWord -Force
                Set-ItemProperty -Path $regPath -Name "EnableInvocationHeader" -Value 1 -Type DWord -Force
                
                if ($Config.PowerShellTranscriptionPath) {
                    # Create transcription directory
                    if (-not (Test-Path $Config.PowerShellTranscriptionPath)) {
                        New-Item -Path $Config.PowerShellTranscriptionPath -ItemType Directory -Force | Out-Null
                    }
                    Set-ItemProperty -Path $regPath -Name "OutputDirectory" -Value $Config.PowerShellTranscriptionPath -Type String -Force
                }
                Write-Log "  Enabled PowerShell transcription" -Level Info
            }
            
            Write-Log "✓ Advanced audit settings applied" -Level Success
            
        } catch {
            Write-Log "Failed to apply advanced audit settings: $($_.Exception.Message)" -Level Error
        }
    }
}

function Get-CurrentAuditPolicies {
    Write-Log "Retrieving current audit policies..." -Level Info
    
    try {
        $output = auditpol /get /category:* 2>&1
        
        $policies = @{}
        $currentCategory = ""
        
        foreach ($line in $output) {
            if ($line -match "^\s*(.+?)\s{2,}(.+)$") {
                $subcategory = $matches[1].Trim()
                $setting = $matches[2].Trim()
                
                if (-not $currentCategory) {
                    $currentCategory = $subcategory
                    $policies[$currentCategory] = @{}
                } else {
                    $policies[$currentCategory][$subcategory] = $setting
                }
            }
        }
        
        return $policies
        
    } catch {
        Write-Log "Failed to retrieve audit policies: $($_.Exception.Message)" -Level Error
        return $null
    }
}

function Export-AuditConfiguration {
    [CmdletBinding()]
    param(
        [string]$ExportPath
    )
    
    Write-Log "Exporting audit configuration..." -Level Info
    
    try {
        # Export audit policy
        auditpol /backup /file:"$ExportPath\AuditPolicy.csv" | Out-Null
        
        # Export event log settings
        $logSettings = @{}
        foreach ($logName in @('Security', 'System', 'Application')) {
            $log = Get-WinEvent -ListLog $logName -ErrorAction SilentlyContinue
            if ($log) {
                $logSettings[$logName] = @{
                    MaximumSizeInBytes = $log.MaximumSizeInBytes
                    LogMode = $log.LogMode
                    IsEnabled = $log.IsEnabled
                }
            }
        }
        
        $logSettings | ConvertTo-Json | Out-File "$ExportPath\EventLogSettings.json"
        Write-Log "✓ Audit configuration exported" -Level Success
        
    } catch {
        Write-Log "Failed to export audit configuration: $($_.Exception.Message)" -Level Error
    }
}

function Import-AuditConfiguration {
    [CmdletBinding()]
    param(
        [string]$ImportPath
    )
    
    Write-Log "Importing audit configuration..." -Level Info
    
    try {
        $policyFile = Join-Path $ImportPath "AuditPolicy.csv"
        if (Test-Path $policyFile) {
            auditpol /restore /file:"$policyFile" | Out-Null
            Write-Log "✓ Audit policies imported" -Level Success
        } else {
            Write-Log "Audit policy file not found: $policyFile" -Level Error
        }
        
    } catch {
        Write-Log "Failed to import audit configuration: $($_.Exception.Message)" -Level Error
    }
}

Export-ModuleMember -Function Set-AuditConfiguration, Get-CurrentAuditPolicies, Export-AuditConfiguration, Import-AuditConfiguration
