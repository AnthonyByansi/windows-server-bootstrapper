<#
.SYNOPSIS
    Firewall Configuration Module

.DESCRIPTION
    Manages Windows Firewall configuration based on server roles and security requirements
#>

function Set-FirewallConfiguration {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory = $false)]
        [string[]]$Roles
    )
    
    Write-Log "Configuring Windows Firewall..." -Level Info
    
    # Load firewall rules configuration
    $configPath = Join-Path $PSScriptRoot "..\Config\firewall-rules.json"
    if (-not (Test-Path $configPath)) {
        Write-Log "Firewall configuration not found: $configPath" -Level Error
        throw "Configuration file not found"
    }
    
    $config = Get-Content $configPath -Raw | ConvertFrom-Json
    
    # Apply global firewall settings
    Set-GlobalFirewallSettings -Config $config.GlobalSettings -WhatIf:$WhatIfPreference
    
    # Apply baseline rules
    Set-BaselineFirewallRules -Rules $config.BaselineRules -InstalledRoles $Roles -WhatIf:$WhatIfPreference
    
    # Apply security rules
    Set-SecurityFirewallRules -Rules $config.SecurityRules -WhatIf:$WhatIfPreference
    
    # Apply block rules
    Set-BlockFirewallRules -Rules $config.BlockRules -WhatIf:$WhatIfPreference
    
    Write-Log "✓ Firewall configuration completed" -Level Success
}

function Set-GlobalFirewallSettings {
    [CmdletBinding(SupportsShouldProcess)]
    param($Config)
    
    Write-Log "Applying global firewall settings..." -Level Info
    
    if ($PSCmdlet.ShouldProcess("Firewall Global Settings", "Configure")) {
        try {
            # Enable firewall for all profiles
            Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
            Write-Log "  Enabled firewall for all profiles" -Level Info
            
            # Set default actions
            Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block -DefaultOutboundAction Allow
            Write-Log "  Set default: Block inbound, Allow outbound" -Level Info
            
            # Configure logging
            if ($Config.EnableLogging) {
                Set-NetFirewallProfile -Profile Domain,Public,Private -LogAllowed $Config.LogSuccessfulConnections -LogBlocked $Config.LogDroppedPackets -LogMaxSizeKilobytes $Config.LogMaxFileSize -LogFileName $Config.LogFilePath
                Write-Log "  Configured firewall logging" -Level Info
            }
            
            # Disable notifications for public profile
            Set-NetFirewallProfile -Profile Public -NotifyOnListen False
            
            Write-Log "✓ Global firewall settings applied" -Level Success
            
        } catch {
            Write-Log "Failed to apply global firewall settings: $($_.Exception.Message)" -Level Error
        }
    }
}

function Set-BaselineFirewallRules {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        $Rules,
        [string[]]$InstalledRoles
    )
    
    Write-Log "Applying baseline firewall rules..." -Level Info
    
    foreach ($rule in $Rules) {
        # Check if this rule requires a specific role
        if ($rule.RequiredRole) {
            $roleMapping = @{
                'DNS' = 'DNS'
                'Web-Server' = 'IIS'
                'AD-Domain-Services' = 'ADDS'
                'Hyper-V' = 'HyperV'
                'Failover-Clustering' = 'Clustering'
            }
            
            $requiredRole = $roleMapping[$rule.RequiredRole]
            if ($InstalledRoles -notcontains $requiredRole) {
                Write-Log "  Skipping rule '$($rule.Name)' - role not installed" -Level Info
                continue
            }
        }
        
        New-CustomFirewallRule -RuleConfig $rule -WhatIf:$WhatIfPreference
    }
    
    Write-Log "✓ Baseline rules applied" -Level Success
}

function Set-SecurityFirewallRules {
    [CmdletBinding(SupportsShouldProcess)]
    param($Rules)
    
    Write-Log "Applying security firewall rules..." -Level Info
    
    foreach ($rule in $Rules) {
        New-CustomFirewallRule -RuleConfig $rule -WhatIf:$WhatIfPreference
    }
    
    Write-Log "✓ Security rules applied" -Level Success
}

function Set-BlockFirewallRules {
    [CmdletBinding(SupportsShouldProcess)]
    param($Rules)
    
    Write-Log "Applying block firewall rules..." -Level Info
    
    foreach ($rule in $Rules) {
        New-CustomFirewallRule -RuleConfig $rule -WhatIf:$WhatIfPreference
    }
    
    Write-Log "✓ Block rules applied" -Level Success
}

function New-CustomFirewallRule {
    [CmdletBinding(SupportsShouldProcess)]
    param($RuleConfig)
    
    if ($PSCmdlet.ShouldProcess($RuleConfig.Name, "Create Firewall Rule")) {
        try {
            # Remove existing rule if it exists
            $existingRule = Get-NetFirewallRule -DisplayName $RuleConfig.Name -ErrorAction SilentlyContinue
            if ($existingRule) {
                Remove-NetFirewallRule -DisplayName $RuleConfig.Name -ErrorAction SilentlyContinue
            }
            
            # Build parameters
            $params = @{
                DisplayName = $RuleConfig.Name
                Description = $RuleConfig.Description
                Direction = $RuleConfig.Direction
                Action = $RuleConfig.Action
                Protocol = $RuleConfig.Protocol
                Enabled = if ($RuleConfig.Enabled) { 'True' } else { 'False' }
            }
            
            # Add optional parameters
            if ($RuleConfig.LocalPort -and $RuleConfig.LocalPort -ne "Any") {
                $params['LocalPort'] = $RuleConfig.LocalPort
            }
            
            if ($RuleConfig.RemotePort -and $RuleConfig.RemotePort -ne "Any") {
                $params['RemotePort'] = $RuleConfig.RemotePort
            }
            
            if ($RuleConfig.Profile -and $RuleConfig.Profile -ne "Any") {
                $params['Profile'] = $RuleConfig.Profile
            }
            
            if ($RuleConfig.RemoteAddress) {
                $params['RemoteAddress'] = $RuleConfig.RemoteAddress
            }
            
            if ($RuleConfig.Program) {
                $params['Program'] = $RuleConfig.Program
            }
            
            # Create the rule
            New-NetFirewallRule @params -ErrorAction Stop | Out-Null
            Write-Log "  Created rule: $($RuleConfig.Name)" -Level Info
            
        } catch {
            Write-Log "  Failed to create rule '$($RuleConfig.Name)': $($_.Exception.Message)" -Level Warning
        }
    }
}

function Remove-UnsafeFirewallRules {
    [CmdletBinding(SupportsShouldProcess)]
    param()
    
    Write-Log "Removing potentially unsafe firewall rules..." -Level Info
    
    if ($PSCmdlet.ShouldProcess("Unsafe Rules", "Remove")) {
        try {
            # Remove rules that allow all inbound traffic
            $unsafeRules = Get-NetFirewallRule | Where-Object {
                $_.Direction -eq 'Inbound' -and 
                $_.Action -eq 'Allow' -and 
                $_.Enabled -eq 'True'
            }
            
            foreach ($rule in $unsafeRules) {
                $portFilter = Get-NetFirewallPortFilter -AssociatedNetFirewallRule $rule
                $addressFilter = Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $rule
                
                # Check for overly permissive rules
                if ($addressFilter.RemoteAddress -contains 'Any' -and $portFilter.LocalPort -contains 'Any') {
                    Write-Log "  ⚠ Found potentially unsafe rule: $($rule.DisplayName)" -Level Warning
                    # Optionally disable or remove
                    # Disable-NetFirewallRule -Name $rule.Name
                }
            }
            
            Write-Log "✓ Unsafe rule check completed" -Level Success
            
        } catch {
            Write-Log "Failed to check for unsafe rules: $($_.Exception.Message)" -Level Error
        }
    }
}

function Get-FirewallStatus {
    Write-Log "Retrieving firewall status..." -Level Info
    
    try {
        $profiles = Get-NetFirewallProfile
        $status = @{
            Domain = $profiles | Where-Object { $_.Name -eq 'Domain' }
            Private = $profiles | Where-Object { $_.Name -eq 'Private' }
            Public = $profiles | Where-Object { $_.Name -eq 'Public' }
            Rules = @{
                Total = (Get-NetFirewallRule).Count
                Enabled = (Get-NetFirewallRule | Where-Object { $_.Enabled -eq 'True' }).Count
                Inbound = (Get-NetFirewallRule | Where-Object { $_.Direction -eq 'Inbound' -and $_.Enabled -eq 'True' }).Count
                Outbound = (Get-NetFirewallRule | Where-Object { $_.Direction -eq 'Outbound' -and $_.Enabled -eq 'True' }).Count
            }
        }
        
        return $status
        
    } catch {
        Write-Log "Failed to retrieve firewall status: $($_.Exception.Message)" -Level Error
        return $null
    }
}

function Export-FirewallConfiguration {
    [CmdletBinding()]
    param(
        [string]$ExportPath
    )
    
    Write-Log "Exporting firewall configuration..." -Level Info
    
    try {
        netsh advfirewall export "$ExportPath" | Out-Null
        Write-Log "✓ Firewall configuration exported to: $ExportPath" -Level Success
        
    } catch {
        Write-Log "Failed to export firewall configuration: $($_.Exception.Message)" -Level Error
    }
}

function Import-FirewallConfiguration {
    [CmdletBinding()]
    param(
        [string]$ImportPath
    )
    
    Write-Log "Importing firewall configuration..." -Level Info
    
    try {
        if (Test-Path $ImportPath) {
            netsh advfirewall import "$ImportPath" | Out-Null
            Write-Log "✓ Firewall configuration imported from: $ImportPath" -Level Success
        } else {
            Write-Log "Import file not found: $ImportPath" -Level Error
        }
        
    } catch {
        Write-Log "Failed to import firewall configuration: $($_.Exception.Message)" -Level Error
    }
}

Export-ModuleMember -Function Set-FirewallConfiguration, Get-FirewallStatus, Export-FirewallConfiguration, Import-FirewallConfiguration
