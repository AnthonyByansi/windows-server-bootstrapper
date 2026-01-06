<#
.SYNOPSIS
    Server Roles and Features Management Module

.DESCRIPTION
    Handles installation and configuration of Windows Server roles and features
#>

function Install-ServerRole {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('IIS', 'DNS', 'ADDS', 'HyperV', 'Clustering')]
        [string]$Role
    )
    
    Write-Log "Processing role: $Role" -Level Info
    
    switch ($Role) {
        'IIS' {
            Install-IISRole
        }
        'DNS' {
            Install-DNSRole
        }
        'ADDS' {
            Install-ADDSRole
        }
        'HyperV' {
            Install-HyperVRole
        }
        'Clustering' {
            Install-ClusteringRole
        }
    }
}

function Install-IISRole {
    [CmdletBinding(SupportsShouldProcess)]
    param()
    
    Write-Log "Installing IIS Web Server..." -Level Info
    
    $features = @(
        'Web-Server',
        'Web-WebServer',
        'Web-Common-Http',
        'Web-Default-Doc',
        'Web-Dir-Browsing',
        'Web-Http-Errors',
        'Web-Static-Content',
        'Web-Http-Redirect',
        'Web-Health',
        'Web-Http-Logging',
        'Web-Custom-Logging',
        'Web-Log-Libraries',
        'Web-ODBC-Logging',
        'Web-Request-Monitor',
        'Web-Http-Tracing',
        'Web-Performance',
        'Web-Stat-Compression',
        'Web-Dyn-Compression',
        'Web-Security',
        'Web-Filtering',
        'Web-Basic-Auth',
        'Web-Windows-Auth',
        'Web-Digest-Auth',
        'Web-Client-Auth',
        'Web-Cert-Auth',
        'Web-Url-Auth',
        'Web-IP-Security',
        'Web-App-Dev',
        'Web-Net-Ext45',
        'Web-Asp-Net45',
        'Web-ISAPI-Ext',
        'Web-ISAPI-Filter',
        'Web-Mgmt-Tools',
        'Web-Mgmt-Console',
        'Web-Scripting-Tools'
    )
    
    if ($PSCmdlet.ShouldProcess("IIS", "Install Features")) {
        try {
            Install-WindowsFeature -Name $features -IncludeManagementTools -ErrorAction Stop
            Write-Log "✓ IIS installed successfully" -Level Success
            
            # Apply IIS security hardening
            Set-IISSecurityHardening
            
        } catch {
            Write-Log "Failed to install IIS: $($_.Exception.Message)" -Level Error
            throw
        }
    }
}

function Set-IISSecurityHardening {
    Write-Log "Applying IIS security hardening..." -Level Info
    
    try {
        Import-Module WebAdministration -ErrorAction SilentlyContinue
        
        # Remove default website
        if (Get-Website -Name "Default Web Site" -ErrorAction SilentlyContinue) {
            Remove-Website -Name "Default Web Site" -ErrorAction SilentlyContinue
            Write-Log "  Removed default website" -Level Info
        }
        
        # Disable directory browsing
        Set-WebConfigurationProperty -Filter /system.webServer/directoryBrowse -Name enabled -Value $false -PSPath IIS:\ -ErrorAction SilentlyContinue
        Write-Log "  Disabled directory browsing" -Level Info
        
        # Remove server header
        Set-WebConfigurationProperty -Filter /system.webServer/security/requestFiltering -Name removeServerHeader -Value $true -PSPath IIS:\ -ErrorAction SilentlyContinue
        Write-Log "  Removed server header" -Level Info
        
        # Set custom errors mode
        Set-WebConfigurationProperty -Filter /system.webServer/httpErrors -Name errorMode -Value DetailedLocalOnly -PSPath IIS:\ -ErrorAction SilentlyContinue
        Write-Log "  Configured custom errors" -Level Info
        
        Write-Log "✓ IIS security hardening applied" -Level Success
        
    } catch {
        Write-Log "Warning: Some IIS hardening steps failed: $($_.Exception.Message)" -Level Warning
    }
}

function Install-DNSRole {
    [CmdletBinding(SupportsShouldProcess)]
    param()
    
    Write-Log "Installing DNS Server..." -Level Info
    
    if ($PSCmdlet.ShouldProcess("DNS", "Install Feature")) {
        try {
            Install-WindowsFeature -Name DNS -IncludeManagementTools -ErrorAction Stop
            Write-Log "✓ DNS installed successfully" -Level Success
            
            # DNS Security hardening
            Set-DNSSecurityHardening
            
        } catch {
            Write-Log "Failed to install DNS: $($_.Exception.Message)" -Level Error
            throw
        }
    }
}

function Set-DNSSecurityHardening {
    Write-Log "Applying DNS security hardening..." -Level Info
    
    try {
        # Enable DNS query logging
        Set-DnsServerDiagnostics -Queries $true -QueryErrors $true -ErrorAction SilentlyContinue
        Write-Log "  Enabled DNS query logging" -Level Info
        
        # Configure DNS cache locking
        Set-DnsServerCache -LockingPercent 100 -ErrorAction SilentlyContinue
        Write-Log "  Configured cache locking" -Level Info
        
        # Disable recursion for public-facing DNS
        # Set-DnsServerRecursion -Enable $false -ErrorAction SilentlyContinue
        
        Write-Log "✓ DNS security hardening applied" -Level Success
        
    } catch {
        Write-Log "Warning: Some DNS hardening steps failed: $($_.Exception.Message)" -Level Warning
    }
}

function Install-ADDSRole {
    [CmdletBinding(SupportsShouldProcess)]
    param()
    
    Write-Log "Installing Active Directory Domain Services..." -Level Info
    
    if ($PSCmdlet.ShouldProcess("AD DS", "Install Feature")) {
        try {
            Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools -ErrorAction Stop
            Write-Log "✓ AD DS installed successfully" -Level Success
            Write-Log "  Note: Domain promotion must be performed separately using Install-ADDSForest or Install-ADDSDomainController" -Level Info
            
        } catch {
            Write-Log "Failed to install AD DS: $($_.Exception.Message)" -Level Error
            throw
        }
    }
}

function Install-HyperVRole {
    [CmdletBinding(SupportsShouldProcess)]
    param()
    
    Write-Log "Installing Hyper-V..." -Level Info
    
    if ($PSCmdlet.ShouldProcess("Hyper-V", "Install Feature")) {
        try {
            Install-WindowsFeature -Name Hyper-V -IncludeManagementTools -Restart:$false -ErrorAction Stop
            Write-Log "✓ Hyper-V installed successfully" -Level Success
            Write-Log "  ⚠ A reboot is required to complete Hyper-V installation" -Level Warning
            
            # Hyper-V security settings
            Set-HyperVSecurityHardening
            
        } catch {
            Write-Log "Failed to install Hyper-V: $($_.Exception.Message)" -Level Error
            throw
        }
    }
}

function Set-HyperVSecurityHardening {
    Write-Log "Applying Hyper-V security hardening..." -Level Info
    
    try {
        # Enable Hyper-V firewall rules
        Enable-NetFirewallRule -DisplayGroup "Hyper-V*" -ErrorAction SilentlyContinue
        Write-Log "  Enabled Hyper-V firewall rules" -Level Info
        
        Write-Log "✓ Hyper-V security hardening applied" -Level Success
        
    } catch {
        Write-Log "Warning: Some Hyper-V hardening steps failed: $($_.Exception.Message)" -Level Warning
    }
}

function Install-ClusteringRole {
    [CmdletBinding(SupportsShouldProcess)]
    param()
    
    Write-Log "Installing Failover Clustering..." -Level Info
    
    if ($PSCmdlet.ShouldProcess("Failover Clustering", "Install Feature")) {
        try {
            Install-WindowsFeature -Name Failover-Clustering -IncludeManagementTools -ErrorAction Stop
            Write-Log "✓ Failover Clustering installed successfully" -Level Success
            Write-Log "  Note: Cluster creation must be performed separately using New-Cluster" -Level Info
            
        } catch {
            Write-Log "Failed to install Failover Clustering: $($_.Exception.Message)" -Level Error
            throw
        }
    }
}

function Get-InstalledRoles {
    Write-Log "Retrieving installed server roles..." -Level Info
    
    try {
        $roles = Get-WindowsFeature | Where-Object { $_.Installed -eq $true -and $_.FeatureType -eq 'Role' }
        return $roles
    } catch {
        Write-Log "Failed to retrieve installed roles: $($_.Exception.Message)" -Level Error
        return $null
    }
}

Export-ModuleMember -Function Install-ServerRole, Get-InstalledRoles
