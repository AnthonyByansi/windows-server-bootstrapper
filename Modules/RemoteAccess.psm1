<#
.SYNOPSIS
    Remote Access Configuration Module

.DESCRIPTION
    Hardens WinRM and RDP configurations for secure remote access
#>

function Set-RemoteAccessConfiguration {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('Basic', 'Moderate', 'Strict')]
        [string]$Profile
    )
    
    Write-Log "Configuring remote access - $Profile profile..." -Level Info
    
    # Configure WinRM
    Set-WinRMHardening -Profile $Profile -WhatIf:$WhatIfPreference
    
    # Configure RDP
    Set-RDPHardening -Profile $Profile -WhatIf:$WhatIfPreference
    
    Write-Log "✓ Remote access configuration completed" -Level Success
}

function Set-WinRMHardening {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [string]$Profile
    )
    
    Write-Log "Hardening WinRM configuration..." -Level Info
    
    if ($PSCmdlet.ShouldProcess("WinRM", "Configure")) {
        try {
            # Enable WinRM if not already enabled
            $winrmService = Get-Service -Name WinRM -ErrorAction SilentlyContinue
            if ($winrmService.Status -ne 'Running') {
                Start-Service -Name WinRM -ErrorAction Stop
                Write-Log "  Started WinRM service" -Level Info
            }
            
            # Configure WinRM service
            Set-Service -Name WinRM -StartupType Automatic -ErrorAction Stop
            
            # Enable HTTPS listener
            $httpsListener = Get-ChildItem WSMan:\localhost\Listener | Where-Object { $_.Keys -contains 'Transport=HTTPS' }
            if (-not $httpsListener) {
                Write-Log "  ⚠ HTTPS listener not configured - HTTP will be used" -Level Warning
                Write-Log "    To enable HTTPS, create a certificate and run:" -Level Info
                Write-Log "    New-WSManInstance -ResourceURI winrm/config/Listener -SelectorSet @{Address='*';Transport='HTTPS'} -ValueSet @{CertificateThumbprint='THUMBPRINT'}" -Level Info
            }
            
            # Disable HTTP listener in strict mode
            if ($Profile -eq 'Strict') {
                $httpListener = Get-ChildItem WSMan:\localhost\Listener | Where-Object { $_.Keys -contains 'Transport=HTTP' }
                if ($httpListener) {
                    Remove-Item -Path $httpListener.PSPath -Recurse -Force -ErrorAction SilentlyContinue
                    Write-Log "  Disabled HTTP listener (Strict mode)" -Level Info
                }
            }
            
            # Configure WinRM security settings
            Set-Item WSMan:\localhost\Service\Auth\Basic -Value $false -Force
            Write-Log "  Disabled Basic authentication" -Level Info
            
            Set-Item WSMan:\localhost\Service\Auth\CredSSP -Value $false -Force
            Write-Log "  Disabled CredSSP authentication" -Level Info
            
            # Enable Kerberos and Certificate auth
            Set-Item WSMan:\localhost\Service\Auth\Kerberos -Value $true -Force
            Set-Item WSMan:\localhost\Service\Auth\Certificate -Value $true -Force
            Write-Log "  Enabled Kerberos and Certificate authentication" -Level Info
            
            # Set max concurrent operations
            Set-Item WSMan:\localhost\Service\MaxConcurrentOperationsPerUser -Value 1500 -Force
            
            # Configure encryption
            Set-Item WSMan:\localhost\Service\AllowUnencrypted -Value $false -Force
            Write-Log "  Disabled unencrypted traffic" -Level Info
            
            # Set trusted hosts (empty by default for security)
            # Set-Item WSMan:\localhost\Client\TrustedHosts -Value "" -Force
            
            Write-Log "✓ WinRM hardening completed" -Level Success
            
        } catch {
            Write-Log "Failed to harden WinRM: $($_.Exception.Message)" -Level Error
        }
    }
}

function Set-RDPHardening {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [string]$Profile
    )
    
    Write-Log "Hardening RDP configuration..." -Level Info
    
    if ($PSCmdlet.ShouldProcess("RDP", "Configure")) {
        try {
            $rdpPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server"
            $rdpSecPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"
            
            # Enable RDP (if needed)
            # Set-ItemProperty -Path $rdpPath -Name "fDenyTSConnections" -Value 0 -Type DWord
            
            # Require Network Level Authentication (NLA)
            Set-ItemProperty -Path $rdpPath -Name "UserAuthentication" -Value 1 -Type DWord -Force
            Write-Log "  Enabled Network Level Authentication (NLA)" -Level Info
            
            # Set minimum encryption level
            $encryptionLevel = switch ($Profile) {
                'Basic' { 2 }      # Client Compatible
                'Moderate' { 3 }   # High
                'Strict' { 3 }     # High
                default { 3 }
            }
            Set-ItemProperty -Path $rdpSecPath -Name "MinEncryptionLevel" -Value $encryptionLevel -Type DWord -Force
            Write-Log "  Set encryption level: $encryptionLevel (1=Low, 2=ClientCompatible, 3=High)" -Level Info
            
            # Require secure RPC communication
            Set-ItemProperty -Path $rdpSecPath -Name "SecurityLayer" -Value 2 -Type DWord -Force
            Write-Log "  Set security layer to SSL/TLS" -Level Info
            
            # Disable clipboard redirection in strict mode
            if ($Profile -eq 'Strict') {
                Set-ItemProperty -Path $rdpSecPath -Name "fDisableClip" -Value 1 -Type DWord -Force
                Write-Log "  Disabled clipboard redirection" -Level Info
            }
            
            # Disable printer redirection in strict mode
            if ($Profile -eq 'Strict') {
                Set-ItemProperty -Path $rdpSecPath -Name "fDisableCpm" -Value 1 -Type DWord -Force
                Write-Log "  Disabled printer redirection" -Level Info
            }
            
            # Disable COM port redirection
            Set-ItemProperty -Path $rdpSecPath -Name "fDisableCcm" -Value 1 -Type DWord -Force
            Write-Log "  Disabled COM port redirection" -Level Info
            
            # Disable drive redirection in strict mode
            if ($Profile -eq 'Strict') {
                Set-ItemProperty -Path $rdpSecPath -Name "fDisableCdm" -Value 1 -Type DWord -Force
                Write-Log "  Disabled drive redirection" -Level Info
            }
            
            # Set idle session limit (15 minutes)
            $idleLimit = switch ($Profile) {
                'Basic' { 1800000 }      # 30 minutes
                'Moderate' { 900000 }    # 15 minutes
                'Strict' { 600000 }      # 10 minutes
                default { 900000 }
            }
            Set-ItemProperty -Path $rdpSecPath -Name "MaxIdleTime" -Value $idleLimit -Type DWord -Force
            Write-Log "  Set idle timeout: $($idleLimit/60000) minutes" -Level Info
            
            # Set disconnected session limit
            Set-ItemProperty -Path $rdpSecPath -Name "MaxDisconnectionTime" -Value $idleLimit -Type DWord -Force
            Write-Log "  Set disconnection timeout: $($idleLimit/60000) minutes" -Level Info
            
            # Require user-specific licenses
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\RCM\Licensing Core" -Name "LicensingMode" -Value 4 -Type DWord -Force -ErrorAction SilentlyContinue
            
            # Delete temporary folders on exit
            Set-ItemProperty -Path $rdpSecPath -Name "DeleteTempDirsOnExit" -Value 1 -Type DWord -Force
            Write-Log "  Enabled deletion of temp folders on exit" -Level Info
            
            # Disable password saving
            $rdpClientPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
            if (-not (Test-Path $rdpClientPath)) {
                New-Item -Path $rdpClientPath -Force | Out-Null
            }
            Set-ItemProperty -Path $rdpClientPath -Name "DisablePasswordSaving" -Value 1 -Type DWord -Force
            Write-Log "  Disabled password saving in RDP client" -Level Info
            
            # Enable RDP firewall rule (if not already enabled)
            Enable-NetFirewallRule -DisplayGroup "Remote Desktop" -ErrorAction SilentlyContinue
            Write-Log "  Enabled RDP firewall rules" -Level Info
            
            Write-Log "✓ RDP hardening completed" -Level Success
            
        } catch {
            Write-Log "Failed to harden RDP: $($_.Exception.Message)" -Level Error
        }
    }
}

function Get-RemoteAccessStatus {
    Write-Log "Retrieving remote access status..." -Level Info
    
    try {
        $status = @{
            WinRM = @{
                ServiceStatus = (Get-Service -Name WinRM).Status
                ServiceStartType = (Get-Service -Name WinRM).StartType
                HTTPListener = $null
                HTTPSListener = $null
            }
            RDP = @{
                Enabled = $null
                NLARequired = $null
                EncryptionLevel = $null
            }
        }
        
        # Get WinRM listeners
        $listeners = Get-ChildItem WSMan:\localhost\Listener -ErrorAction SilentlyContinue
        $status.WinRM.HTTPListener = ($listeners | Where-Object { $_.Keys -contains 'Transport=HTTP' }) -ne $null
        $status.WinRM.HTTPSListener = ($listeners | Where-Object { $_.Keys -contains 'Transport=HTTPS' }) -ne $null
        
        # Get RDP status
        $rdpPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server"
        $rdpSecPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"
        
        $status.RDP.Enabled = (Get-ItemProperty -Path $rdpPath -Name "fDenyTSConnections" -ErrorAction SilentlyContinue).fDenyTSConnections -eq 0
        $status.RDP.NLARequired = (Get-ItemProperty -Path $rdpPath -Name "UserAuthentication" -ErrorAction SilentlyContinue).UserAuthentication -eq 1
        $status.RDP.EncryptionLevel = (Get-ItemProperty -Path $rdpSecPath -Name "MinEncryptionLevel" -ErrorAction SilentlyContinue).MinEncryptionLevel
        
        return $status
        
    } catch {
        Write-Log "Failed to retrieve remote access status: $($_.Exception.Message)" -Level Error
        return $null
    }
}

Export-ModuleMember -Function Set-RemoteAccessConfiguration, Get-RemoteAccessStatus
