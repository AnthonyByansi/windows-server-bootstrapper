<#
.SYNOPSIS
    Security Hardening Module - CIS Inspired Controls

.DESCRIPTION
    Applies CIS-inspired security hardening based on selected profile
#>

function Apply-SecurityHardening {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('Basic', 'Moderate', 'Strict')]
        [string]$Profile
    )
    
    Write-Log "Applying $Profile security hardening profile..." -Level Info
    
    # Load hardening profile
    $profilePath = Join-Path $PSScriptRoot "..\Config\hardening-profiles.json"
    if (-not (Test-Path $profilePath)) {
        Write-Log "Hardening profile configuration not found: $profilePath" -Level Error
        throw "Configuration file not found"
    }
    
    $config = Get-Content $profilePath -Raw | ConvertFrom-Json
    $profileConfig = $config.Profiles.$Profile
    
    if (-not $profileConfig) {
        Write-Log "Profile $Profile not found in configuration" -Level Error
        throw "Invalid profile"
    }
    
    Write-Log "Profile Description: $($profileConfig.Description)" -Level Info
    
    # Apply configurations
    Set-PasswordPolicy -Config $profileConfig.PasswordPolicy -WhatIf:$WhatIfPreference
    Set-AccountPolicy -Config $profileConfig.AccountPolicy -WhatIf:$WhatIfPreference
    Set-SecurityOptions -Config $profileConfig.SecurityOptions -WhatIf:$WhatIfPreference
    Set-ServiceHardening -Config $profileConfig.Services -WhatIf:$WhatIfPreference
    Set-RegistryHardening -Config $profileConfig.RegistryHardening -WhatIf:$WhatIfPreference
    
    if ($profileConfig.UAC) {
        Set-UACConfiguration -Config $profileConfig.UAC -WhatIf:$WhatIfPreference
    }
    
    if ($profileConfig.NetworkSecurity) {
        Set-NetworkSecurity -Config $profileConfig.NetworkSecurity -WhatIf:$WhatIfPreference
    }
    
    Write-Log "✓ Security hardening completed" -Level Success
}

function Set-PasswordPolicy {
    [CmdletBinding(SupportsShouldProcess)]
    param($Config)
    
    Write-Log "Configuring password policy..." -Level Info
    
    if ($PSCmdlet.ShouldProcess("Password Policy", "Apply Configuration")) {
        try {
            # Export current policy for backup
            secedit /export /cfg "$Script:BackupPath\secpol_backup.inf" /quiet
            
            # Configure password policy via secedit
            $secTemplate = @"
[Unicode]
Unicode=yes
[System Access]
MinimumPasswordLength = $($Config.MinimumPasswordLength)
PasswordComplexity = $(if ($Config.PasswordComplexity) { 1 } else { 0 })
PasswordHistorySize = $($Config.PasswordHistorySize)
MaximumPasswordAge = $($Config.MaximumPasswordAge)
MinimumPasswordAge = $($Config.MinimumPasswordAge)
LockoutBadCount = $($Config.LockoutThreshold)
LockoutDuration = $($Config.LockoutDuration)
ResetLockoutCount = $($Config.LockoutWindow)
[Version]
signature="`$CHICAGO`$"
Revision=1
"@
            
            $tempFile = "$env:TEMP\secpol_temp.inf"
            $secTemplate | Out-File $tempFile -Encoding Unicode
            
            secedit /configure /db secedit.sdb /cfg $tempFile /quiet
            Remove-Item $tempFile -Force
            
            Write-Log "  Minimum password length: $($Config.MinimumPasswordLength)" -Level Info
            Write-Log "  Password complexity: $($Config.PasswordComplexity)" -Level Info
            Write-Log "  Password history: $($Config.PasswordHistorySize)" -Level Info
            Write-Log "  Account lockout threshold: $($Config.LockoutThreshold)" -Level Info
            Write-Log "✓ Password policy configured" -Level Success
            
        } catch {
            Write-Log "Failed to configure password policy: $($_.Exception.Message)" -Level Error
        }
    }
}

function Set-AccountPolicy {
    [CmdletBinding(SupportsShouldProcess)]
    param($Config)
    
    Write-Log "Configuring account policies..." -Level Info
    
    if ($PSCmdlet.ShouldProcess("Account Policy", "Apply Configuration")) {
        try {
            # Rename Administrator account
            if ($Config.RenameAdministrator) {
                $adminAccount = Get-LocalUser | Where-Object { $_.SID -like "*-500" }
                if ($adminAccount -and $adminAccount.Name -ne $Config.NewAdministratorName) {
                    Rename-LocalUser -Name $adminAccount.Name -NewName $Config.NewAdministratorName -ErrorAction Stop
                    Write-Log "  Renamed Administrator to: $($Config.NewAdministratorName)" -Level Info
                }
            }
            
            # Disable Guest account
            if ($Config.DisableGuestAccount) {
                $guestAccount = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
                if ($guestAccount -and $guestAccount.Enabled) {
                    Disable-LocalUser -Name "Guest" -ErrorAction Stop
                    Write-Log "  Disabled Guest account" -Level Info
                }
            }
            
            # Limit blank password use
            if ($Config.LimitBlankPasswordUse) {
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LimitBlankPasswordUse" -Value 1 -Type DWord -ErrorAction Stop
                Write-Log "  Limited blank password use to console only" -Level Info
            }
            
            Write-Log "✓ Account policies configured" -Level Success
            
        } catch {
            Write-Log "Failed to configure account policies: $($_.Exception.Message)" -Level Error
        }
    }
}

function Set-SecurityOptions {
    [CmdletBinding(SupportsShouldProcess)]
    param($Config)
    
    Write-Log "Configuring security options..." -Level Info
    
    if ($PSCmdlet.ShouldProcess("Security Options", "Apply Configuration")) {
        try {
            # SMB Signing
            if ($Config.RequireSMBSigning) {
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "RequireSecuritySignature" -Value 1 -Type DWord
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "RequireSecuritySignature" -Value 1 -Type DWord
                Write-Log "  Enabled required SMB signing" -Level Info
            }
            
            # Disable LM Hash
            if ($Config.DisableLMHash) {
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "NoLMHash" -Value 1 -Type DWord
                Write-Log "  Disabled LM hash storage" -Level Info
            }
            
            # NTLM Restrictions
            if ($Config.RestrictNTLM) {
                $ntlmValue = switch ($Config.RestrictNTLM) {
                    "AuditOnly" { 1 }
                    "DenyAllServers" { 3 }
                    "DenyAll" { 5 }
                    default { 0 }
                }
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -Name "RestrictSendingNTLMTraffic" -Value $ntlmValue -Type DWord -ErrorAction SilentlyContinue
                Write-Log "  Configured NTLM restrictions: $($Config.RestrictNTLM)" -Level Info
            }
            
            # Require NTLMv2
            if ($Config.RequireNTLMv2) {
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel" -Value 5 -Type DWord
                Write-Log "  Required NTLMv2 authentication" -Level Info
            }
            
            # Restrict Anonymous SAM enumeration
            if ($Config.RestrictAnonymousSAM) {
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymousSAM" -Value 1 -Type DWord
                Write-Log "  Restricted anonymous SAM enumeration" -Level Info
            }
            
            # Restrict Anonymous
            if ($Config.RestrictAnonymous) {
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymous" -Value $Config.RestrictAnonymous -Type DWord
                Write-Log "  Set anonymous restriction level: $($Config.RestrictAnonymous)" -Level Info
            }
            
            # Disable Auto Admin Logon
            if ($Config.DisableAutoAdminLogon) {
                Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "AutoAdminLogon" -Value 0 -Type String
                Write-Log "  Disabled automatic administrator logon" -Level Info
            }
            
            # Clear page file at shutdown
            if ($Config.ClearPageFileAtShutdown) {
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "ClearPageFileAtShutdown" -Value 1 -Type DWord
                Write-Log "  Enabled clear page file at shutdown" -Level Info
            }
            
            # LDAP Client Signing
            if ($Config.LDAPClientSigning) {
                $ldapValue = switch ($Config.LDAPClientSigning) {
                    "NegotiateSigning" { 1 }
                    "RequireSigning" { 2 }
                    default { 0 }
                }
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LDAP" -Name "LDAPClientIntegrity" -Value $ldapValue -Type DWord -ErrorAction SilentlyContinue
                Write-Log "  Configured LDAP client signing: $($Config.LDAPClientSigning)" -Level Info
            }
            
            # Disable IP Source Routing
            if ($Config.DisableIPSourceRouting) {
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "DisableIPSourceRouting" -Value 2 -Type DWord
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" -Name "DisableIPSourceRouting" -Value 2 -Type DWord -ErrorAction SilentlyContinue
                Write-Log "  Disabled IP source routing" -Level Info
            }
            
            Write-Log "✓ Security options configured" -Level Success
            
        } catch {
            Write-Log "Failed to configure security options: $($_.Exception.Message)" -Level Error
        }
    }
}

function Set-ServiceHardening {
    [CmdletBinding(SupportsShouldProcess)]
    param($Config)
    
    Write-Log "Hardening services..." -Level Info
    
    if ($PSCmdlet.ShouldProcess("Services", "Disable Unnecessary Services")) {
        try {
            foreach ($serviceName in $Config.DisableUnnecessaryServices) {
                $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
                if ($service) {
                    if ($service.Status -eq 'Running') {
                        Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
                    }
                    Set-Service -Name $serviceName -StartupType Disabled -ErrorAction SilentlyContinue
                    Write-Log "  Disabled service: $serviceName" -Level Info
                }
            }
            
            Write-Log "✓ Service hardening completed" -Level Success
            
        } catch {
            Write-Log "Failed to harden services: $($_.Exception.Message)" -Level Error
        }
    }
}

function Set-RegistryHardening {
    [CmdletBinding(SupportsShouldProcess)]
    param($Config)
    
    Write-Log "Applying registry hardening..." -Level Info
    
    if ($PSCmdlet.ShouldProcess("Registry", "Apply Hardening")) {
        try {
            # Disable AutoRun
            if ($Config.DisableAutoRun) {
                Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Value 255 -Type DWord -Force
                Write-Log "  Disabled AutoRun for all drives" -Level Info
            }
            
            # Enable DEP (Data Execution Prevention)
            if ($Config.EnableDEP) {
                bcdedit /set nx AlwaysOn | Out-Null
                Write-Log "  Enabled DEP (Always On)" -Level Info
            }
            
            # Enable SEHOP (Structured Exception Handler Overwrite Protection)
            if ($Config.EnableSEHOP) {
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" -Name "DisableExceptionChainValidation" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue
                Write-Log "  Enabled SEHOP" -Level Info
            }
            
            # Disable LLMNR
            if ($Config.DisableLLMNR) {
                if (-not (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient")) {
                    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Force | Out-Null
                }
                Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -Value 0 -Type DWord -Force
                Write-Log "  Disabled LLMNR" -Level Info
            }
            
            # Disable NetBIOS
            if ($Config.DisableNetBIOS) {
                $adapters = Get-WmiObject Win32_NetworkAdapterConfiguration -Filter "IPEnabled=TRUE"
                foreach ($adapter in $adapters) {
                    $adapter.SetTcpipNetbios(2) | Out-Null
                }
                Write-Log "  Disabled NetBIOS over TCP/IP" -Level Info
            }
            
            # Enable Windows Firewall
            if ($Config.EnableFirewall) {
                Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
                Write-Log "  Enabled Windows Firewall for all profiles" -Level Info
            }
            
            Write-Log "✓ Registry hardening completed" -Level Success
            
        } catch {
            Write-Log "Failed to apply registry hardening: $($_.Exception.Message)" -Level Error
        }
    }
}

function Set-UACConfiguration {
    [CmdletBinding(SupportsShouldProcess)]
    param($Config)
    
    Write-Log "Configuring UAC settings..." -Level Info
    
    if ($PSCmdlet.ShouldProcess("UAC", "Configure")) {
        try {
            $uacPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
            
            if ($Config.EnableLUA) {
                Set-ItemProperty -Path $uacPath -Name "EnableLUA" -Value 1 -Type DWord
                Write-Log "  Enabled User Account Control" -Level Info
            }
            
            if ($Config.AdminApprovalMode) {
                Set-ItemProperty -Path $uacPath -Name "FilterAdministratorToken" -Value 1 -Type DWord
                Write-Log "  Enabled Admin Approval Mode" -Level Info
            }
            
            if ($Config.PromptOnSecureDesktop) {
                Set-ItemProperty -Path $uacPath -Name "PromptOnSecureDesktop" -Value 1 -Type DWord
                Write-Log "  UAC prompts on secure desktop" -Level Info
            }
            
            Write-Log "✓ UAC configured" -Level Success
            
        } catch {
            Write-Log "Failed to configure UAC: $($_.Exception.Message)" -Level Error
        }
    }
}

function Set-NetworkSecurity {
    [CmdletBinding(SupportsShouldProcess)]
    param($Config)
    
    Write-Log "Configuring network security..." -Level Info
    
    if ($PSCmdlet.ShouldProcess("Network Security", "Configure")) {
        try {
            if ($Config.RequireSMB3) {
                Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -ErrorAction SilentlyContinue
                Set-SmbServerConfiguration -EnableSMB2Protocol $false -Force -ErrorAction SilentlyContinue
                Write-Log "  Disabled SMB1 and SMB2, enforcing SMB3" -Level Info
            }
            
            Write-Log "✓ Network security configured" -Level Success
            
        } catch {
            Write-Log "Failed to configure network security: $($_.Exception.Message)" -Level Error
        }
    }
}

function Backup-CurrentConfiguration {
    [CmdletBinding()]
    param(
        [string]$BackupPath
    )
    
    Write-Log "Backing up current configuration..." -Level Info
    
    try {
        New-Item -Path $BackupPath -ItemType Directory -Force | Out-Null
        
        # Backup security policy
        secedit /export /cfg "$BackupPath\SecurityPolicy.inf" /quiet
        
        # Backup firewall rules
        netsh advfirewall export "$BackupPath\FirewallRules.wfw" | Out-Null
        
        # Backup registry keys
        $regKeys = @(
            "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa",
            "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters",
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies"
        )
        
        foreach ($key in $regKeys) {
            if (Test-Path $key) {
                $fileName = $key.Replace(":", "").Replace("\", "_") + ".reg"
                reg export $key "$BackupPath\$fileName" /y | Out-Null
            }
        }
        
        # Export current services state
        Get-Service | Select-Object Name, Status, StartType | Export-Csv "$BackupPath\Services.csv" -NoTypeInformation
        
        Write-Log "✓ Configuration backed up to: $BackupPath" -Level Success
        
    } catch {
        Write-Log "Failed to backup configuration: $($_.Exception.Message)" -Level Error
    }
}

Export-ModuleMember -Function Apply-SecurityHardening, Backup-CurrentConfiguration
