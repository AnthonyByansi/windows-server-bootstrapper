<#
.SYNOPSIS
    Validation Module

.DESCRIPTION
    Performs validation checks and compliance verification
#>

function Invoke-ValidationChecks {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Profile
    )
    
    Write-Log "Running validation checks..." -Level Info
    
    $results = @{
        Timestamp = Get-Date
        Profile = $Profile
        OverallStatus = "Pass"
        Categories = @{}
    }
    
    # Validate password policy
    $results.Categories['PasswordPolicy'] = Test-PasswordPolicy -Profile $Profile
    
    # Validate account policy
    $results.Categories['AccountPolicy'] = Test-AccountPolicy -Profile $Profile
    
    # Validate security options
    $results.Categories['SecurityOptions'] = Test-SecurityOptions -Profile $Profile
    
    # Validate firewall
    $results.Categories['Firewall'] = Test-FirewallConfiguration
    
    # Validate audit policies
    $results.Categories['AuditPolicies'] = Test-AuditPolicies -Profile $Profile
    
    # Validate remote access
    $results.Categories['RemoteAccess'] = Test-RemoteAccess -Profile $Profile
    
    # Validate services
    $results.Categories['Services'] = Test-ServiceConfiguration -Profile $Profile
    
    # Calculate overall status
    $failCount = 0
    $warnCount = 0
    foreach ($category in $results.Categories.Values) {
        $failCount += ($category.Checks | Where-Object { $_.Status -eq 'Fail' }).Count
        $warnCount += ($category.Checks | Where-Object { $_.Status -eq 'Warning' }).Count
    }
    
    if ($failCount -gt 0) {
        $results.OverallStatus = "Fail"
    } elseif ($warnCount -gt 0) {
        $results.OverallStatus = "Warning"
    }
    
    Write-Log "Validation completed: $($results.OverallStatus) ($failCount failures, $warnCount warnings)" -Level Info
    
    return $results
}

function Test-PasswordPolicy {
    param([string]$Profile)
    
    $checks = @()
    
    try {
        # Export current policy
        $tempFile = "$env:TEMP\secpol_check.inf"
        secedit /export /cfg $tempFile /quiet
        $policy = Get-Content $tempFile
        Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
        
        # Parse policy
        $minPasswordLength = ($policy | Select-String "MinimumPasswordLength = (\d+)").Matches.Groups[1].Value
        $passwordComplexity = ($policy | Select-String "PasswordComplexity = (\d+)").Matches.Groups[1].Value
        $passwordHistory = ($policy | Select-String "PasswordHistorySize = (\d+)").Matches.Groups[1].Value
        
        # Check minimum password length
        $expectedLength = switch ($Profile) {
            'Basic' { 10 }
            'Moderate' { 14 }
            'Strict' { 16 }
        }
        
        $checks += @{
            Name = "Minimum Password Length"
            Expected = $expectedLength
            Actual = $minPasswordLength
            Status = if ([int]$minPasswordLength -ge $expectedLength) { "Pass" } else { "Fail" }
        }
        
        # Check password complexity
        $checks += @{
            Name = "Password Complexity"
            Expected = "Enabled"
            Actual = if ($passwordComplexity -eq "1") { "Enabled" } else { "Disabled" }
            Status = if ($passwordComplexity -eq "1") { "Pass" } else { "Fail" }
        }
        
        # Check password history
        $checks += @{
            Name = "Password History"
            Expected = "24"
            Actual = $passwordHistory
            Status = if ([int]$passwordHistory -ge 12) { "Pass" } else { "Warning" }
        }
        
    } catch {
        $checks += @{
            Name = "Password Policy Check"
            Expected = "Success"
            Actual = "Error: $($_.Exception.Message)"
            Status = "Fail"
        }
    }
    
    return @{
        Category = "Password Policy"
        Checks = $checks
    }
}

function Test-AccountPolicy {
    param([string]$Profile)
    
    $checks = @()
    
    try {
        # Check if Guest account is disabled
        $guest = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
        $checks += @{
            Name = "Guest Account Disabled"
            Expected = "Disabled"
            Actual = if ($guest.Enabled) { "Enabled" } else { "Disabled" }
            Status = if (-not $guest.Enabled) { "Pass" } else { "Fail" }
        }
        
        # Check if Administrator is renamed
        $admin = Get-LocalUser | Where-Object { $_.SID -like "*-500" }
        $checks += @{
            Name = "Administrator Account Renamed"
            Expected = "Renamed"
            Actual = $admin.Name
            Status = if ($admin.Name -ne "Administrator") { "Pass" } else { "Warning" }
        }
        
    } catch {
        $checks += @{
            Name = "Account Policy Check"
            Expected = "Success"
            Actual = "Error: $($_.Exception.Message)"
            Status = "Fail"
        }
    }
    
    return @{
        Category = "Account Policy"
        Checks = $checks
    }
}

function Test-SecurityOptions {
    param([string]$Profile)
    
    $checks = @()
    
    try {
        # Check SMB signing
        $smbSigning = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "RequireSecuritySignature" -ErrorAction SilentlyContinue
        $checks += @{
            Name = "SMB Signing Required"
            Expected = "Enabled"
            Actual = if ($smbSigning.RequireSecuritySignature -eq 1) { "Enabled" } else { "Disabled" }
            Status = if ($smbSigning.RequireSecuritySignature -eq 1) { "Pass" } else { "Warning" }
        }
        
        # Check LM hash disabled
        $noLMHash = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "NoLMHash" -ErrorAction SilentlyContinue
        $checks += @{
            Name = "LM Hash Storage Disabled"
            Expected = "Disabled"
            Actual = if ($noLMHash.NoLMHash -eq 1) { "Disabled" } else { "Enabled" }
            Status = if ($noLMHash.NoLMHash -eq 1) { "Pass" } else { "Fail" }
        }
        
        # Check NTLMv2
        $ntlmLevel = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel" -ErrorAction SilentlyContinue
        $checks += @{
            Name = "NTLMv2 Authentication Required"
            Expected = "Level 5"
            Actual = "Level $($ntlmLevel.LmCompatibilityLevel)"
            Status = if ($ntlmLevel.LmCompatibilityLevel -ge 5) { "Pass" } else { "Fail" }
        }
        
    } catch {
        $checks += @{
            Name = "Security Options Check"
            Expected = "Success"
            Actual = "Error: $($_.Exception.Message)"
            Status = "Fail"
        }
    }
    
    return @{
        Category = "Security Options"
        Checks = $checks
    }
}

function Test-FirewallConfiguration {
    $checks = @()
    
    try {
        # Check firewall status for all profiles
        $profiles = Get-NetFirewallProfile
        
        foreach ($profile in $profiles) {
            $checks += @{
                Name = "Firewall Enabled - $($profile.Name)"
                Expected = "Enabled"
                Actual = if ($profile.Enabled) { "Enabled" } else { "Disabled" }
                Status = if ($profile.Enabled) { "Pass" } else { "Fail" }
            }
        }
        
        # Check default inbound action
        $domainProfile = $profiles | Where-Object { $_.Name -eq 'Domain' }
        $checks += @{
            Name = "Default Inbound Action"
            Expected = "Block"
            Actual = $domainProfile.DefaultInboundAction
            Status = if ($domainProfile.DefaultInboundAction -eq 'Block') { "Pass" } else { "Warning" }
        }
        
    } catch {
        $checks += @{
            Name = "Firewall Check"
            Expected = "Success"
            Actual = "Error: $($_.Exception.Message)"
            Status = "Fail"
        }
    }
    
    return @{
        Category = "Firewall Configuration"
        Checks = $checks
    }
}

function Test-AuditPolicies {
    param([string]$Profile)
    
    $checks = @()
    
    try {
        # Check key audit policies
        $auditOutput = auditpol /get /category:* 2>&1
        
        # Check logon auditing
        if ($auditOutput -match "Logon.*Success and Failure") {
            $checks += @{
                Name = "Logon Events Audited"
                Expected = "Success and Failure"
                Actual = "Success and Failure"
                Status = "Pass"
            }
        } else {
            $checks += @{
                Name = "Logon Events Audited"
                Expected = "Success and Failure"
                Actual = "Not Configured"
                Status = "Fail"
            }
        }
        
        # Check account management auditing
        if ($auditOutput -match "User Account Management.*Success and Failure") {
            $checks += @{
                Name = "Account Management Audited"
                Expected = "Success and Failure"
                Actual = "Success and Failure"
                Status = "Pass"
            }
        } else {
            $checks += @{
                Name = "Account Management Audited"
                Expected = "Success and Failure"
                Actual = "Not Configured"
                Status = "Warning"
            }
        }
        
    } catch {
        $checks += @{
            Name = "Audit Policy Check"
            Expected = "Success"
            Actual = "Error: $($_.Exception.Message)"
            Status = "Fail"
        }
    }
    
    return @{
        Category = "Audit Policies"
        Checks = $checks
    }
}

function Test-RemoteAccess {
    param([string]$Profile)
    
    $checks = @()
    
    try {
        # Check RDP NLA
        $nla = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "UserAuthentication" -ErrorAction SilentlyContinue
        $checks += @{
            Name = "RDP Network Level Authentication"
            Expected = "Enabled"
            Actual = if ($nla.UserAuthentication -eq 1) { "Enabled" } else { "Disabled" }
            Status = if ($nla.UserAuthentication -eq 1) { "Pass" } else { "Fail" }
        }
        
        # Check WinRM service
        $winrm = Get-Service -Name WinRM -ErrorAction SilentlyContinue
        if ($winrm) {
            $checks += @{
                Name = "WinRM Service"
                Expected = "Running"
                Actual = $winrm.Status
                Status = if ($winrm.Status -eq 'Running') { "Pass" } else { "Warning" }
            }
        }
        
    } catch {
        $checks += @{
            Name = "Remote Access Check"
            Expected = "Success"
            Actual = "Error: $($_.Exception.Message)"
            Status = "Fail"
        }
    }
    
    return @{
        Category = "Remote Access"
        Checks = $checks
    }
}

function Test-ServiceConfiguration {
    param([string]$Profile)
    
    $checks = @()
    
    try {
        # Check if RemoteRegistry is disabled
        $remoteRegistry = Get-Service -Name RemoteRegistry -ErrorAction SilentlyContinue
        if ($remoteRegistry) {
            $checks += @{
                Name = "Remote Registry Service"
                Expected = "Disabled"
                Actual = $remoteRegistry.StartType
                Status = if ($remoteRegistry.StartType -eq 'Disabled') { "Pass" } else { "Warning" }
            }
        }
        
    } catch {
        $checks += @{
            Name = "Service Configuration Check"
            Expected = "Success"
            Actual = "Error: $($_.Exception.Message)"
            Status = "Fail"
        }
    }
    
    return @{
        Category = "Service Configuration"
        Checks = $checks
    }
}

Export-ModuleMember -Function Invoke-ValidationChecks
