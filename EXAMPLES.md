# Example Usage Scenarios

## Scenario 1: Fresh IIS Web Server (Moderate Security)

Deploy a new web server with moderate hardening:

```powershell
# Step 1: Review configuration
Get-Content .\Config\hardening-profiles.json

# Step 2: Preview changes
.\Bootstrap-Server.ps1 -Roles IIS -HardeningProfile Moderate -WhatIf

# Step 3: Apply configuration
.\Bootstrap-Server.ps1 -Roles IIS -HardeningProfile Moderate

# Step 4: Validate
.\Validate-Hardening.ps1 -Profile Moderate
```

**Expected Results:**
- IIS installed with secure defaults
- Directory browsing disabled
- Server headers removed
- Moderate password policies applied
- Firewall rules for HTTP/HTTPS
- Comprehensive audit logging

---

## Scenario 2: Active Directory Domain Controller (Strict Security)

Deploy a domain controller with maximum security:

```powershell
# Install AD DS role with strict hardening
.\Bootstrap-Server.ps1 -Roles ADDS -HardeningProfile Strict

# After running, promote the server to DC manually:
Install-ADDSForest -DomainName "contoso.local" -InstallDNS
```

**Security Applied:**
- 16-character minimum password length
- 3-attempt lockout threshold
- SMB signing required
- NTLM restricted
- Advanced audit policies
- PowerShell logging enabled

---

## Scenario 3: Hyper-V Virtualization Host

Deploy a Hyper-V host for production:

```powershell
# Install Hyper-V with moderate hardening
.\Bootstrap-Server.ps1 -Roles HyperV -HardeningProfile Moderate

# System will require reboot
Restart-Computer
```

**Configuration Includes:**
- Hyper-V role and management tools
- Hyper-V firewall rules
- Live migration configuration
- Security hardening for host

---

## Scenario 4: Multi-Role Server (File Server + DNS)

Deploy a file server that also provides DNS:

```powershell
# Install both roles
.\Bootstrap-Server.ps1 -Roles DNS -HardeningProfile Moderate

# DNS is installed, configure as needed
# File Server role can be added separately via Add-WindowsFeature
```

---

## Scenario 5: Security Assessment Only

Generate a compliance report without making changes:

```powershell
# Generate report without changes
.\Bootstrap-Server.ps1 -ReportOnly

# Or validate against strict profile
.\Validate-Hardening.ps1 -Profile Strict
```

**Use Cases:**
- Initial security assessment
- Compliance auditing
- Before/after comparison

---

## Scenario 6: Incremental Hardening

Apply only security hardening to existing server:

```powershell
# Apply hardening without installing new roles
.\Bootstrap-Server.ps1 -HardeningProfile Moderate

# Or skip specific components
.\Bootstrap-Server.ps1 -HardeningProfile Strict -SkipFirewall
```

---

## Scenario 7: Custom Configuration

Modify configuration before applying:

```powershell
# 1. Edit configuration file
notepad .\Config\hardening-profiles.json

# 2. Customize your profile (e.g., change password length)
# Find "Moderate" profile and modify MinimumPasswordLength to 12

# 3. Apply custom configuration
.\Bootstrap-Server.ps1 -HardeningProfile Moderate

# 4. Validate
.\Validate-Hardening.ps1 -Profile Moderate
```

---

## Scenario 8: Disaster Recovery / Rollback

Restore previous configuration:

```powershell
# List available backups
Get-ChildItem .\Backups\

# Rollback to specific backup
.\Rollback-Configuration.ps1 -BackupPath ".\Backups\Backup-2026-01-06-1430"

# Reboot to complete rollback
Restart-Computer
```

---

## Scenario 9: Development Environment (Basic Security)

Set up a development server with minimal restrictions:

```powershell
# Apply basic hardening (less restrictive)
.\Bootstrap-Server.ps1 -Roles IIS -HardeningProfile Basic

# Basic profile allows:
# - 10-character passwords (vs 14/16)
# - 10-attempt lockout (vs 5/3)
# - More relaxed security settings
```

---

## Scenario 10: Batch Deployment

Deploy to multiple servers using remoting:

```powershell
# Define target servers
$servers = @("WEB-01", "WEB-02", "WEB-03")

# Deploy to all servers
foreach ($server in $servers) {
    Invoke-Command -ComputerName $server -ScriptBlock {
        cd "C:\Deployment\ServerBootstrap"
        .\Bootstrap-Server.ps1 -Roles IIS -HardeningProfile Moderate
    }
}

# Collect reports
foreach ($server in $servers) {
    Copy-Item "\\$server\C$\Deployment\ServerBootstrap\Reports\*" `
              ".\CollectedReports\$server\" -Recurse
}
```

---

## Best Practices

### 1. Always Test First
```powershell
# Use WhatIf to preview
.\Bootstrap-Server.ps1 -WhatIf

# Test in lab environment
# Review generated report
```

### 2. Create Baseline Backup
```powershell
# Before first run
.\Bootstrap-Server.ps1 -BackupOnly

# Keep the backup safe for disaster recovery
```

### 3. Incremental Approach
```powershell
# Day 1: Basic hardening
.\Bootstrap-Server.ps1 -HardeningProfile Basic

# Day 7: Upgrade to Moderate (after testing)
.\Bootstrap-Server.ps1 -HardeningProfile Moderate

# Day 30: Upgrade to Strict (if needed)
.\Bootstrap-Server.ps1 -HardeningProfile Strict
```

### 4. Regular Validation
```powershell
# Weekly validation check
.\Validate-Hardening.ps1 -Profile Moderate

# Review compliance reports
# Address any failures or warnings
```

### 5. Document Changes
```powershell
# Keep logs of all runs
Get-ChildItem .\Logs\ | Sort-Object LastWriteTime -Descending

# Maintain change log
# Document any custom modifications
```

---

## Troubleshooting Common Issues

### Issue: Script requires Administrator privileges
```powershell
# Solution: Run PowerShell as Administrator
Start-Process powershell -Verb RunAs
```

### Issue: Execution policy blocks script
```powershell
# Solution: Set execution policy
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### Issue: Some settings don't apply
```powershell
# Solution: Check for pending reboot
Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending"

# Reboot if true
Restart-Computer
```

### Issue: Need to undo specific setting
```powershell
# Solution: Use rollback script
.\Rollback-Configuration.ps1 -BackupPath ".\Backups\[latest]"

# Or manually adjust in registry/policy
```

---

## Integration with DSC (Desired State Configuration)

The bootstrap script can be integrated with DSC:

```powershell
# 1. Run bootstrap for initial setup
.\Bootstrap-Server.ps1 -HardeningProfile Moderate

# 2. Create DSC configuration to maintain state
# 3. Apply DSC configuration for drift detection

# Export current state as DSC
# (Custom script needed for full DSC integration)
```

---

## Scheduled Compliance Checks

Set up automated validation:

```powershell
# Create scheduled task for weekly validation
$action = New-ScheduledTaskAction -Execute "PowerShell.exe" `
    -Argument "-File C:\ServerBootstrap\Validate-Hardening.ps1 -Profile Moderate"

$trigger = New-ScheduledTaskTrigger -Weekly -At 2am -DaysOfWeek Monday

Register-ScheduledTask -TaskName "WeeklySecurityValidation" `
    -Action $action -Trigger $trigger -RunLevel Highest
```

---

## Environment-Specific Customization

Create organization-specific profiles:

```powershell
# Copy moderate profile as template
$config = Get-Content .\Config\hardening-profiles.json | ConvertFrom-Json

# Add custom "Corporate" profile
$config.Profiles | Add-Member -MemberType NoteProperty -Name "Corporate" -Value $config.Profiles.Moderate

# Customize settings
$config.Profiles.Corporate.PasswordPolicy.MinimumPasswordLength = 12

# Save updated configuration
$config | ConvertTo-Json -Depth 10 | Out-File .\Config\hardening-profiles.json

# Use custom profile
.\Bootstrap-Server.ps1 -HardeningProfile Corporate
```
