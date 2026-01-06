# Windows Server Bootstrap & Hardening Automation

## Quick Reference

### Prerequisites
- Windows Server 2016/2019/2022
- PowerShell 5.1 or later
- Administrator privileges
- 10GB+ free disk space

### Basic Usage

#### Run with defaults (Moderate hardening)
```powershell
.\Bootstrap-Server.ps1
```

#### Install specific roles with strict hardening
```powershell
.\Bootstrap-Server.ps1 -HardeningProfile Strict -Roles IIS,DNS
```

#### Generate report only (no changes)
```powershell
.\Bootstrap-Server.ps1 -ReportOnly
```

#### Preview changes without applying (WhatIf)
```powershell
.\Bootstrap-Server.ps1 -WhatIf
```

### Hardening Profiles

| Profile | Description | Use Case |
|---------|-------------|----------|
| **Basic** | Essential security hardening | Development environments |
| **Moderate** | Balanced security (CIS Level 1) | Most production servers |
| **Strict** | Maximum security | High-security environments |

### Available Server Roles

- **IIS** - Internet Information Services
- **DNS** - Domain Name System server
- **ADDS** - Active Directory Domain Services
- **HyperV** - Hyper-V virtualization
- **Clustering** - Failover Clustering

### Key Security Controls

#### Password Policy (Moderate)
- Minimum length: 14 characters
- Complexity: Required
- History: 24 passwords
- Lockout threshold: 5 attempts
- Lockout duration: 30 minutes

#### Account Security
- Administrator account renamed
- Guest account disabled
- Blank password use restricted
- Anonymous access restricted

#### Network Security
- SMB signing required
- LM hash storage disabled
- NTLMv2 required
- LLMNR disabled (Strict)
- NetBIOS disabled (Strict)

#### Audit Policies
- Logon/Logoff events
- Account management
- Policy changes
- Privilege use
- System events
- PowerShell logging

### Firewall Configuration

Default policy:
- **Inbound**: Block (whitelist approach)
- **Outbound**: Allow
- **Logging**: Enabled

Auto-configured rules for:
- Installed server roles
- Windows Update
- Windows Defender
- NTP time sync
- Remote management (WinRM/RDP)

### Utility Scripts

#### Validate Current Hardening
```powershell
.\Validate-Hardening.ps1 -Profile Moderate
```

#### Rollback Configuration
```powershell
.\Rollback-Configuration.ps1 -BackupPath ".\Backups\Backup-2026-01-06-1430"
```

### Directory Structure

```
Server Bootstrap/
├── Bootstrap-Server.ps1          # Main script
├── Validate-Hardening.ps1        # Validation utility
├── Rollback-Configuration.ps1    # Rollback utility
├── Config/                       # Configuration files
├── Modules/                      # PowerShell modules
├── Logs/                         # Execution logs
├── Backups/                      # Configuration backups
└── Reports/                      # HTML reports
```

### Advanced Options

#### Skip specific configurations
```powershell
# Skip hardening, only install roles
.\Bootstrap-Server.ps1 -Roles IIS,DNS -SkipHardening

# Skip firewall configuration
.\Bootstrap-Server.ps1 -SkipFirewall

# Skip audit policy configuration
.\Bootstrap-Server.ps1 -SkipAuditPolicy
```

#### Backup only
```powershell
.\Bootstrap-Server.ps1 -BackupOnly
```

### Configuration Files

#### hardening-profiles.json
Defines security settings for each profile

#### firewall-rules.json
Firewall rule definitions for roles and security

#### audit-policies.json
Audit policy configuration and event log settings

### Validation Checks

The validation system checks:
- Password policy compliance
- Account security settings
- Security options (SMB, NTLM, etc.)
- Firewall status and rules
- Audit policies
- Remote access hardening
- Service configuration

### Reports

HTML reports include:
- Overall compliance score
- Detailed check results
- System information
- Applied changes
- Recommendations

### Important Notes

1. **Always test in non-production first**
2. Review configuration files before applying
3. Backup is automatically created before changes
4. Some settings require reboot to take effect
5. Review firewall rules for your environment
6. Customize profiles in Config/ directory

### Typical Workflow

1. Review and customize configuration files
2. Run with `-WhatIf` to preview changes
3. Create backup: `-BackupOnly`
4. Apply configuration
5. Review generated HTML report
6. Validate: `.\Validate-Hardening.ps1`
7. Reboot if required
8. Monitor logs for issues

### Troubleshooting

#### Script fails to run
- Ensure running as Administrator
- Check PowerShell version: `$PSVersionTable`
- Review execution policy: `Get-ExecutionPolicy`

#### Need to revert changes
```powershell
.\Rollback-Configuration.ps1 -BackupPath ".\Backups\[timestamp]"
```

#### Check what was changed
- Review log file in `Logs/` directory
- Open HTML report in `Reports/` directory

### References

- CIS Microsoft Windows Server Benchmarks
- Microsoft Security Baselines
- DISA STIGs for Windows Server
- PowerShell Gallery: DSC Resources

### Customization

To add custom hardening:
1. Edit `Config/hardening-profiles.json`
2. Add checks to `Modules/Validation.psm1`
3. Update reporting in `Modules/Reporting.psm1`

### License & Disclaimer

Use at your own risk. Always test thoroughly before production deployment.
Review all changes to ensure compatibility with your applications.

---

**Version**: 1.0.0  
**Last Updated**: January 2026
