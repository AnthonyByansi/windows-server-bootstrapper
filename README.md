# Windows Server Bootstrap & Hardening Automation

PowerShell automation framework for bootstrapping and hardening Windows Server environments with CIS-inspired security baselines.

## Features

- Server role installation (IIS, DNS, AD DS, Hyper-V, Failover Clustering)
- Security hardening with three profiles (Basic, Moderate, Strict)
- Automated firewall configuration
- Advanced audit policy management
- WinRM and RDP hardening
- Pre-flight validation and compliance reporting
- Automatic backup and rollback capability

## Quick Start

### Prerequisites
- Windows Server 2016/2019/2022
- PowerShell 5.1 or later
- Administrator privileges

### Basic Usage

```powershell
# Run with default settings (moderate hardening)
.\Bootstrap-Server.ps1

# Run with specific profile
.\Bootstrap-Server.ps1 -HardeningProfile Strict

# Install specific roles only
.\Bootstrap-Server.ps1 -Roles IIS,DNS -SkipHardening

# Dry run (no changes made)
.\Bootstrap-Server.ps1 -WhatIf

# Generate compliance report only
.\Bootstrap-Server.ps1 -ReportOnly
```

## Project Structure

```
Server Bootstrap/
├── Bootstrap-Server.ps1          # Main entry point
├── Config/
│   ├── hardening-profiles.json  # Hardening profiles (Basic/Moderate/Strict)
│   ├── firewall-rules.json      # Firewall rule definitions
│   └── audit-policies.json      # Audit policy configuration
├── Modules/
│   ├── ServerRoles.psm1         # Role/Feature installation
│   ├── SecurityHardening.psm1   # CIS hardening functions
│   ├── FirewallConfig.psm1      # Firewall management
│   ├── AuditConfig.psm1         # Audit policy configuration
│   ├── RemoteAccess.psm1        # WinRM/RDP hardening
│   ├── Validation.psm1          # Pre/post checks
│   └── Reporting.psm1           # HTML report generation
├── Logs/                        # Execution logs
├── Backups/                     # Configuration backups
└── Reports/                     # HTML compliance reports
```

## Hardening Profiles

### Basic
- Essential security hardening
- Minimal disruption to services
- Good for development environments

### Moderate (Default)
- Balanced security and usability
- CIS Level 1 inspired
- Recommended for most production servers

### Strict
- Maximum security hardening
- May impact some applications
- For high-security environments

## Security Controls

### Password & Account Policies
- Minimum password length: 14 characters
- Password complexity requirements
- Password history: 24 passwords
- Account lockout threshold: 5 attempts
- Administrator account renaming
- Guest account disabled

### Audit Policies
- Logon/Logoff events
- Account management
- Policy changes
- Privilege use
- Object access
- Process tracking
- System events

### Network Security
- SMB signing required
- LM hash storage disabled
- NTLM authentication restricted
- Anonymous enumeration blocked
- Null session pipes restricted

### Firewall Rules
- Default deny inbound
- Role-specific rules (IIS: 80/443, DNS: 53, RDP: 3389, etc.)
- Anti-malware communication allowed
- Windows Update access permitted

## Reports

The script generates detailed HTML reports including:
- Applied configurations
- Warnings and recommendations
- Compliance status
- Validation results
- Execution timeline

## Versioning

This project follows [Semantic Versioning](https://semver.org/) (MAJOR.MINOR.PATCH).

- **Current Version:** v1.0.0
- **Release Tags:** All releases are tagged in git (e.g., `v1.0.0`, `v1.1.0`)
- **Version Management:** Use `Manage-Version.ps1` to bump versions and create release tags

For details on versioning strategy and release process, see [VERSIONING.md](VERSIONING.md).

## Rollback

All original configurations are backed up to `./Backups/` with timestamps. To rollback:

```powershell
.\Rollback-Configuration.ps1 -BackupDate "2026-01-06-1430"
```

## Advanced Configuration

Edit configuration files in `./Config/` to customize:
- Hardening profiles
- Firewall rules
- Audit policies
- Role-specific settings

## Testing

```powershell
# Validate current hardening status
.\Validate-Hardening.ps1

# Compare against profile
.\Validate-Hardening.ps1 -Profile Strict
```

## Logging

Logs are written to `./Logs/Bootstrap-YYYY-MM-DD-HHMM.log` with:
- Timestamps for all operations
- Success/failure status
- Error details
- Configuration changes

## Contributing

This is a bootstrap framework - customize it for your environment:
1. Fork the repository
2. Add your organization-specific hardening
3. Customize roles and features
4. Extend reporting as needed

## Warnings

- **Always test in non-production first**
- Review hardening profiles before applying
- Some settings may break specific applications
- Backup your system before running
- Review firewall rules for your environment

## References

- CIS Microsoft Windows Server Benchmarks
- Microsoft Security Baselines
- DISA STIGs for Windows Server
- NSA Cybersecurity Guidance

## License

Use at your own risk. 

---

**Created:** January 2026  
**Version:** 1.0.0 ([Release History](CHANGELOG.md) | [Versioning](VERSIONING.md))  
**Tested on:** Windows Server 2019/2022
