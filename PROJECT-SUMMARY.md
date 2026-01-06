# Windows Server Bootstrap & Hardening Automation

PowerShell automation framework for deploying and hardening Windows Server environments with CIS-inspired security baselines.

## Components

### Core Scripts
- Bootstrap-Server.ps1 - Main orchestrator  
- Validate-Hardening.ps1 - Compliance validator
- Rollback-Configuration.ps1 - Rollback utility

### PowerShell Modules
- ServerRoles.psm1 - Role installation
- SecurityHardening.psm1 - Security controls
- FirewallConfig.psm1 - Firewall management
- AuditConfig.psm1 - Audit policies
- RemoteAccess.psm1 - WinRM/RDP hardening
- Validation.psm1 - Compliance checking
- Reporting.psm1 - HTML reports

### Configuration Files
- hardening-profiles.json - Security profiles
- firewall-rules.json - Firewall rules
- audit-policies.json - Audit settings

## Key Features

- Automated server hardening with 3 security profiles
- 50+ CIS-inspired security controls
- Server role deployment (IIS, DNS, ADDS, Hyper-V, Clustering)
- Automated firewall configuration
- Advanced audit policies
- Pre-flight validation
- HTML compliance reports
- Automatic backup and rollback

## Security Profiles

| Profile | Password | Lockout | Use Case |
|---------|----------|---------|----------|
| Basic | 10 chars | 10 attempts | Development |
| Moderate | 14 chars | 5 attempts | Production |
| Strict | 16 chars | 3 attempts | High Security |

## Usage

```powershell
# Default installation
.\Bootstrap-Server.ps1

# With specific role and profile
.\Bootstrap-Server.ps1 -Roles IIS -HardeningProfile Strict

# Validation
.\Validate-Hardening.ps1 -Profile Moderate

# Rollback
.\Rollback-Configuration.ps1 -BackupPath ".\Backups\[timestamp]"
```

## Project Statistics

- Lines of Code: 3,500+
- Modules: 7
- Security Controls: 50+
- Validation Checks: 30+
- Documentation: 5 files

**Version**: 1.0.0  
**Release**: January 2026

### 3. **Intelligent Pre-Flight Checks**
Validates environment before making changes:
- PowerShell version
- Admin privileges
- Disk space
- Network connectivity
- Pending reboots

### 4. **Comprehensive Backup System**
Auto-backs up:
- Security policies (secedit)
- Firewall rules (netsh)
- Registry keys (reg export)
- Service states (CSV)

### 5. **Modular Architecture**
Each component is independent and can be:
- Used separately
- Customized easily
- Extended with new features
- Tested in isolation

### 6. **Role-Aware Firewall**
Automatically configures firewall rules based on installed server roles - no manual configuration needed.

### 7. **Validation Framework**
Built-in compliance checking with:
- Expected vs actual comparison
---

## Technology Stack

- PowerShell 5.1+
- Windows Server 2016/2019/2022
- JSON configuration
- HTML5/CSS3 reporting
- Tools: secedit, auditpol, netsh, bcdedit, reg

---

## Project Structure

```
Server Bootstrap/
│
├── Bootstrap-Server.ps1              Main orchestrator (400+ lines)
├── Validate-Hardening.ps1            Validation utility (150+ lines)
├── Rollback-Configuration.ps1        Rollback utility (100+ lines)
│
├── Config/
│   ├── hardening-profiles.json       3 security profiles
│   ├── firewall-rules.json           Firewall rule definitions
│   └── audit-policies.json           Audit configurations
│
├── Modules/
│   ├── ServerRoles.psm1              Role installation (300+ lines)
│   ├── SecurityHardening.psm1        Security controls (450+ lines)
│   ├── FirewallConfig.psm1           Firewall management (300+ lines)
│   ├── AuditConfig.psm1              Audit policies (350+ lines)
│   ├── RemoteAccess.psm1             WinRM/RDP (300+ lines)
│   ├── Validation.psm1               Compliance checks (350+ lines)
│   └── Reporting.psm1                HTML reports (400+ lines)
│
├── Logs/                             Execution logs
├── Backups/                          Configuration backups
├── Reports/                          HTML compliance reports
│
└── Documentation/
    ├── README.md                     Main documentation
    ├── QUICKSTART.md                 Quick reference
    ├── EXAMPLES.md                   Usage scenarios
    ├── CHANGELOG.md                  Version history
    └── PROJECT-SUMMARY.md            Project overview
```

---

## Use Cases

- Enterprise IT: Standardize deployments, ensure compliance
- Managed Service Providers: Rapid onboarding, consistent security
- Security Teams: Baseline enforcement, audit preparation
- Development Teams: Dev/test environment setup

---

## Best Practices

- Least Privilege: Minimal permissions by default
- Defense in Depth: Multiple security layers
- Fail Secure: Default deny policies
- Audit Everything: Comprehensive logging
- Backup First: Always create restore point
- Validate After: Post-installation checks
- Document Changes: Detailed logging and reporting
- Idempotent: Safe to run multiple times

---

## Prerequisites

- Windows Server 2016+
- PowerShell 5.1+
- Administrator privileges
- 10GB+ free disk space
- Network connectivity

---

## Future Enhancements

- DSC integration for drift detection
- GPO export/import functionality
- Certificate management automation
- STIG compliance profile
- Multi-server orchestration
- Web-based dashboard
- Email reporting
- Integration with SIEM systems

---

## License & Disclaimer

This project is provided as-is for educational and professional use.

**Important**: Test thoroughly before production. Review all changes. Understand each security control. Maintain backups.

---

**Version**: 1.0.0  
**Release**: January 2026  
**Status**: Production Ready
