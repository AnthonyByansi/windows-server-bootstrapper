# Changelog

All notable changes to the Windows Server Bootstrap & Hardening Automation project.

## [1.0.0] - 2026-01-06

### Initial Release

#### Features

**Core Functionality**
- Complete server bootstrap and hardening automation
- Support for Windows Server 2016/2019/2022
- Three hardening profiles: Basic, Moderate, Strict
- Automatic backup before applying changes
- Comprehensive HTML reporting
- Validation and compliance checking
- Rollback capability

**Server Roles**
- IIS (Internet Information Services)
- DNS (Domain Name System)
- AD DS (Active Directory Domain Services)
- Hyper-V (Virtualization Platform)
- Failover Clustering

**Security Hardening**
- Password policy configuration (CIS-inspired)
- Account security policies
- Security options (SMB, NTLM, LM Hash)
- Service hardening
- Registry hardening
- UAC configuration
- Network security settings

**Firewall Configuration**
- Automated firewall rule creation
- Role-based rule deployment
- Security-focused block rules
- Global firewall settings
- Logging configuration

**Audit Policies**
- Advanced audit policy configuration
- Event log size and retention settings
- PowerShell script block logging
- PowerShell transcription
- Command line logging in process creation

**Remote Access**
- WinRM hardening (HTTPS preferred, authentication)
- RDP security (NLA, encryption levels)
- Session timeout configuration
- Device redirection controls

**Validation & Reporting**
- Pre-flight environment checks
- Post-installation validation
- HTML compliance reports with charts
- Compliance scoring
- Detailed check results

#### Project Structure

```
Server Bootstrap/
├── Bootstrap-Server.ps1          # Main orchestrator
├── Validate-Hardening.ps1        # Validation utility
├── Rollback-Configuration.ps1    # Rollback utility
├── README.md                     # Comprehensive documentation
├── QUICKSTART.md                 # Quick reference guide
├── EXAMPLES.md                   # Usage scenarios
├── CHANGELOG.md                  # This file
├── Config/
│   ├── hardening-profiles.json  # Security profiles
│   ├── firewall-rules.json      # Firewall configuration
│   └── audit-policies.json      # Audit settings
└── Modules/
    ├── ServerRoles.psm1         # Role installation
    ├── SecurityHardening.psm1   # Hardening functions
    ├── FirewallConfig.psm1      # Firewall management
    ├── AuditConfig.psm1         # Audit configuration
    ├── RemoteAccess.psm1        # WinRM/RDP hardening
    ├── Validation.psm1          # Compliance checks
    └── Reporting.psm1           # HTML report generation
```

#### Security Controls

**Basic Profile**
- 10-character minimum password
- 10-attempt lockout threshold
- Essential service hardening
- Basic audit logging

**Moderate Profile (Default)**
- 14-character minimum password
- 5-attempt lockout threshold
- SMB signing required
- NTLMv2 required
- Comprehensive audit policies
- Recommended for production

**Strict Profile**
- 16-character minimum password
- 3-attempt lockout threshold
- Maximum security restrictions
- NTLM completely blocked
- Page file clearing enabled
- Device redirection disabled
- For high-security environments

#### CIS Benchmark Alignment

Implements controls inspired by:
- CIS Microsoft Windows Server 2019 Benchmark v1.3.0
- CIS Microsoft Windows Server 2022 Benchmark v2.0.0

Key CIS controls included:
- Account Policies
- Local Policies
- Event Log
- System Services
- Windows Firewall
- Advanced Audit Policy Configuration

#### Reporting Features

- Overall compliance score with visual meter
- Category-based check results
- Pass/Fail/Warning status indicators
- System information summary
- Applied changes log
- Professional HTML output
- Auto-opens in browser

#### Utility Scripts

**Validation**
- Standalone validation script
- Profile-based compliance checking
- Console and HTML output
- Automated checks for all security controls

**Rollback**
- Restore previous configuration
- Security policy restoration
- Firewall rule restoration
- Registry key restoration
- Service state restoration

#### Configuration Files

**JSON-based configuration**
- Easy to customize
- Three pre-defined profiles
- Extensible architecture
- Well-documented settings

#### Command-Line Parameters

- `-HardeningProfile`: Select security profile
- `-Roles`: Specify roles to install
- `-SkipHardening`: Skip security hardening
- `-SkipFirewall`: Skip firewall configuration
- `-SkipAuditPolicy`: Skip audit configuration
- `-ReportOnly`: Generate report without changes
- `-WhatIf`: Preview changes
- `-BackupOnly`: Create backup only

#### Pre-Flight Checks

- PowerShell version validation
- Administrator privilege check
- Operating system detection
- Disk space verification
- Network connectivity test
- Pending reboot detection

#### Metrics

- **Total Lines of Code**: ~3,500+
- **Modules**: 7
- **Security Controls**: 50+
- **Validation Checks**: 30+
- **Firewall Rules**: 15+ baseline
- **Audit Categories**: 10+

#### Tested On

- Windows Server 2019 Standard/Datacenter
- Windows Server 2022 Standard/Datacenter
- PowerShell 5.1
- PowerShell 7.x (Core)

#### Documentation

- Comprehensive README with 200+ lines
- Quick start guide
- 10+ usage examples
- API documentation in module comments
- Inline code documentation

#### Known Limitations

- Domain promotion must be done separately for AD DS
- HTTPS listener for WinRM requires manual certificate
- Some settings require system reboot
- SMB1 must be manually uninstalled if present
- Group Policy Objects (GPO) not directly managed

#### Future Enhancements (Planned)

- DSC (Desired State Configuration) integration
- GPO export/import functionality
- Certificate management automation
- STIG compliance profile
- Linux/Container support
- Web-based dashboard
- Multi-server orchestration
- Drift detection and remediation

---

## Version History

### Pre-Release Development
- 2026-01-06: Initial development and testing
- 2026-01-06: v1.0.0 Release

---

## Contributing

We welcome contributions! Areas for improvement:
- Additional server roles
- Enhanced validation checks
- More granular hardening controls
- Performance optimizations
- Bug fixes
- Documentation improvements

---

## Support

For issues, questions, or contributions:
1. Review documentation (README.md, QUICKSTART.md)
2. Check examples (EXAMPLES.md)
3. Review logs in Logs/ directory
4. Test in non-production environment first

---

## License

This project is released as-is for educational and professional use.
Always test thoroughly before production deployment.

---

**Project**: Windows Server Bootstrap & Hardening Automation  
**Version**: 1.0.0  
**Release Date**: January 6, 2026  
**Author**: Server Bootstrap Project  
**Status**: Production Ready
