# File Structure

```
Server Bootstrap/
│
├── Bootstrap-Server.ps1              Main orchestrator script
├── Validate-Hardening.ps1            Compliance validation utility
├── Rollback-Configuration.ps1        Configuration rollback tool
│
├── Config/                           Configuration Files
│   ├── hardening-profiles.json       Security profiles (Basic/Moderate/Strict)
│   ├── firewall-rules.json           Firewall rule definitions
│   └── audit-policies.json           Audit policy configurations
│
├── Modules/                          PowerShell Modules
│   ├── ServerRoles.psm1              IIS, DNS, ADDS, Hyper-V, Clustering
│   ├── SecurityHardening.psm1        Password policies, account security
│   ├── FirewallConfig.psm1           Firewall management
│   ├── AuditConfig.psm1              Audit policies & event logs
│   ├── RemoteAccess.psm1             WinRM & RDP hardening
│   ├── Validation.psm1               Compliance checking
│   └── Reporting.psm1                HTML report generation
│
├── Logs/                             Execution logs (auto-created)
│   └── Bootstrap-YYYY-MM-DD-HHMM.log Timestamped log files
│
├── Backups/                          Configuration backups (auto-created)
│   └── Backup-YYYY-MM-DD-HHMM/       Timestamped backup directories
│       ├── SecurityPolicy.inf        Security policy export
│       ├── FirewallRules.wfw         Firewall rules export
│       ├── Services.csv              Service states
│       └── HKLM_*.reg                Registry backups
│
├── Reports/                          HTML compliance reports (auto-created)
│   └── Report-YYYY-MM-DD-HHMM.html   Compliance reports
│
└── Documentation/
    ├── README.md                     Comprehensive documentation
    ├── QUICKSTART.md                 Quick reference guide
    ├── EXAMPLES.md                   Usage scenarios
    ├── CHANGELOG.md                  Version history
    └── PROJECT-SUMMARY.md            Project overview
```

| File | Purpose | Lines | Key Features |
|------|---------|-------|--------------|
| `Bootstrap-Server.ps1` | Main orchestrator | 400+ | Pre-flight checks, role installation, hardening, reporting |
| `Validate-Hardening.ps1` | Validation tool | 150+ | Compliance checking, console output, HTML reports |
| `Rollback-Configuration.ps1` | Rollback utility | 100+ | Restore policies, firewall, registry, services |
