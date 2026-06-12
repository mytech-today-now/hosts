# Hosts File Manager

**Cross-platform ad/malware blocking via the system hosts file.**

Part of the [myTech.Today](https://mytech.today) PowerShell toolkit.

## Features

- **Cross-Platform** — Windows, macOS, and Linux
- **Ad & Malware Blocking** — Downloads rules from [someonewhocares.org](https://someonewhocares.org/hosts/hosts)
- **Smart Merging** — Preserves your custom host entries
- **Automatic Backups** — Timestamped backups before every change (max 10 retained)
- **DNS Cache Flush** — Platform-specific flush after update
- **Restore** — Roll back to any previous backup

## Quick Start

```powershell
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy Unrestricted

# Windows: Run as Administrator | macOS/Linux: sudo pwsh
.\hosts.ps1
```

## Usage

```powershell
.\hosts.ps1                     # Update hosts file
.\hosts.ps1 -WhatIf             # Preview changes
.\hosts.ps1 -Force              # Skip prompts
.\hosts.ps1 -BackupOnly         # Backup only
.\hosts.ps1 -RestoreBackup      # Restore latest backup
.\hosts.ps1 -SkipDNSFlush       # Update without DNS flush
```

## Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `-BackupOnly` | Switch | Backup current hosts file without updating |
| `-RestoreBackup` | Switch | Restore from most recent backup |
| `-BackupPath` | String | Specific backup file to restore |
| `-SkipDNSFlush` | Switch | Skip DNS cache flush |
| `-Force` | Switch | Skip confirmation prompts |
| `-WhatIf` | Switch | Preview without applying |

## Requirements

- PowerShell 7.0+ (Core), elevated privileges, internet connection

## File Locations

| Platform | Hosts File | Backups | Logs |
|----------|-----------|---------|------|
| Windows | `C:\Windows\System32\drivers\etc\hosts` | `%USERPROFILE%\myTech.Today\hosts\backups\` | `%USERPROFILE%\myTech.Today\logs\hosts.YYYY-MM.md` |
| macOS/Linux | `/etc/hosts` | `~/myTech.Today/hosts/backups/` | `~/myTech.Today/logs/hosts.YYYY-MM.md` |

---

### About myTech.Today

**Safe. Secure. Support. Solutions.** — Midwest IT services including Managed IT, Cyber Security, Cloud Solutions, AI & Automation, and PowerShell tooling.

📧 [sales@mytech.today](mailto:sales@mytech.today) · 🌐 [mytech.today](https://mytech.today) · 💻 [@mytech-today-now](https://github.com/mytech-today-now)

© 2025 myTech.Today. All rights reserved.
