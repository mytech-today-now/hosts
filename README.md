# Hosts File Manager

**Version:** 2.0.0
**Author:** myTech.Today
**PowerShell Version:** 7.0+ (PowerShell Core)
**Platforms:** Windows, macOS, Linux

## Overview

The `hosts.ps1` script manages the system hosts file by downloading and merging ad-blocking/malware-blocking rules from [someonewhocares.org](https://someonewhocares.org/hosts/hosts) while preserving existing custom host entries.

**Cross-Platform Support:**

- Windows: `C:\Windows\System32\drivers\etc\hosts`
- macOS: `/etc/hosts`
- Linux: `/etc/hosts`

## Features

- **Cross-Platform Compatibility** - Works on Windows, macOS, and Linux
- **Elevated Privilege Check** - Ensures script runs with proper permissions (Administrator on Windows, root on macOS/Linux)
- **Automatic Backups** - Creates timestamped backups before making changes
- **Smart Merging** - Preserves custom host entries while adding blocking rules
- **DNS Cache Flush** - Automatically applies changes by flushing DNS cache (platform-specific)
- **Comprehensive Logging** - Follows myTech.Today standards with monthly log rotation
- **WhatIf Support** - Preview changes without applying them
- **Restore Capability** - Restore from any previous backup
- **Error Handling** - Robust error handling with detailed logging

## Requirements

- **PowerShell 7.0 or later** (PowerShell Core) - [Install PowerShell](https://docs.microsoft.com/en-us/powershell/scripting/install/installing-powershell)
- Elevated privileges:
  - **Windows:** Run PowerShell as Administrator
  - **macOS/Linux:** Run with `sudo pwsh` or as root
- Internet connection (for downloading blocking rules)

## Installation

1. Copy `hosts.ps1` to your desired location
2. Run PowerShell with elevated privileges:
   - **Windows:** Run PowerShell as Administrator
   - **macOS/Linux:** Run `sudo pwsh`
3. Execute the script with desired parameters

## Usage

### Basic Usage

```powershell
# Update hosts file with latest blocking rules
.\hosts.ps1

# Preview changes without applying (WhatIf)
.\hosts.ps1 -WhatIf

# Update without confirmation prompts
.\hosts.ps1 -Force
```

### Backup Operations

```powershell
# Create backup only (no update)
.\hosts.ps1 -BackupOnly

# Restore from most recent backup
.\hosts.ps1 -RestoreBackup

# Restore from specific backup
.\hosts.ps1 -RestoreBackup -BackupPath "C:\Users\YourName\myTech.Today\hosts\backups\hosts.backup.2025-11-21_143022"
```

### Advanced Options

```powershell
# Update without flushing DNS cache
.\hosts.ps1 -SkipDNSFlush

# Combine parameters
.\hosts.ps1 -Force -SkipDNSFlush
```

## Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `-BackupOnly` | Switch | Creates backup of current hosts file without updating |
| `-RestoreBackup` | Switch | Restores hosts file from most recent backup |
| `-BackupPath` | String | Specific backup file to restore (used with -RestoreBackup) |
| `-SkipDNSFlush` | Switch | Skip DNS cache flush after updating hosts file |
| `-Force` | Switch | Skip confirmation prompts |
| `-WhatIf` | Switch | Preview changes without applying them |

## File Locations

### Hosts File

| Platform | Path |
|----------|------|
| Windows | `C:\Windows\System32\drivers\etc\hosts` |
| macOS | `/etc/hosts` |
| Linux | `/etc/hosts` |

### Backups and Logs

| Platform | Backups | Logs |
|----------|---------|------|
| Windows | `%USERPROFILE%\myTech.Today\hosts\backups\` | `%USERPROFILE%\myTech.Today\logs\hosts.YYYY-MM.md` |
| macOS/Linux | `~/myTech.Today/hosts/backups/` | `~/myTech.Today/logs/hosts.YYYY-MM.md` |

## How It Works

1. **Platform Detection** - Automatically detects Windows, macOS, or Linux
2. **Privilege Check** - Verifies elevated privileges (Administrator or root)
3. **Backup Creation** - Creates timestamped backup of current hosts file
4. **Download Rules** - Fetches latest blocking rules from someonewhocares.org
5. **Extract Custom Entries** - Identifies and preserves custom host entries
6. **Merge Content** - Combines blocking rules with custom entries
7. **Update Hosts File** - Writes merged content to system hosts file
8. **Flush DNS Cache** - Clears DNS cache using platform-specific commands

## Custom Entries

The script automatically preserves custom host entries that are not part of the someonewhocares.org blocking list. Custom entries are identified by:

- Entries that don't contain "someonewhocares.org" references
- Entries in the custom section (marked by the script)
- User-added comments and configurations

Custom entries are appended to the end of the merged hosts file with a clear section marker:

```text
# === Custom Host Entries (Preserved by myTech.Today hosts.ps1) ===
```

## Backup Management

- Backups are created with timestamp format: `hosts.backup.YYYY-MM-DD_HHmmss`
- Maximum of 10 backups are kept (oldest are automatically deleted)
- Each backup operation logs the file path and size
- Backups can be restored at any time using the `-RestoreBackup` parameter

## Logging

All operations are logged following myTech.Today standards:

- **Log Location:** `%USERPROFILE%\myTech.Today\logs\hosts.YYYY-MM.md`
- **Log Format:** Markdown table format
- **Log Rotation:** Monthly (one file per month)
- **Log Levels:** INFO, WARN, ERROR

Example log entry:

```markdown
| 2025-11-21 14:30:22 | [INFO] | Hosts file update completed successfully |
```

## Error Handling

The script includes comprehensive error handling:

- Network errors during download
- File permission errors
- Invalid backup paths
- DNS flush failures
- Detailed error logging with stack traces

## Exit Codes

- `0` - Success
- `1` - Error (check logs for details)

## Examples

### Example 1: First-time Setup

```powershell
# Windows: Run PowerShell as Administrator
.\hosts.ps1

# macOS/Linux: Run with sudo
sudo pwsh -File hosts.ps1
```

### Example 2: Regular Updates

```powershell
# Update with latest blocking rules (no prompts)
.\hosts.ps1 -Force
```

### Example 3: Testing Changes

```powershell
# Preview what would change
.\hosts.ps1 -WhatIf
```

### Example 4: Backup Before Manual Edit

```powershell
# Create backup before manually editing hosts file
.\hosts.ps1 -BackupOnly
```

### Example 5: Restore After Problem

```powershell
# Restore from most recent backup
.\hosts.ps1 -RestoreBackup
```

## Troubleshooting

### "Access Denied" or "Permission Denied" Error

**Windows:**

- Ensure you're running PowerShell as Administrator
- Check file permissions on the hosts file

**macOS/Linux:**

- Run with `sudo pwsh` or as the root user
- Check file permissions: `ls -la /etc/hosts`
- Reset permissions if needed: `sudo chmod 644 /etc/hosts`

### "Download Failed" Error

- Verify internet connection
- Check if someonewhocares.org is accessible
- Review firewall/proxy settings

### Custom Entries Not Preserved

- Check log file for details on what was detected
- Ensure custom entries don't contain "someonewhocares.org" references
- Manually add entries after update if needed

### DNS Not Flushing on Linux

Some Linux distributions don't have a DNS cache by default. If DNS flush fails:

- The script will continue without error
- Changes will take effect on the next DNS lookup
- Try restarting the network service if needed

## Support

For issues, questions, or contributions:

- GitHub: <https://github.com/mytech-today-now/PowerShellScripts>
- Check logs:
  - Windows: `%USERPROFILE%\myTech.Today\logs\hosts.YYYY-MM.md`
  - macOS/Linux: `~/myTech.Today/logs/hosts.YYYY-MM.md`

## License

Part of the myTech.Today PowerShell Scripts collection.

## Changelog

### Version 2.0.0 (2025-12-14)

- **Cross-platform support** for Windows, macOS, and Linux
- Platform-specific hosts file path detection using `$IsWindows`, `$IsMacOS`, `$IsLinux`
- Cross-platform elevated privilege detection (Administrator on Windows, root on macOS/Linux)
- Platform-specific DNS cache flush commands
- Updated documentation for multi-platform usage
- Requires PowerShell 7.0+ (PowerShell Core)

### Version 1.0.0 (2025-11-21)

- Initial release (Windows-only)
- Download and merge blocking rules from someonewhocares.org
- Preserve custom host entries
- Automatic backup management
- DNS cache flushing
- Comprehensive logging
- WhatIf support
- Restore capability
