# Augment AI Prompt: Windows Hosts File Manager with Ad/Malware Blocking

## Objective
Generate a PowerShell 5.1 script `hosts.ps1` that manages the Windows hosts file by downloading and merging ad-blocking/malware-blocking rules from https://someonewhocares.org/hosts/hosts while preserving existing custom host entries.

## Script Requirements

### Script Name
`hosts.ps1`

### Synopsis
Add additional host rules to the Windows hosts file by downloading and merging ad-blocking rules from https://someonewhocares.org/hosts/hosts

### Description
This script will:
1. **Require Administrator privileges** - Must run in Administrator mode
2. **Backup existing hosts file** - Create timestamped backup before making changes
3. **Download current blocking rules** - Fetch the latest version from https://someonewhocares.org/hosts/hosts
4. **Preserve custom entries** - Extract and preserve any custom host entries from the current hosts file
5. **Merge content** - Append the current hosts file custom entries to the end of the downloaded blocking rules
6. **Update hosts file** - Save the merged content to the Windows hosts file location
7. **Flush DNS cache** - Clear DNS cache to apply changes immediately
8. **Log all operations** - Comprehensive logging following myTech.Today standards

### Technical Specifications

**PowerShell Version**: 5.1+
**Execution Policy**: Requires Administrator privileges
**Windows Hosts File Location**: `$env:SystemRoot\System32\drivers\etc\hosts`

### Functionality Requirements

1. **Administrator Check**
   - Verify script is running with Administrator privileges
   - Exit with error if not running as Administrator
   - Provide clear error message with instructions to run as Administrator

2. **Backup Management**
   - Create backup directory: `%USERPROFILE%\myTech.Today\hosts\backups\`
   - Backup filename format: `hosts.backup.YYYY-MM-DD_HHmmss`
   - Keep last 10 backups, delete older ones
   - Log backup creation with file path and size

3. **Download Blocking Rules**
   - URL: `https://someonewhocares.org/hosts/hosts`
   - Use `Invoke-WebRequest` with proper error handling
   - Validate downloaded content (check for valid hosts file format)
   - Handle network errors gracefully
   - Log download success/failure with file size

4. **Parse Current Hosts File**
   - Read existing Windows hosts file
   - Identify custom entries (entries NOT from someonewhocares.org)
   - Preserve comments that are user-added
   - Detect section markers to identify custom vs. downloaded content
   - Store custom entries for merging

5. **Merge Content**
   - Start with downloaded blocking rules from someonewhocares.org
   - Add section separator comment: `# === Custom Host Entries (Preserved by myTech.Today hosts.ps1) ===`
   - Append preserved custom entries
   - Ensure proper line endings (CRLF for Windows)
   - Validate merged content format

6. **Update Hosts File**
   - Write merged content to `$env:SystemRoot\System32\drivers\etc\hosts`
   - Set proper file permissions
   - Verify write operation success
   - Handle file lock errors (if hosts file is in use)

7. **DNS Cache Management**
   - Execute `ipconfig /flushdns` to clear DNS cache
   - Capture and log command output
   - Verify DNS flush success

8. **Logging**
   - Log to: `%USERPROFILE%\myTech.Today\logs\hosts.md`
   - Monthly log rotation (one file per month) Log to: `%USERPROFILE%\myTech.Today\logs\hosts.YYYY-MM.md`
   - Use Markdown format with monthly rotation
   - Log levels: INFO, SUCCESS, WARNING, ERROR
   - Include timestamps, operation details, file sizes, entry counts
   - Suppress Write-Progress output: `$ProgressPreference = 'SilentlyContinue'`

### Parameters

```powershell
[CmdletBinding(SupportsShouldProcess=$true)]
param(
    [Parameter(Mandatory = $false)]
    [switch]$BackupOnly,
    # Creates backup of current hosts file without updating

    [Parameter(Mandatory = $false)]
    [switch]$RestoreBackup,
    # Restores hosts file from most recent backup

    [Parameter(Mandatory = $false)]
    [string]$BackupPath,
    # Specific backup file to restore (used with -RestoreBackup)

    [Parameter(Mandatory = $false)]
    [switch]$SkipDNSFlush,
    # Skip DNS cache flush after updating hosts file

    [Parameter(Mandatory = $false)]
    [switch]$Force
    # Skip confirmation prompts
)
```

### myTech.Today Standards Compliance

1. **Follow all guidelines in** `.augment/guidelines.md`
2. **Use ASCII characters only** - NO EMOJI - Use `[OK]`, `[FAIL]`, `[WARN]`, `[INFO]`
3. **Centralized logging** - `%USERPROFILE%\myTech.Today\logs\hosts.md`
4. **Monthly log rotation** - Log to: `%USERPROFILE%\myTech.Today\logs\hosts.YYYY-MM.md`
5. **Script copy location** - `%USERPROFILE%\myTech.Today\hosts\hosts.ps1`
6. **Backup location** - `%USERPROFILE%\myTech.Today\backups\hosts\`
7. **Error handling** - Comprehensive try-catch blocks with detailed error logging
8. **Comment-based help** - Complete with SYNOPSIS, DESCRIPTION, PARAMETER, EXAMPLE, NOTES
9. **Progress suppression** - Set `$ProgressPreference = 'SilentlyContinue'`
10. **Proper exit codes** - 0 for success, non-zero for errors
11. **WhatIf support** - Support `-WhatIf` for testing without making changes

### Example Usage Scenarios

```powershell
# Example 1: Update hosts file with latest blocking rules
.\hosts.ps1

# Example 2: Preview changes without applying (WhatIf)
.\hosts.ps1 -WhatIf

# Example 3: Update without confirmation prompts
.\hosts.ps1 -Force

# Example 4: Create backup only
.\hosts.ps1 -BackupOnly

# Example 5: Restore from most recent backup
.\hosts.ps1 -RestoreBackup

# Example 6: Restore from specific backup
.\hosts.ps1 -RestoreBackup -BackupPath "C:\Users\Kyle\myTech.Today\hosts\backups\hosts.backup.2025-01-21_143022"
```

### Expected Output

Please generate:
1. **Complete PowerShell script** `hosts.ps1` with all functionality
2. **Comment-based help** with comprehensive documentation
3. **Example usage scenarios** (at least 5 examples)
4. **Error handling** for all operations
5. **Logging implementation** following myTech.Today standards

