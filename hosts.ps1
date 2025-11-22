<#
.SYNOPSIS
    Add additional host rules to the Windows hosts file by downloading and merging ad-blocking rules.

.DESCRIPTION
    This script manages the Windows hosts file by downloading ad-blocking/malware-blocking rules
    from https://someonewhocares.org/hosts/hosts while preserving existing custom host entries.
    
    The script will:
    - Require Administrator privileges
    - Backup existing hosts file with timestamped backups
    - Download current blocking rules from someonewhocares.org
    - Preserve custom entries from the current hosts file
    - Merge downloaded rules with custom entries
    - Update the Windows hosts file
    - Flush DNS cache to apply changes immediately
    - Log all operations following myTech.Today standards

.PARAMETER BackupOnly
    Creates backup of current hosts file without updating.

.PARAMETER RestoreBackup
    Restores hosts file from most recent backup.

.PARAMETER BackupPath
    Specific backup file to restore (used with -RestoreBackup).

.PARAMETER SkipDNSFlush
    Skip DNS cache flush after updating hosts file.

.PARAMETER Force
    Skip confirmation prompts and bypass up-to-date check (force update even if already current).

.EXAMPLE
    .\hosts.ps1
    Update hosts file with latest blocking rules.

.EXAMPLE
    .\hosts.ps1 -WhatIf
    Preview changes without applying (WhatIf).

.EXAMPLE
    .\hosts.ps1 -Force
    Update without confirmation prompts.

.EXAMPLE
    .\hosts.ps1 -BackupOnly
    Create backup only.

.EXAMPLE
    .\hosts.ps1 -RestoreBackup
    Restore from most recent backup.

.EXAMPLE
    .\hosts.ps1 -RestoreBackup -BackupPath "C:\Users\Kyle\myTech.Today\hosts\backups\hosts.backup.2025-01-21_143022"
    Restore from specific backup.

.NOTES
    Name:           hosts.ps1
    Author:         myTech.Today
    Version:        1.0.0
    DateCreated:    2025-11-21
    LastModified:   2025-11-21
    Requires:       PowerShell 5.1 or later
                    Administrator privileges
    
    Changelog:
    1.0.0 - Initial release

.LINK
    https://github.com/mytech-today-now/PowerShellScripts
#>

[CmdletBinding(SupportsShouldProcess=$true)]
param(
    [Parameter(Mandatory = $false)]
    [switch]$BackupOnly,

    [Parameter(Mandatory = $false)]
    [switch]$RestoreBackup,

    [Parameter(Mandatory = $false)]
    [string]$BackupPath,

    [Parameter(Mandatory = $false)]
    [switch]$SkipDNSFlush,

    [Parameter(Mandatory = $false)]
    [switch]$Force
)

#region Script Variables

$script:ScriptVersion = "1.0.0"
$script:HostsFileUrl = "https://someonewhocares.org/hosts/hosts"
$script:HostsFilePath = "$env:SystemRoot\System32\drivers\etc\hosts"
$script:BackupDirectory = "$env:USERPROFILE\myTech.Today\hosts\backups"
$script:MaxBackups = 10
$script:CustomSectionMarker = "# === Custom Host Entries (Preserved by myTech.Today hosts.ps1) ==="

# Suppress progress bars
$script:OriginalProgressPreference = $ProgressPreference
$ProgressPreference = 'SilentlyContinue'

#endregion

#region Load Logging Module

# Load shared logging module from GitHub
$loggingUrl = 'https://raw.githubusercontent.com/mytech-today-now/scripts/refs/heads/main/logging.ps1'
try {
    Write-Host "[INFO] Loading logging module..." -ForegroundColor Cyan
    Invoke-Expression (Invoke-WebRequest -Uri $loggingUrl -UseBasicParsing).Content
    Write-Host "[OK] Logging module loaded successfully" -ForegroundColor Green
}
catch {
    Write-Host "[FAIL] Failed to load logging module: $_" -ForegroundColor Red
    Write-Host "[INFO] Continuing without centralized logging..." -ForegroundColor Yellow
    
    # Fallback logging function
    function Write-Log {
        param([string]$Message, [string]$Level = 'INFO')
        $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
        Write-Host "[$timestamp] [$Level] $Message"
    }
}

# Initialize logging
try {
    Initialize-Log -ScriptName "hosts" -ScriptVersion $script:ScriptVersion
}
catch {
    Write-Host "[WARN] Could not initialize centralized logging: $_" -ForegroundColor Yellow
}

#endregion

#region Helper Functions

function Test-AdministratorPrivilege {
    <#
    .SYNOPSIS
        Checks if the script is running with administrator privileges.
    #>
    [CmdletBinding()]
    param()

    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function New-HostsBackup {
    <#
    .SYNOPSIS
        Creates a timestamped backup of the current hosts file.
    #>
    [CmdletBinding()]
    param()

    try {
        # Create backup directory if it doesn't exist
        if (-not (Test-Path $script:BackupDirectory)) {
            New-Item -Path $script:BackupDirectory -ItemType Directory -Force | Out-Null
            Write-Log "Created backup directory: $script:BackupDirectory" -Level INFO
        }

        # Generate backup filename with timestamp
        $timestamp = Get-Date -Format 'yyyy-MM-dd_HHmmss'
        $backupFileName = "hosts.backup.$timestamp"
        $backupPath = Join-Path $script:BackupDirectory $backupFileName

        # Copy hosts file to backup location
        Copy-Item -Path $script:HostsFilePath -Destination $backupPath -Force

        $fileSize = (Get-Item $backupPath).Length
        Write-Log "Backup created: $backupPath (Size: $fileSize bytes)" -Level INFO
        Write-Host "[OK] Backup created: $backupFileName" -ForegroundColor Green

        # Clean up old backups (keep only last 10)
        Remove-OldBackups

        return $backupPath
    }
    catch {
        Write-Log "Failed to create backup: $_" -Level ERROR
        throw
    }
}

function Remove-OldBackups {
    <#
    .SYNOPSIS
        Removes old backup files, keeping only the most recent ones.
    #>
    [CmdletBinding()]
    param()

    try {
        $backups = Get-ChildItem -Path $script:BackupDirectory -Filter "hosts.backup.*" |
                   Sort-Object LastWriteTime -Descending

        if ($backups.Count -gt $script:MaxBackups) {
            $backupsToRemove = $backups | Select-Object -Skip $script:MaxBackups

            foreach ($backup in $backupsToRemove) {
                Remove-Item -Path $backup.FullName -Force
                Write-Log "Removed old backup: $($backup.Name)" -Level INFO
            }

            Write-Host "[INFO] Cleaned up $($backupsToRemove.Count) old backup(s)" -ForegroundColor Cyan
        }
    }
    catch {
        Write-Log "Failed to remove old backups: $_" -Level WARN
    }
}

function Get-LatestBackup {
    <#
    .SYNOPSIS
        Gets the most recent backup file.
    #>
    [CmdletBinding()]
    param()

    try {
        $latestBackup = Get-ChildItem -Path $script:BackupDirectory -Filter "hosts.backup.*" |
                        Sort-Object LastWriteTime -Descending |
                        Select-Object -First 1

        return $latestBackup
    }
    catch {
        Write-Log "Failed to get latest backup: $_" -Level ERROR
        throw
    }
}

function Get-BlockingRules {
    <#
    .SYNOPSIS
        Downloads blocking rules from someonewhocares.org.
    #>
    [CmdletBinding()]
    param()

    try {
        Write-Host "[INFO] Downloading blocking rules from $script:HostsFileUrl..." -ForegroundColor Cyan
        Write-Log "Downloading blocking rules from: $script:HostsFileUrl" -Level INFO

        $response = Invoke-WebRequest -Uri $script:HostsFileUrl -UseBasicParsing -TimeoutSec 30

        if ($response.StatusCode -eq 200) {
            $content = $response.Content
            $contentSize = $content.Length

            Write-Log "Downloaded blocking rules successfully (Size: $contentSize bytes)" -Level INFO
            Write-Host "[OK] Downloaded blocking rules ($contentSize bytes)" -ForegroundColor Green

            # Validate content (should contain hosts file entries somewhere in the content)
            if ($content -match '\d+\.\d+\.\d+\.\d+\s+\S+') {
                return $content
            }
            else {
                throw "Downloaded content does not appear to be a valid hosts file"
            }
        }
        else {
            throw "HTTP request failed with status code: $($response.StatusCode)"
        }
    }
    catch {
        Write-Log "Failed to download blocking rules: $_" -Level ERROR
        throw
    }
}

function Test-HostsFileUpToDate {
    <#
    .SYNOPSIS
        Checks if the current hosts file already contains the downloaded blocking rules.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$DownloadedContent
    )

    try {
        if (-not (Test-Path $script:HostsFilePath)) {
            Write-Log "Hosts file not found, update needed" -Level INFO
            return $false
        }

        # Read current hosts file
        $currentContent = Get-Content -Path $script:HostsFilePath -Raw

        # Extract signature lines from downloaded content (first 10 non-comment IP entries)
        $downloadedLines = $DownloadedContent -split "`r?`n" | Where-Object {
            $_ -match '^\s*\d+\.\d+\.\d+\.\d+\s+\S+' -and $_ -notmatch '^\s*#'
        } | Select-Object -First 10

        if ($downloadedLines.Count -eq 0) {
            Write-Log "No valid entries found in downloaded content" -Level WARN
            return $false
        }

        # Check if all signature lines exist in current hosts file
        $matchCount = 0
        foreach ($line in $downloadedLines) {
            # Normalize whitespace for comparison
            $normalizedLine = $line -replace '\s+', ' '
            $normalizedCurrent = $currentContent -replace '\s+', ' '

            if ($normalizedCurrent -match [regex]::Escape($normalizedLine)) {
                $matchCount++
            }
        }

        # If at least 80% of signature lines match, consider it up-to-date
        $matchPercentage = ($matchCount / $downloadedLines.Count) * 100

        if ($matchPercentage -ge 80) {
            Write-Log "Hosts file appears up-to-date (Match: $matchPercentage%)" -Level INFO
            Write-Host "[INFO] Hosts file is already up-to-date ($([math]::Round($matchPercentage, 0))% match)" -ForegroundColor Cyan
            return $true
        }
        else {
            Write-Log "Hosts file needs update (Match: $matchPercentage%)" -Level INFO
            return $false
        }
    }
    catch {
        Write-Log "Failed to check if hosts file is up-to-date: $_" -Level WARN
        # On error, assume update is needed to be safe
        return $false
    }
}

function Get-CustomHostEntries {
    <#
    .SYNOPSIS
        Extracts custom host entries from the current hosts file.
    #>
    [CmdletBinding()]
    param()

    try {
        if (-not (Test-Path $script:HostsFilePath)) {
            Write-Log "Hosts file not found: $script:HostsFilePath" -Level WARN
            return @()
        }

        $hostsContent = Get-Content -Path $script:HostsFilePath -Raw
        $customEntries = @()
        $inCustomSection = $false

        # Split content into lines
        $lines = $hostsContent -split "`r?`n"

        foreach ($line in $lines) {
            # Check if we've reached the custom section marker
            if ($line -match 'Custom Host Entries.*myTech\.Today') {
                $inCustomSection = $true
                continue
            }

            # If we're in the custom section, collect entries
            if ($inCustomSection) {
                $customEntries += $line
            }
            # Check if this line is NOT from someonewhocares.org
            elseif ($line -notmatch 'someonewhocares\.org' -and
                    $line -notmatch '^#\s*Last\s+updated:' -and
                    $line -notmatch '^#\s*This\s+file' -and
                    $line.Trim() -ne '' -and
                    $line -match '^\s*\d+\.\d+\.\d+\.\d+\s+' -or
                    ($line.Trim().StartsWith('#') -and $line -notmatch 'someonewhocares')) {
                # This appears to be a custom entry
                $customEntries += $line
            }
        }

        if ($customEntries.Count -gt 0) {
            Write-Log "Found $($customEntries.Count) custom host entries" -Level INFO
            Write-Host "[INFO] Found $($customEntries.Count) custom host entries" -ForegroundColor Cyan
        }

        return $customEntries
    }
    catch {
        Write-Log "Failed to extract custom entries: $_" -Level ERROR
        throw
    }
}

function Merge-HostsContent {
    <#
    .SYNOPSIS
        Merges downloaded blocking rules with custom entries.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BlockingRules,

        [Parameter(Mandatory = $true)]
        [array]$CustomEntries
    )

    try {
        Write-Host "[INFO] Merging blocking rules with custom entries..." -ForegroundColor Cyan

        # Start with blocking rules
        $mergedContent = $BlockingRules

        # Add custom section if there are custom entries
        if ($CustomEntries.Count -gt 0) {
            # Ensure blocking rules end with newline
            if (-not $mergedContent.EndsWith("`n")) {
                $mergedContent += "`r`n"
            }

            # Add section marker
            $mergedContent += "`r`n$script:CustomSectionMarker`r`n"

            # Add custom entries
            foreach ($entry in $CustomEntries) {
                if (-not [string]::IsNullOrWhiteSpace($entry)) {
                    $mergedContent += "$entry`r`n"
                }
            }
        }

        Write-Log "Merged content created successfully" -Level INFO
        Write-Host "[OK] Content merged successfully" -ForegroundColor Green

        return $mergedContent
    }
    catch {
        Write-Log "Failed to merge content: $_" -Level ERROR
        throw
    }
}

function Update-HostsFile {
    <#
    .SYNOPSIS
        Updates the Windows hosts file with merged content.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Content
    )

    try {
        Write-Host "[INFO] Updating hosts file..." -ForegroundColor Cyan

        # Write content to hosts file
        Set-Content -Path $script:HostsFilePath -Value $Content -Force -Encoding ASCII

        # Verify write operation
        if (Test-Path $script:HostsFilePath) {
            $fileSize = (Get-Item $script:HostsFilePath).Length
            Write-Log "Hosts file updated successfully (Size: $fileSize bytes)" -Level INFO
            Write-Host "[OK] Hosts file updated successfully" -ForegroundColor Green
            return $true
        }
        else {
            throw "Hosts file not found after write operation"
        }
    }
    catch {
        Write-Log "Failed to update hosts file: $_" -Level ERROR
        throw
    }
}

function Invoke-DNSFlush {
    <#
    .SYNOPSIS
        Flushes the DNS cache to apply changes immediately.
    #>
    [CmdletBinding()]
    param()

    try {
        Write-Host "[INFO] Flushing DNS cache..." -ForegroundColor Cyan
        Write-Log "Executing: ipconfig /flushdns" -Level INFO

        & ipconfig /flushdns 2>&1 | Out-Null

        if ($LASTEXITCODE -eq 0) {
            Write-Log "DNS cache flushed successfully" -Level INFO
            Write-Host "[OK] DNS cache flushed successfully" -ForegroundColor Green
            return $true
        }
        else {
            Write-Log "DNS flush command returned exit code: $LASTEXITCODE" -Level WARN
            Write-Host "[WARN] DNS flush may have failed (exit code: $LASTEXITCODE)" -ForegroundColor Yellow
            return $false
        }
    }
    catch {
        Write-Log "Failed to flush DNS cache: $_" -Level ERROR
        Write-Host "[FAIL] Failed to flush DNS cache: $_" -ForegroundColor Red
        return $false
    }
}

function Restore-HostsFile {
    <#
    .SYNOPSIS
        Restores hosts file from a backup.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$BackupFilePath
    )

    try {
        # If no backup path specified, use the latest backup
        if ([string]::IsNullOrWhiteSpace($BackupFilePath)) {
            $latestBackup = Get-LatestBackup

            if ($null -eq $latestBackup) {
                throw "No backup files found in $script:BackupDirectory"
            }

            $BackupFilePath = $latestBackup.FullName
            Write-Host "[INFO] Using latest backup: $($latestBackup.Name)" -ForegroundColor Cyan
        }

        # Verify backup file exists
        if (-not (Test-Path $BackupFilePath)) {
            throw "Backup file not found: $BackupFilePath"
        }

        Write-Host "[INFO] Restoring hosts file from backup..." -ForegroundColor Cyan
        Write-Log "Restoring from backup: $BackupFilePath" -Level INFO

        # Create a backup of current hosts file before restoring
        Write-Host "[INFO] Creating safety backup of current hosts file..." -ForegroundColor Cyan
        New-HostsBackup | Out-Null

        # Restore from backup
        Copy-Item -Path $BackupFilePath -Destination $script:HostsFilePath -Force

        Write-Log "Hosts file restored successfully from: $BackupFilePath" -Level INFO
        Write-Host "[OK] Hosts file restored successfully" -ForegroundColor Green

        return $true
    }
    catch {
        Write-Log "Failed to restore hosts file: $_" -Level ERROR
        throw
    }
}

#endregion

#region Main Script Execution

try {
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "  Windows Hosts File Manager v$script:ScriptVersion" -ForegroundColor Cyan
    Write-Host "  myTech.Today" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""

    Write-Log "Script started - Version: $script:ScriptVersion" -Level INFO

    # Check administrator privileges
    if (-not (Test-AdministratorPrivilege)) {
        Write-Host "[FAIL] This script requires administrator privileges" -ForegroundColor Red
        Write-Host "[INFO] Please run PowerShell as Administrator and try again" -ForegroundColor Yellow
        Write-Log "Script terminated - Administrator privileges required" -Level ERROR
        exit 1
    }

    Write-Host "[OK] Running with administrator privileges" -ForegroundColor Green
    Write-Log "Administrator privileges verified" -Level INFO

    # Handle BackupOnly parameter
    if ($BackupOnly) {
        Write-Host ""
        Write-Host "[INFO] Backup-only mode" -ForegroundColor Cyan
        Write-Log "Backup-only mode requested" -Level INFO

        if ($PSCmdlet.ShouldProcess($script:HostsFilePath, "Create backup")) {
            $backupPath = New-HostsBackup
            Write-Host ""
            Write-Host "[OK] Backup completed: $backupPath" -ForegroundColor Green
            Write-Log "Backup-only operation completed successfully" -Level INFO
        }

        exit 0
    }

    # Handle RestoreBackup parameter
    if ($RestoreBackup) {
        Write-Host ""
        Write-Host "[INFO] Restore mode" -ForegroundColor Cyan
        Write-Log "Restore mode requested" -Level INFO

        if ($PSCmdlet.ShouldProcess($script:HostsFilePath, "Restore from backup")) {
            Restore-HostsFile -BackupFilePath $BackupPath

            # Flush DNS cache unless skipped
            if (-not $SkipDNSFlush) {
                Write-Host ""
                Invoke-DNSFlush | Out-Null
            }

            Write-Host ""
            Write-Host "[OK] Restore completed successfully" -ForegroundColor Green
            Write-Log "Restore operation completed successfully" -Level INFO
        }

        exit 0
    }

    # Normal update mode
    Write-Host ""
    Write-Host "[INFO] Update mode - Downloading and merging blocking rules" -ForegroundColor Cyan
    Write-Log "Update mode - Starting hosts file update process" -Level INFO

    # Step 1: Create backup
    Write-Host ""
    Write-Host "[STEP 1/5] Creating backup..." -ForegroundColor Cyan

    if ($PSCmdlet.ShouldProcess($script:HostsFilePath, "Create backup")) {
        $backupPath = New-HostsBackup
    }

    # Step 2: Download blocking rules
    Write-Host ""
    Write-Host "[STEP 2/5] Downloading blocking rules..." -ForegroundColor Cyan

    $blockingRules = $null
    if ($PSCmdlet.ShouldProcess($script:HostsFileUrl, "Download blocking rules")) {
        $blockingRules = Get-BlockingRules
    }

    # Step 2.5: Sanity check - Is hosts file already up-to-date?
    Write-Host ""
    Write-Host "[STEP 2.5/5] Checking if update is needed..." -ForegroundColor Cyan

    if (-not $Force -and (Test-HostsFileUpToDate -DownloadedContent $blockingRules)) {
        Write-Host ""
        Write-Host "========================================" -ForegroundColor Green
        Write-Host "  No Update Needed" -ForegroundColor Green
        Write-Host "========================================" -ForegroundColor Green
        Write-Host ""
        Write-Host "[OK] Hosts file is already up-to-date with latest blocking rules" -ForegroundColor Green
        Write-Host "[INFO] Backup created: $backupPath" -ForegroundColor Cyan
        Write-Host "[INFO] Use -Force to update anyway" -ForegroundColor Cyan
        Write-Host ""

        Write-Log "Hosts file already up-to-date, no changes needed" -Level INFO
        exit 0
    }

    if ($Force) {
        Write-Host "[INFO] Force mode - Updating even if already up-to-date" -ForegroundColor Yellow
        Write-Log "Force mode enabled - bypassing up-to-date check" -Level INFO
    }
    else {
        Write-Host "[INFO] Update needed - Hosts file will be updated" -ForegroundColor Cyan
    }

    # Step 3: Extract custom entries
    Write-Host ""
    Write-Host "[STEP 3/5] Extracting custom entries..." -ForegroundColor Cyan

    $customEntries = Get-CustomHostEntries

    # Step 4: Merge content
    Write-Host ""
    Write-Host "[STEP 4/5] Merging content..." -ForegroundColor Cyan

    $mergedContent = $null
    if ($PSCmdlet.ShouldProcess("Blocking rules and custom entries", "Merge")) {
        $mergedContent = Merge-HostsContent -BlockingRules $blockingRules -CustomEntries $customEntries
    }

    # Step 5: Update hosts file
    Write-Host ""
    Write-Host "[STEP 5/5] Updating hosts file..." -ForegroundColor Cyan

    if ($PSCmdlet.ShouldProcess($script:HostsFilePath, "Update hosts file")) {
        Update-HostsFile -Content $mergedContent
    }

    # Flush DNS cache unless skipped
    if (-not $SkipDNSFlush) {
        Write-Host ""
        if ($PSCmdlet.ShouldProcess("DNS cache", "Flush")) {
            Invoke-DNSFlush | Out-Null
        }
    }
    else {
        Write-Host ""
        Write-Host "[INFO] DNS cache flush skipped (use -SkipDNSFlush parameter)" -ForegroundColor Yellow
        Write-Log "DNS cache flush skipped by user request" -Level INFO
    }

    # Summary
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Green
    Write-Host "  Update Completed Successfully!" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "[INFO] Hosts file location: $script:HostsFilePath" -ForegroundColor Cyan
    Write-Host "[INFO] Backup location: $backupPath" -ForegroundColor Cyan
    Write-Host "[INFO] Custom entries preserved: $($customEntries.Count)" -ForegroundColor Cyan
    Write-Host ""

    Write-Log "Hosts file update completed successfully" -Level INFO

    exit 0
}
catch {
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Red
    Write-Host "  ERROR: Operation Failed" -ForegroundColor Red
    Write-Host "========================================" -ForegroundColor Red
    Write-Host ""
    Write-Host "[FAIL] $($_.Exception.Message)" -ForegroundColor Red
    Write-Host ""

    Write-Log "Script failed with error: $($_.Exception.Message)" -Level ERROR
    Write-Log "Stack trace: $($_.ScriptStackTrace)" -Level ERROR

    # Restore progress preference
    $ProgressPreference = $script:OriginalProgressPreference

    exit 1
}
finally {
    # Restore progress preference
    $ProgressPreference = $script:OriginalProgressPreference
}

#endregion

