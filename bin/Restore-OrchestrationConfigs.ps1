<#
.SYNOPSIS
    Interactively restores configuration files from a backup tar.gz.
    Prompts the user for confirmation on each individual file before writing.
#>
[CmdletBinding()]
param (
    [Parameter(Mandatory=$false)]
    [string]$BackupArchivePath,
    [string]$TargetRoot = "/usr/share/stigs/orchestration_overlay"
)

$ErrorActionPreference = "Continue"

# 1. If no archive path is passed, automatically suggest the newest backup
if (-not $BackupArchivePath) {
    $BackupsDir = Join-Path $TargetRoot "backups"
    $LatestBackup = Get-ChildItem -Path "$BackupsDir/*.tar.gz" -ErrorAction SilentlyContinue | 
                    Sort-Object LastWriteTime -Descending | 
                    Select-Object -First 1

    if ($LatestBackup) {
        $BackupArchivePath = $LatestBackup.FullName
        Write-Host "[*] No archive specified. Auto-detected latest backup:" -ForegroundColor Cyan
        Write-Host "    $BackupArchivePath" -ForegroundColor Gray
    } else {
        Write-Error "No backup archives found in $BackupsDir. Please supply -BackupArchivePath."
        return
    }
}

if (-not (Test-Path $BackupArchivePath)) {
    Write-Error "Specified backup archive does not exist: $BackupArchivePath"
    return
}

# 2. Stage extraction in a safe temporary directory
$SystemTemp = [System.IO.Path]::GetTempPath()
$TempExtractDir = Join-Path $SystemTemp "config_restore_interactive_$(Get-Random)"
New-Item -ItemType Directory -Path $TempExtractDir -Force | Out-Null

try {
    Write-Host "[*] Inspecting archive contents..." -ForegroundColor Cyan
    $tarOutput = bash -c "tar -xzf '$BackupArchivePath' -C '$TempExtractDir'" 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Failed to unpack archive for inspection: $tarOutput"
        return
    }

    # Find all extracted files
    $ExtractedFiles = Get-ChildItem -Path $TempExtractDir -Recurse -File
    if ($ExtractedFiles.Count -eq 0) {
        Write-Warning "Archive is empty or contains no files."
        return
    }

    Write-Host "[+] Found $($ExtractedFiles.Count) files in archive." -ForegroundColor Green
    Write-Host "------------------------------------------------------------------" -ForegroundColor Gray
    Write-Host "Controls: [Y] Restore this file  |  [N] Skip  |  [A] Restore all remaining  |  [Q] Abort" -ForegroundColor Yellow
    Write-Host "------------------------------------------------------------------" -ForegroundColor Gray

    $RestoreAll = $false
    $RestoredCount = 0
    $SkippedCount = 0

    foreach ($File in $ExtractedFiles) {
        $RelativePath    = [System.IO.Path]::GetRelativePath($TempExtractDir, $File.FullName)
        $DestinationPath = Join-Path $TargetRoot $RelativePath
        $DestinationDir  = Split-Path -Parent $DestinationPath

        $FileExists = Test-Path $DestinationPath
        $StatusLabel = if ($FileExists) { "[OVERWRITE EXISTING]" } else { "[CREATE NEW FILE]" }
        $StatusColor = if ($FileExists) { "Yellow" } else { "Green" }

        Write-Host "`nTarget: " -NoNewline
        Write-Host $RelativePath -ForegroundColor White -NoNewline
        Write-Host " $StatusLabel" -ForegroundColor $StatusColor

        # Prompt user unless 'All' was chosen
        if (-not $RestoreAll) {
            $Prompt = Read-Host "Restore this file? [Y/n/a/q]"
            $Action = if ([string]::IsNullOrWhiteSpace($Prompt)) { "y" } else { $Prompt.Trim().ToLower() }

            switch ($Action) {
                "y" { 
                    # Proceed with copy
                }
                "n" { 
                    Write-Host "  [-] Skipped." -ForegroundColor DarkGray
                    $SkippedCount++
                    continue 
                }
                "a" { 
                    $RestoreAll = $true
                    Write-Host "  [+] Restoring all remaining files without prompting..." -ForegroundColor Cyan
                }
                "q" { 
                    Write-Warning "`n[!] Restore operation aborted by user. Cleaned up staging directory."
                    return 
                }
                default { 
                    Write-Host "  [-] Invalid input. Defaulting to skip." -ForegroundColor DarkGray
                    $SkippedCount++
                    continue 
                }
            }
        }

        # Perform copy
        if (-not (Test-Path $DestinationDir)) {
            New-Item -ItemType Directory -Path $DestinationDir -Force | Out-Null
        }

        Copy-Item -Path $File.FullName -Destination $DestinationPath -Force
        Write-Host "  [✓] Restored successfully." -ForegroundColor Green
        $RestoredCount++
    }

    Write-Host "`n------------------------------------------------------------------" -ForegroundColor Gray
    Write-Host "[SUCCESS] Interactive restore session finished." -ForegroundColor Green
    Write-Host "  Files Restored : $RestoredCount" -ForegroundColor Green
    Write-Host "  Files Skipped  : $SkippedCount" -ForegroundColor Yellow
    Write-Host "------------------------------------------------------------------" -ForegroundColor Gray
}
finally {
    # Ensure temporary files are always cleaned up
    if (Test-Path $TempExtractDir) {
        Remove-Item -Path $TempExtractDir -Recurse -Force -ErrorAction SilentlyContinue | Out-Null
    }
}