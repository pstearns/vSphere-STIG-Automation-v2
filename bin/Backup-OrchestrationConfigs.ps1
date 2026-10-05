<#
.SYNOPSIS
    Scans, catalogs, and backs up all modular configuration files into a single tar.gz archive.
    Explicitly ignores binaries, examples, and non-config extension patterns.
#>
[CmdletBinding()]
param (
    [string]$SourceRoot = "/usr/share/stigs/orchestration_overlay",
    [string]$BackupDestinationDir = "/usr/share/stigs/orchestration_overlay/backups"
)

$ErrorActionPreference = "Continue"

if (-not (Test-Path $BackupDestinationDir)) {
    New-Item -ItemType Directory -Path $BackupDestinationDir -Force | Out-Null
}

$DateStr     = (Get-Date).ToString("yyyyMMdd_HHmmss")
$ArchiveFile = Join-Path $BackupDestinationDir "orchestration_configs_backup_$DateStr.tar.gz"
$SystemTemp  = [System.IO.Path]::GetTempPath()
$StagingDir  = Join-Path $SystemTemp "config_backup_staging_$DateStr"

# Explicit configuration file extensions and allowed extensionless files
$AllowedExtensions = @(".json", ".xml", ".yml", ".yaml", ".env")
$AllowedNoExtension = @("email_address")

Write-Host "[*] Starting Configuration Scan..." -ForegroundColor Cyan

# 1. Locate and filter valid configuration files
$ConfigFiles = Get-ChildItem -Path $SourceRoot -Recurse -File | Where-Object {
    $InConfDir = $_.DirectoryName -match "([/\\]conf([/\\]|$))" -or $_.DirectoryName -match "([/\\]stigman-watcher([/\\]|$))"
    $IsExample = $_.FullName -match "([/\\]_examples([/\\]|$))"
    
    # Verify extension type or matching extensionless config list
    $Extension = [System.IO.Path]::GetExtension($_.Name).ToLower()
    $IsValidType = ($AllowedExtensions -contains $Extension) -or ($AllowedNoExtension -contains $_.Name)

    # File must be in a config directory, NOT be an example, and be a valid configuration file type
    $InConfDir -and -not $IsExample -and $IsValidType
}

if ($ConfigFiles.Count -eq 0) {
    Write-Warning "[-] No valid configuration files found matching criteria."
    return
}

Write-Host "[+] Found $($ConfigFiles.Count) configuration files to back up:" -ForegroundColor Green
Write-Host "--------------------------------------------------" -ForegroundColor Gray

# 2. Stage files preserving relative directory structure
foreach ($File in $ConfigFiles) {
    $RelativePath = [System.IO.Path]::GetRelativePath($SourceRoot, $File.FullName)
    Write-Host "  -> $RelativePath" -ForegroundColor Gray

    $TargetStagePath = Join-Path $StagingDir $RelativePath
    $TargetStageDir  = Split-Path -Parent $TargetStagePath

    if (-not (Test-Path $TargetStageDir)) {
        New-Item -ItemType Directory -Path $TargetStageDir -Force | Out-Null
    }

    Copy-Item -Path $File.FullName -Destination $TargetStagePath -Force
}
Write-Host "--------------------------------------------------" -ForegroundColor Gray

# 3. Compress using Linux-native tar + gzip
if (Test-Path $StagingDir) {
    Write-Host "[*] Compressing configuration files with tar + gzip..." -ForegroundColor Cyan
    
    $tarOutput = bash -c "tar -czf '$ArchiveFile' -C '$StagingDir' ." 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Error "tar compression failed: $tarOutput"
        return
    }
} else {
    Write-Error "Staging directory was not created."
    return
}

# 4. Cleanup staging directory
if (Test-Path $StagingDir) {
    Remove-Item -Path $StagingDir -Recurse -Force | Out-Null
}

Write-Host "[SUCCESS] Backup complete! Archive saved to: $ArchiveFile" -ForegroundColor Green