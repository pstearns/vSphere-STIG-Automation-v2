# =========================================================================
# SCRIPT: test-esxi-pipeline.ps1
# DESCRIPTION: Force-reloads modules and runs targeted ESXi tests
# =========================================================================

$OverlayRoot = "/usr/share/stigs/orchestration_overlay"
$OrchestrationModule = Join-Path $OverlayRoot "modules/RemediationOrchestration.psm1"

# Force-Unload any cached modules in the session
Get-Module | Where-Object { $_.Name -match "Orchestration" -or $_.Name -match "Provider" -or $_.Name -match "Functions" -or $_.Name -match "Helpers" } | ForEach-Object {
    Write-Host "Unloading stale module: $($_.Name)" -ForegroundColor DarkGray
    Remove-Module $_.Name -ErrorAction SilentlyContinue
}

Write-Host "Importing Orchestration Engine..." -ForegroundColor Cyan
Import-Module $OrchestrationModule -Force

# Define your target ESXi host
$TestESXiName = "huagvdiesx01" 

Write-Host "Starting targeted ESXi STIG execution for: $TestESXiName" -ForegroundColor Yellow
Write-Host "------------------------------------------------------------"

Invoke-StigRemediation -AssetType ESXi -TargetName $TestESXiName -OverlayRoot $OverlayRoot

Write-Host "------------------------------------------------------------"
Write-Host "Execution finished." -ForegroundColor Green