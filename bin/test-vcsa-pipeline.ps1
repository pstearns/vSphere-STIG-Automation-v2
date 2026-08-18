# =========================================================================
# SCRIPT: test-vcsa-pipeline.ps1
# DESCRIPTION: Force-reloads modules and runs targeted VCSA tests.
# =========================================================================

$OverlayRoot = "/usr/share/stigs/orchestration_overlay"
$OrchestrationModule = Join-Path $OverlayRoot "modules/RemediationOrchestration.psm1"

# Force-Unload any cached VCSA or core modules in the session
Get-Module | Where-Object { $_.Name -match "Orchestration" -or $_.Name -match "Provider" -or $_.Name -match "Functions" -or $_.Name -match "Helpers" } | ForEach-Object {
    Write-Host "Unloading stale module: $($_.Name)" -ForegroundColor DarkGray
    Remove-Module $_.Name -ErrorAction SilentlyContinue
}

Write-Host "Importing Orchestration Engine..." -ForegroundColor Cyan
Import-Module $OrchestrationModule -Force

# Define your target VCSA FQDN (must match active targets in global_config.yml)
# Replace with the exact FQDN of the VCSA you want to run the hardening playbook against
$TestVCSAName = "huarinfvc" 

Write-Host "Starting targeted VCSA STIG execution for: $TestVCSAName" -ForegroundColor Yellow
Write-Host "------------------------------------------------------------"

# Invoke the unified engine with 'VCSA' AssetType
Invoke-StigRemediation -AssetType VCSA -TargetName $TestVCSAName -OverlayRoot $OverlayRoot

Write-Host "------------------------------------------------------------"
Write-Host "Execution finished." -ForegroundColor Green