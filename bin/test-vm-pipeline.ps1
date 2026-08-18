# =========================================================================
# SCRIPT: test-vm-pipeline.ps1
# DESCRIPTION: Targeted execution to verify VM Provider binding & pipeline
# =========================================================================

$OverlayRoot = "/usr/share/stigs/orchestration_overlay"
$OrchestrationModule = Join-Path $OverlayRoot "modules/RemediationOrchestration.psm1"

# 1. Clean old imported module sessions
if (Get-Module RemediationOrchestration) {
    Remove-Module RemediationOrchestration
}

Write-Host "Importing Orchestration Engine..." -ForegroundColor Cyan
Import-Module $OrchestrationModule -Force

# 2. Define your test parameters
# Replace 'TEST-VM-01' with the exact name of a VM in your staging checklist directory
$TestVMName = "NIPRTF-0474" 

Write-Host "Starting targeted VM STIG execution for: $TestVMName" -ForegroundColor Yellow
Write-Host "------------------------------------------------------------"

# 3. Invoke the unified engine with 'VM' AssetType
Invoke-StigRemediation -AssetType vm -TargetName $TestVMName -OverlayRoot $OverlayRoot

Write-Host "------------------------------------------------------------"
Write-Host "Execution finished. Inspecting log files..." -ForegroundColor Green