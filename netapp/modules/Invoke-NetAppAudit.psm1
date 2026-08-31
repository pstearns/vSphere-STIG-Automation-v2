# =========================================================================
# MODULE: Invoke-NetAppAudit.psm1
# DESCRIPTION: Main orchestrator for the NetApp STIG workflow
# =========================================================================

$ThisModuleFolder = $PSScriptRoot                           # /.../netapp/modules
$ProjectRoot      = Split-Path -Parent $ThisModuleFolder    # /.../netapp

Write-Verbose "ThisModuleFolder : $ThisModuleFolder"
Write-Verbose "ProjectRoot       : $ProjectRoot"

# === Import modules from TWO locations ===
try {
    # 1. Shared modules from the parent orchestration_overlay/modules folder
    $ParentModulesPath = Join-Path (Split-Path -Parent $ProjectRoot) "modules"

    if (Test-Path (Join-Path $ParentModulesPath "globalFunctions.psm1")) {
        Import-Module (Join-Path $ParentModulesPath "globalFunctions.psm1")      -Global -Force -ErrorAction Stop
        Import-Module (Join-Path $ParentModulesPath "CredentialManagement.psm1") -Global -Force -ErrorAction Stop
    } else {
        throw "Could not find globalFunctions.psm1 in $ParentModulesPath"
    }

    # 2. NetApp helper from the same folder as this module
    Import-Module (Join-Path $ThisModuleFolder "NetAppStigHelper.psm1") -Global -Force -ErrorAction Stop

}
catch {
    Write-Error "Failed to import required modules."
    Write-Error $_.Exception.Message
    return
}

# =========================================================================
# MAIN FUNCTION
# =========================================================================

function Invoke-NetAppAudit {
    [CmdletBinding()]
    param (
        [string]$ProjectRoot = $Global:ProjectRoot
    )

    if (-not $ProjectRoot) {
        $ProjectRoot = Split-Path -Parent $PSScriptRoot
    }

    Write-StigLog "Starting NetApp STIG Audit Workflow..." -Severity INFO -Source "NetAppOrchestrator"

    $InputsPath = Join-Path $ProjectRoot "conf/inputs.yml"
    if (-not (Test-Path $InputsPath)) {
        Write-StigLog "inputs.yml not found at $InputsPath" -Severity ERROR -Source "NetAppOrchestrator"
        return $null
    }

    $Inputs = Get-Content $InputsPath -Raw | ConvertFrom-Yaml
    $EnabledTargets = @($Inputs.netapp_targets | Where-Object { 
        $_.enabled -eq $true -or "$($_.enabled)".ToLower() -eq "true" 
    })

    if ($EnabledTargets.Count -eq 0) {
        Write-StigLog "No enabled NetApp targets found in inputs.yml." -Severity WARN -Source "NetAppOrchestrator"
        return $null
    }

    $CredentialFile = Join-Path $ProjectRoot "..\conf\.creds.json.encrypted"
    if (-not (Test-Path $CredentialFile)) {
        Write-StigLog "FATAL: Credential file not found at $CredentialFile" -Severity ERROR -Source "NetAppOrchestrator"
        return $null
    }

    $DateStr = Get-Date -Format "yyyyMMdd"
    $CompletedWorkflows = @()

    foreach ($target in $EnabledTargets) {
        $fqdn        = $target.fqdn
        $clusterName = $target.cluster_name
        if (-not $fqdn -or -not $clusterName) { continue }

        Write-StigLog "--- Processing Target: $fqdn (Cluster: $clusterName) ---" -Severity INFO -Source "NetAppOrchestrator"

        $creds = Get-NetAppTargetCredential -FQDN $fqdn -CredentialFile $CredentialFile
        if (-not $creds) {
            Write-StigLog "Skipping $fqdn - no credentials found." -Severity WARN -Source "NetAppOrchestrator"
            continue
        }

        $result = Start-NetAppChecklistGeneration -TargetFQDN $fqdn `
                                                  -ClusterName   $clusterName `
                                                  -Credentials   $creds `
                                                  -DateString    $DateStr `
                                                  -ProjectRoot   $ProjectRoot

        if ($result) {
            Write-StigLog "Successfully generated checklist for $fqdn" -Severity SUCCESS -Source "NetAppOrchestrator"
            $CompletedWorkflows += $result
        } else {
            Write-StigLog "Workflow failed for $fqdn." -Severity ERROR -Source "NetAppOrchestrator"
        }
    }

    Write-StigLog "NetApp STIG Audit completed." -Severity SUCCESS -Source "NetAppOrchestrator"
    return $CompletedWorkflows
}

Export-ModuleMember -Function Invoke-NetAppAudit