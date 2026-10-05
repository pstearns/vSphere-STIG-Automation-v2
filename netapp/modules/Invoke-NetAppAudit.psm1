# =========================================================================
# MODULE: Invoke-NetAppAudit.psm1
# DESCRIPTION: Main orchestrator for the NetApp STIG workflow
# =========================================================================

$ThisModuleFolder = $PSScriptRoot                           # /.../netapp/modules
$ProjectRoot      = Split-Path -Parent $ThisModuleFolder    # /.../netapp

Write-Verbose "ThisModuleFolder : $ThisModuleFolder"
Write-Verbose "ProjectRoot       : $ProjectRoot"


# === Import modules ===
try {
    $ParentModulesPath = Join-Path (Split-Path -Parent $ProjectRoot) "modules"

    if (Test-Path (Join-Path $ParentModulesPath "globalFunctions.psm1")) {
        Import-Module (Join-Path $ParentModulesPath "globalFunctions.psm1")      -Global -Force -ErrorAction Stop
        Import-Module (Join-Path $ParentModulesPath "CredentialManagement.psm1") -Global -Force -ErrorAction Stop
    } else {
        throw "Could not find globalFunctions.psm1 in $ParentModulesPath"
    }

    Import-Module (Join-Path $ThisModuleFolder "NetAppStigHelper.psm1") -Global -Force -ErrorAction Stop
}
catch {
    Write-Error "Failed to import required modules: $($_.Exception.Message)"
    return
}

function Invoke-NetAppAudit {
    [CmdletBinding()]
    param (
        [string]$ProjectRoot = $Global:ProjectRoot
    )

    if (-not $ProjectRoot) {
        $ProjectRoot = Split-Path -Parent $PSScriptRoot
    }

    $OverlayRoot = Split-Path -Parent $ProjectRoot
    $StartTime   = Get-Date
    $DateStr     = $StartTime.ToString("yyyyMMdd")

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

    $CredentialFile = Join-Path $ProjectRoot "../conf/.creds.json.encrypted"
    if (-not (Test-Path $CredentialFile)) {
        Write-StigLog "FATAL: Credential file not found at $CredentialFile" -Severity ERROR -Source "NetAppOrchestrator"
        return $null
    }

    $CompletedWorkflows = @()
    $ClusterSummaries   = @()
    $totalCat1 = 0; $totalCat2 = 0; $totalCat3 = 0; $totalTargets = 0

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

        $clusterCat1 = 0; $clusterCat2 = 0; $clusterCat3 = 0; $targetCount = 0
        $clusterStatus = "SUCCESS"

        if ($result) {
            Write-StigLog "Successfully generated checklist for $fqdn" -Severity SUCCESS -Source "NetAppOrchestrator"
            $CompletedWorkflows += $result
            $targetCount = 1

            # FIXED: Changed $result.CklPath to $result.CklFile to match helper output
            if ($result.CklFile -and (Test-Path $result.CklFile)) {
                try {
                    [xml]$cklXml = Get-Content -Path $result.CklFile -Raw
                    
                    $openVulns = @($cklXml.CHECKLIST.STIGS.iSTIG.VULN) | Where-Object { $_.STATUS -eq "Open" }

                    foreach ($v in $openVulns) {
                        $sevNode = @($v.STIG_DATA) | Where-Object { $_.VULN_ATTRIBUTE -eq "Severity" }
                        $sev     = if ($sevNode) { $sevNode.ATTRIBUTE_DATA.Trim() } else { "medium" }

                        switch ($sev.ToLower()) {
                            "high"   { $clusterCat1++ }
                            "medium" { $clusterCat2++ }
                            "low"    { $clusterCat3++ }
                        }
                    }
                } catch {
                    Write-StigLog "Failed to parse checklist findings for $fqdn : $($_.Exception.Message)" -Severity WARN -Source "NetAppOrchestrator"
                }
            }
        } else {
            Write-StigLog "Workflow failed for $fqdn." -Severity ERROR -Source "NetAppOrchestrator"
            $clusterStatus = "FAILED"
        }

        $clusterTotalOpen = $clusterCat1 + $clusterCat2 + $clusterCat3
        $totalCat1 += $clusterCat1
        $totalCat2 += $clusterCat2
        $totalCat3 += $clusterCat3
        $totalTargets += $targetCount

        $ClusterSummaries += [PSCustomObject]@{
            Name           = $clusterName
            Scope          = "ONTAP ($fqdn)"
            Status         = $clusterStatus
            TargetsScanned = $targetCount
            Cat1Open       = $clusterCat1
            Cat2Open       = $clusterCat2
            Cat3Open       = $clusterCat3
            TotalOpen      = $clusterTotalOpen
        }
    }

    Write-StigLog "NetApp STIG Audit completed." -Severity SUCCESS -Source "NetAppOrchestrator"

    # --- Compile Summary JSON & Dispatch HTML Report ---
    $summaryObj = [PSCustomObject]@{
        JobName             = "NETAPP_STIG_Audit"
        DateStr             = $DateStr
        TotalTargetsScanned = $totalTargets
        Cat1Open            = $totalCat1
        Cat2Open            = $totalCat2
        Cat3Open            = $totalCat3
        vCenters            = $ClusterSummaries
    }

    $SummaryJsonDir = Join-Path $ProjectRoot "reports/$DateStr"
    if (-not (Test-Path $SummaryJsonDir)) { New-Item -ItemType Directory -Path $SummaryJsonDir -Force | Out-Null }
    $SummaryJsonPath = Join-Path $SummaryJsonDir "stig_run_summary_NETAPP_STIG_Audit.json"
    $summaryObj | ConvertTo-Json -Depth 5 | Set-Content -Path $SummaryJsonPath -Force

    $MailScriptPath = Join-Path $OverlayRoot "bin/send_alert.ps1"
    $LogPath        = Join-Path $OverlayRoot "logs/netapp_execution_trace.log"

    if (Test-Path $MailScriptPath) {
        & $MailScriptPath -JobName "NETAPP_STIG_Audit" -LogPath $LogPath -ExitCode 0 -Status "SUCCESS" -SummaryJsonPath $SummaryJsonPath
    }

    return $CompletedWorkflows
}

Export-ModuleMember -Function Invoke-NetAppAudit