# =========================================================================
# SCRIPT: Invoke-TargetedStigTest.ps1
# DESCRIPTION: Unified Targeted Test Runner for STIG Audit and Remediation.
#              Allows testing against a small, specific subset of assets
#              (1 VCSA + 1 ESXi + 1 VM) without scanning the entire environment.
# =========================================================================

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [ValidateSet("Audit", "Remediation")]
    [string]$Mode,

    # --- Audit Mode Parameters ---
    [string]$vCenter,
    [string]$EsxiHostName,
    [string]$VmName,

    # --- Remediation Mode Parameters ---
    [ValidateSet("VCSA", "ESXi", "VM")]
    [string]$AssetType,

    [string]$TargetName,

    [string]$OverlayRoot = "/usr/share/stigs/orchestration_overlay"
)

$ErrorActionPreference = 'Stop'

#region Module Reload
Write-Host "[*] Force-reloading STIG modules..." -ForegroundColor DarkGray

Get-Module | Where-Object { 
    $_.Name -match "Orchestration|Provider|Functions|Helpers" 
} | ForEach-Object {
    Remove-Module $_.Name -ErrorAction SilentlyContinue -Force
}

# Import core modules
Import-Module (Join-Path $OverlayRoot "modules/globalFunctions.psm1") -Force
Import-Module (Join-Path $OverlayRoot "modules/CredentialManagement.psm1") -Force
Import-Module (Join-Path $OverlayRoot "modules/StigOrchestration.psm1") -Force
Import-Module (Join-Path $OverlayRoot "modules/RemediationOrchestration.psm1") -Force

Write-Host "[+] Modules reloaded successfully.`n" -ForegroundColor Green
#endregion

#region Logging Initialization
$LogDir = Join-Path $OverlayRoot "logs"
Initialize-StigLogging -LogDirectory $LogDir -Silent:$false
#endregion

Write-Host "========================================================" -ForegroundColor Cyan
Write-Host "          UNIFIED TARGETED STIG TEST RUNNER" -ForegroundColor Cyan
Write-Host "========================================================" -ForegroundColor Cyan
Write-Host "Mode          : $Mode"
Write-Host "Overlay Root  : $OverlayRoot`n"

try {

    # =================================================================
    #                          AUDIT MODE
    # =================================================================
    if ($Mode -eq "Audit") {

        if (-not $vCenter -or -not $EsxiHostName -or -not $VmName) {
            throw "When using -Mode Audit, you must provide -vCenter, -EsxiHostName, and -VmName."
        }

        Write-Host "[MODE] Running AUDIT pipeline on small target set..." -ForegroundColor Yellow

        # Get credentials
        $CredentialFile = Join-Path $OverlayRoot "conf/.creds.json.encrypted"
        $Creds = Get-vCenterCredential -FQDN $vCenter -FilePath $CredentialFile

        if (-not $Creds) {
            throw "Failed to retrieve credentials for vCenter: $vCenter"
        }

        $AdminUser    = $Creds.AdminCred.UserName
        $AdminPass    = $Creds.AdminCred.GetNetworkCredential().Password
        $RootPass     = $Creds.RootCred.GetNetworkCredential().Password
        $EsxiRootPass = $Creds.EsxiCred.GetNetworkCredential().Password

        $DateStr       = Get-Date -Format "yyyyMMdd"
        $vCenterShort  = ($vCenter -split '\.')[0].ToUpper()

        # --- VCSA ---
        Write-Host "`n[1/3] Testing VCSA Audit..." -ForegroundColor Cyan
        $VcsaTarget = [PSCustomObject]@{
            FQDN             = $vCenter
            AdminUser        = $AdminUser
            AdminPass        = $AdminPass
            RootPass         = $RootPass
            vCenterShortName = $vCenterShort
            DateStr          = $DateStr
        }
        $VcsaResult = Invoke-VcsaAudit -Target $VcsaTarget -OverlayRoot $OverlayRoot
        if ($VcsaResult) { 
            $VcsaResult | Format-StigChecklist -OverlayRoot $OverlayRoot 
            Get-StigScanSummary -ReportDir (Join-Path $OverlayRoot "reports/$DateStr/$vCenterShort/VCSA") -AnswersXmlPath (Join-Path $OverlayRoot "conf/vcsa/answers.xml")
            Invoke-StigManSync -vCenterShortName $vCenterShort -SectionReportDir (Join-Path $OverlayRoot "reports/$DateStr/$vCenterShort/VCSA") -OverlayRoot $OverlayRoot
        }

        # --- ESXi ---
        Write-Host "`n[2/3] Testing ESXi Audit..." -ForegroundColor Cyan
        $EsxiTarget = @([PSCustomObject]@{
            Name             = $EsxiHostName
            vCenter          = $vCenter
            AdminUser        = $AdminUser
            AdminPass        = $AdminPass
            RootPass         = $EsxiRootPass
            vCenterShortName = $vCenterShort
            DateStr          = $DateStr
        })
        $EsxiResult = Invoke-EsxiAudit -TargetList $EsxiTarget -OverlayRoot $OverlayRoot
        if ($EsxiResult) { 
            $EsxiResult | Format-StigChecklist -OverlayRoot $OverlayRoot 
            Get-StigScanSummary -ReportDir (Join-Path $OverlayRoot "reports/$DateStr/$vCenterShort/ESXi") -AnswersXmlPath (Join-Path $OverlayRoot "conf/esxi/answers.xml")
            Invoke-StigManSync -vCenterShortName $vCenterShort -SectionReportDir (Join-Path $OverlayRoot "reports/$DateStr/$vCenterShort/ESXi") -OverlayRoot $OverlayRoot
        }

        # --- VM ---
        Write-Host "`n[3/3] Testing VM Audit..." -ForegroundColor Cyan
        $VmTarget = @([PSCustomObject]@{
            Name             = $VmName
            vCenter          = $vCenter
            AdminUser        = $AdminUser
            AdminPass        = $AdminPass
            vCenterShortName = $vCenterShort
            DateStr          = $DateStr
        })
        $VmResult = Invoke-VmAudit -TargetList $VmTarget -OverlayRoot $OverlayRoot
        if ($VmResult) { 
            $VmResult | Format-StigChecklist -OverlayRoot $OverlayRoot 
            Get-StigScanSummary -ReportDir (Join-Path $OverlayRoot "reports/$DateStr/$vCenterShort/VMs") -AnswersXmlPath (Join-Path $OverlayRoot "conf/vm/answers.xml")
            Invoke-StigManSync -vCenterShortName $vCenterShort -SectionReportDir (Join-Path $OverlayRoot "reports/$DateStr/$vCenterShort/VMs") -OverlayRoot $OverlayRoot
        }

        Write-Host "`n[+] Audit testing completed successfully." -ForegroundColor Green
    }

    # =================================================================
    #                       REMEDIATION MODE
    # =================================================================
    elseif ($Mode -eq "Remediation") {

        if (-not $AssetType -or -not $TargetName) {
            throw "When using -Mode Remediation, you must provide both -AssetType and -TargetName."
        }

        Write-Host ""
        Write-Host "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!" -ForegroundColor Red
        Write-Host "!!            WARNING: REMEDIATION MODE ENABLED         !!" -ForegroundColor Red
        Write-Host "!!   This will make real changes to the target asset.   !!" -ForegroundColor Red
        Write-Host "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!" -ForegroundColor Red
        Write-Host ""

        $confirmation = Read-Host "Are you sure you want to proceed with remediation on $AssetType '$TargetName'? (yes/no)"
        if ($confirmation -ne "yes") {
            Write-Host "Remediation cancelled by user." -ForegroundColor Yellow
            return
        }

        Write-Host "`n[MODE] Running REMEDIATION for $AssetType -> $TargetName" -ForegroundColor Yellow

        Invoke-StigRemediation -AssetType $AssetType -TargetName $TargetName -OverlayRoot $OverlayRoot -Silent:$false

        Write-Host "`n[+] Remediation testing completed." -ForegroundColor Green
    }

}
catch {
    Write-StigLog -Message "Targeted Test Runner failed: $_" -Severity ERROR -Source "TestRunner"
    Write-Host "`n[ERROR] $_" -ForegroundColor Red
    exit 1
}

Write-Host "`n========================================================" -ForegroundColor Cyan
Write-Host "               TEST RUN COMPLETED" -ForegroundColor Cyan
Write-Host "========================================================" -ForegroundColor Cyan