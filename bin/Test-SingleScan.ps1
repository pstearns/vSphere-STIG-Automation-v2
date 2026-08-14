<#
.SYNOPSIS
    Secure test harness to verify targeted single-asset scanning, checklist formatting,
    and optimized summaries for VCSA, ESXi, and VMs using secure credentials from the vault.
#>
[CmdletBinding()]
param (
    [Parameter(Mandatory=$true, HelpMessage="The FQDN of the target vCenter Server as stored in the vault.")][string]$vCenter,
    [Parameter(Mandatory=$true, HelpMessage="The exact name of the ESXi Host to scan.")][string]$EsxiHostName,
    [Parameter(Mandatory=$true, HelpMessage="The exact name of the VM to scan.")][string]$VmName,
    [string]$OverlayRoot = "/usr/share/stigs/orchestration_overlay"
)

# 1. Import Master Modules and Worker Dependencies
Write-Host "[*] Importing secure STIG Orchestration modules..." -ForegroundColor Cyan
Import-Module (Join-Path $OverlayRoot "modules/globalFunctions.psm1") -Force
Import-Module (Join-Path $OverlayRoot "modules/CredentialManagement.psm1") -Force
Import-Module (Join-Path $OverlayRoot "modules/StigOrchestration.psm1") -Force
Import-Module (Join-Path $OverlayRoot "modules/vcsa/Invoke-VcsaAudit.psm1") -Force
Import-Module (Join-Path $OverlayRoot "modules/esxi/Invoke-EsxiAudit.psm1") -Force
Import-Module (Join-Path $OverlayRoot "modules/vm/Invoke-VmAudit.psm1") -Force

# 2. Retrieve secure credentials from the AES-256 Vault
$CredentialFile = Join-Path $OverlayRoot "conf/.creds.json.encrypted"
if (-not (Test-Path $CredentialFile)) {
    Write-Error "Secure credential store not found at $CredentialFile. Please configure credentials first."
    return
}

Write-Host "[*] Retrieving credentials from secure vault for FQDN: ${$vCenter}..." -ForegroundColor Cyan
$vCenterCreds = Get-vCenterCredential -FQDN $vCenter -FilePath $CredentialFile

if ($null -eq $vCenterCreds) {
    Write-Error "No credentials returned for $vCenter. Ensure FQDN matches exactly with vault records."
    return
}

# Safely extract decrypted credentials in-memory
$AdminUser    = $vCenterCreds.AdminCred.UserName
$AdminPass    = $vCenterCreds.AdminCred.GetNetworkCredential().Password
$VcsaRootPass = $vCenterCreds.RootCred.GetNetworkCredential().Password
$EsxiRootPass = $vCenterCreds.EsxiCred.GetNetworkCredential().Password

# 3. Initialize dual-channel Logging (Prints to console & logs)
$LogDir = Join-Path $OverlayRoot "logs"
Initialize-StigLogging -LogDirectory $LogDir -Silent:$false

$DateStr = Get-Date -Format "yyyyMMdd"
$vCenterShort = ($vCenter -split '\.')[0].ToUpper()

Write-Host "`n========================================================" -ForegroundColor Cyan
Write-Host "             STARTING SECURE END-TO-END TEST RUN" -ForegroundColor Cyan
Write-Host "========================================================" -ForegroundColor Cyan

# =========================================================================
# TEST 1: SINGLE VCSA AUDIT -> CHECKLIST -> SECTION SUMMARY
# =========================================================================
Write-Host "`n[TEST 1/3] Initiating VCSA Appliance STIG Run..." -ForegroundColor Yellow

$SingleVcsaTarget = [PSCustomObject]@{
    FQDN             = $vCenter
    AdminUser        = $AdminUser
    AdminPass        = $AdminPass
    RootPass         = $VcsaRootPass
    vCenterShortName = $vCenterShort
    DateStr          = $DateStr
    ReportDir        = Join-Path $OverlayRoot "reports/$DateStr/$vCenterShort/VCSA"
}

try {
    # Execute VCSA Worker directly
    $VcsaResult = Invoke-VcsaAudit -Target $SingleVcsaTarget -OverlayRoot $OverlayRoot
    
    if ($null -ne $VcsaResult) {
        # Stream into checklist formatter
        $VcsaResult | Format-StigChecklist -OverlayRoot $OverlayRoot
        
        # Run optimized section-based summary
        $VcsaReportPath = Join-Path $OverlayRoot "reports/$DateStr/$vCenterShort/VCSA"
        $VcsaAnswersXml = Join-Path $OverlayRoot "conf/vcsa/answers.xml"
        
        Write-Host "`n[+] VCSA Audit & Formatting finished. Running section summary..." -ForegroundColor Green
        Get-StigScanSummary -ReportDir $VcsaReportPath -AnswersXmlPath $VcsaAnswersXml
    } else {
        Write-Warning "VCSA Audit completed but did not produce XML results."
    }
}
catch {
    Write-Host "[CRITICAL ERROR] VCSA test pipeline failed: $_" -ForegroundColor Red
}

# =========================================================================
# TEST 2: SINGLE ESXI AUDIT -> CHECKLIST -> SECTION SUMMARY
# =========================================================================
Write-Host "`n[TEST 2/3] Initiating Single ESXi Host STIG Run..." -ForegroundColor Yellow

$SingleEsxiTarget = @(
    [PSCustomObject]@{
        Name             = $EsxiHostName
        vCenter          = $vCenter
        AdminUser        = $AdminUser
        AdminPass        = $AdminPass
        RootPass         = $EsxiRootPass
        vCenterShortName = $vCenterShort
        DateStr          = $DateStr
    }
)

try {
    # Execute ESXi worker with vault credentials
    $EsxiResult = Invoke-EsxiAudit -TargetList $SingleEsxiTarget -OverlayRoot $OverlayRoot
    
    if ($null -ne $EsxiResult) {
        # Stream into checklist formatter
        $EsxiResult | Format-StigChecklist -OverlayRoot $OverlayRoot
        
        # Run optimized section-based summary
        $EsxiReportPath = Join-Path $OverlayRoot "reports/$DateStr/$vCenterShort/ESXi"
        $EsxiAnswersXml = Join-Path $OverlayRoot "conf/esxi/answers.xml"
        
        Write-Host "`n[+] ESXi Audit & Formatting finished. Running section summary..." -ForegroundColor Green
        Get-StigScanSummary -ReportDir $EsxiReportPath -AnswersXmlPath $EsxiAnswersXml
    } else {
        Write-Warning "ESXi Audit completed but did not produce XML results."
    }
}
catch {
    Write-Host "[CRITICAL ERROR] ESXi test pipeline failed: $_" -ForegroundColor Red
}

# =========================================================================
# TEST 3: SINGLE VM AUDIT -> CHECKLIST -> SECTION SUMMARY
# =========================================================================
Write-Host "`n[TEST 3/3] Initiating Single Virtual Machine STIG Run..." -ForegroundColor Yellow

$SingleVmTarget = @(
    [PSCustomObject]@{
        Name             = $VmName
        vCenter          = $vCenter
        AdminUser        = $AdminUser
        AdminPass        = $AdminPass
        vCenterShortName = $vCenterShort
        DateStr          = $DateStr
    }
)

try {
    # Execute VM worker with vault credentials
    $VmResult = Invoke-VmAudit -TargetList $SingleVmTarget -OverlayRoot $OverlayRoot
    
    if ($null -ne $VmResult) {
        # Stream into checklist formatter
        $VmResult | Format-StigChecklist -OverlayRoot $OverlayRoot
        
        # Run optimized section-based summary
        $VmReportPath = Join-Path $OverlayRoot "reports/$DateStr/$vCenterShort/VMs"
        $VmAnswersXml = Join-Path $OverlayRoot "conf/vm/answers.xml"
        
        Write-Host "`n[+] VM Audit & Formatting finished. Running section summary..." -ForegroundColor Green
        Get-StigScanSummary -ReportDir $VmReportPath -AnswersXmlPath $VmAnswersXml
    } else {
        Write-Warning "VM Audit completed but did not produce XML results."
    }
}
catch {
    Write-Host "[CRITICAL ERROR] VM test pipeline failed: $_" -ForegroundColor Red
}

Write-Host "`n========================================================" -ForegroundColor Cyan
Write-Host "                TEST SCAN EXECUTION COMPLETE" -ForegroundColor Cyan
Write-Host "========================================================" -ForegroundColor Cyan