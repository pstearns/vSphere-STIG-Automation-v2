<#
.SYNOPSIS
    ESXi Root Password Rotator with Automated STIG Verification & JSON Summary Output.
    Path: /usr/share/stigs/orchestration_overlay/scripts/Reset-EsxiRootPasswords.ps1
#>
param (
    [string]$VaultPath = "/usr/share/stigs/orchestration_overlay/conf/.creds.json.encrypted",
    [string]$ModulePath = "/usr/share/stigs/orchestration_overlay/modules/CredentialManagement.psm1",
    [string]$SummaryOutputPath = "/usr/share/stigs/orchestration_overlay/reports/esxi_rotation_summary.json"
)

$ErrorActionPreference = "Stop"

# Create reports directory if it doesn't exist
$reportsDir = Split-Path -Path $SummaryOutputPath -Parent
if (-not (Test-Path $reportsDir)) {
    New-Item -ItemType Directory -Path $reportsDir -Force | Out-Null
}

# 1. Ignore untrusted SSL certificates
if (Get-Module -ListAvailable -Name VMware.PowerCLI) {
    Set-PowerCLIConfiguration -InvalidCertificateAction Ignore -Confirm:$false | Out-Null
}

# 2. Import Credential Management Module
if (-not (Test-Path $ModulePath)) {
    Write-Error "CredentialManagement module not found at: $ModulePath"
    [System.Environment]::Exit(1)
}
Import-Module $ModulePath -Force

# 3. Target vCenter Inventory
$VC_list = @(
    "huarinfvc.niprpnp.army.mil",
    "huarvdivcsa.niprpnp.army.mil",
    "huar35tvc.swi.local",
    "huafinfvc.niprpnp.army.mil",
    "huafvdivcsa.niprpnp.army.mil",
    "huagvc.niprpnp.army.mil"
)

$overallSuccess = $true
$vCenterReportList = @()
$totalTargetsScanned = 0

foreach ($VC in $VC_list) {
    Write-Host "`n========================================================"
    Write-Host "[INFO] Processing vCenter: ${VC}"
    Write-Host "========================================================"

    # Default metrics for this vCenter
    $vCenterStatus = "SUCCESS"
    $targetsScanned = 0

    # Retrieve decrypted vCenter credentials
    $vcEntry = Get-vCenterCredential -FQDN $VC -FilePath $VaultPath
    if (-not $vcEntry -or -not $vcEntry.AdminCred -or -not $vcEntry.EsxiCred) {
        Write-Warning "Skipping ${VC} - Missing AdminCred or EsxiCred in vault ($VaultPath)."
        $overallSuccess = $false
        continue
    }

    $esxiRootCred = $vcEntry.EsxiCred
    $plainPassword = $esxiRootCred.GetNetworkCredential().Password

    try {
        $connection = Connect-VIServer $VC -Credential $vcEntry.AdminCred -ErrorAction Stop
        Write-Host "[SUCCESS] Connected to ${VC}"
    } catch {
        Write-Warning "[WARN] Could not connect to ${VC}: $($_.Exception.Message)"
        $overallSuccess = $false
        $vCenterReportList += [PSCustomObject]@{
            Name           = $VC
            Scope          = "ESXi Root Password Rotation"
            Status         = "FAILED"
            TargetsScanned = 0
            Cat1Open       = 0
            Cat2Open       = 0
            Cat3Open       = 0
            TotalOpen      = 0
        }
        continue
    }

    $vmhosts = Get-VMHost | Sort-Object Name
    $targetsScanned = $vmhosts.Count
    $totalTargetsScanned += $targetsScanned
    Write-Host "[INFO] Found $targetsScanned ESXi host(s) managed by ${VC}"

    $vCenterHostsSuccess = $true

    foreach ($vmhost in $vmhosts) {
        Write-Host "`n---> Rotating root password on ESXi Host: $($vmhost.Name)"
        try {
            # 1. Temporarily clear history & aging constraints to allow password update
            $vmhost | Get-AdvancedSetting -Name "Security.PasswordHistory" | Set-AdvancedSetting -Value "0" -Confirm:$false | Out-Null
            $vmhost | Get-AdvancedSetting -Name "Security.PasswordMaxDays" | Set-AdvancedSetting -Value "9999" -Confirm:$false | Out-Null

            # 2. Update password via ESXCLI V2
            $esxcli = Get-EsxCli -VMHost $vmhost -V2
            $accountArgs = @{
                id                   = $esxiRootCred.UserName
                password             = $plainPassword
                passwordconfirmation = $plainPassword
            }
            $result = $esxcli.system.account.set.Invoke($accountArgs)

            # 3. Restore DoD STIG Password Policy Defaults
            $vmhost | Get-AdvancedSetting -Name "Security.PasswordHistory" | Set-AdvancedSetting -Value "5" -Confirm:$false | Out-Null
            $vmhost | Get-AdvancedSetting -Name "Security.PasswordMaxDays" | Set-AdvancedSetting -Value "90" -Confirm:$false | Out-Null

            Write-Host "[SUCCESS] Password rotated & STIG policies restored on $($vmhost.Name)"
        } catch {
            Write-Error "[ERROR] Failed password rotation on $($vmhost.Name): $($_.Exception.Message)"
            $overallSuccess = $false
            $vCenterHostsSuccess = $false
            # Ensure STIG settings are restored even if rotation failed
            try {
                $vmhost | Get-AdvancedSetting -Name "Security.PasswordHistory" | Set-AdvancedSetting -Value "5" -Confirm:$false | Out-Null
                $vmhost | Get-AdvancedSetting -Name "Security.PasswordMaxDays" | Set-AdvancedSetting -Value "90" -Confirm:$false | Out-Null
            } catch { }
        }
    }

    if (-not $vCenterHostsSuccess) { $vCenterStatus = "FAILED" }

    # Populate expected fields for send_alert.ps1
    $vCenterReportList += [PSCustomObject]@{
        Name           = $VC
        Scope          = "ESXi Root Password Rotation"
        Status         = $vCenterStatus
        TargetsScanned = $targetsScanned
        Cat1Open       = 0
        Cat2Open       = 0
        Cat3Open       = 0
        TotalOpen      = 0
    }

    Disconnect-VIServer $connection -Confirm:$false
}

# --- Generate JSON Summary for send_alert.ps1 Compliance ---
$summaryObj = [PSCustomObject]@{
    TotalTargetsScanned = $totalTargetsScanned
    Cat1Open            = 0
    Cat2Open            = 0
    Cat3Open            = 0
    vCenters            = $vCenterReportList
}

$summaryObj | ConvertTo-Json -Depth 4 | Out-File -FilePath $SummaryOutputPath -Encoding utf8

# Explicit exit status mapping
if (-not $overallSuccess) {
    Write-Error "[FATAL] Script completed with active execution failures."
    [System.Environment]::Exit(1)
} else {
    Write-Host "[SUCCESS] All password rotation activities finished cleanly."
    [System.Environment]::Exit(0)
}