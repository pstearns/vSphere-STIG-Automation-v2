param (
    [string]$VaultPath = "/usr/share/stigs/orchestration_overlay/conf/.creds.json.encrypted",
    [string]$ModulePath = "/usr/share/stigs/orchestration_overlay/modules/CredentialManagement.psm1"
)

$ErrorActionPreference = "Stop"

# 1. Ignore untrusted SSL certificates
if (Get-Module -ListAvailable -Name VMware.PowerCLI) {
    Set-PowerCLIConfiguration -InvalidCertificateAction Ignore -Confirm:$false | Out-Null
}

# 2. Import Credential Management Module
if (-not (Test-Path $ModulePath)) {
    throw "CredentialManagement module not found at: $ModulePath"
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

foreach ($VC in $VC_list) {
    Write-Host "`n========================================================"
    Write-Host "[INFO] Processing vCenter: ${VC}"
    Write-Host "========================================================"

    # Retrieve decrypted vCenter credentials (AdminCred & EsxiCred)
    $vcEntry = Get-vCenterCredential -FQDN $VC -FilePath $VaultPath
    if (-not $vcEntry -or -not $vcEntry.AdminCred -or -not $vcEntry.EsxiCred) {
        Write-Warning "Skipping ${VC} - Missing AdminCred or EsxiCred in vault ($VaultPath)."
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
        continue
    }

    $vmhosts = Get-VMHost | Sort-Object Name
    Write-Host "[INFO] Found $($vmhosts.Count) ESXi host(s) managed by ${VC}"

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
            # Ensure STIG settings are restored even if the rotation call failed
            try {
                $vmhost | Get-AdvancedSetting -Name "Security.PasswordHistory" | Set-AdvancedSetting -Value "5" -Confirm:$false | Out-Null
                $vmhost | Get-AdvancedSetting -Name "Security.PasswordMaxDays" | Set-AdvancedSetting -Value "90" -Confirm:$false | Out-Null
            } catch { }
            $overallSuccess = $false
        }
    }

    Disconnect-VIServer $connection -Confirm:$false
}

if (-not $overallSuccess) {
    throw "One or more ESXi hosts encountered errors during password rotation."
}