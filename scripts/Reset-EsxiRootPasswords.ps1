<#
.SYNOPSIS
    ESXi Root Password Rotator with Automated STIG Verification & JSON Summary Output.
    Path: /usr/share/stigs/orchestration_overlay/scripts/Reset-EsxiRootPasswords.ps1
#>
param (
    [string]$TargetVC,  # Optional: Pass FQDN or shortname to target a single vCenter
    [string]$GlobalConfigPath = "/usr/share/stigs/orchestration_overlay/conf/global_config.yml",
    [string]$VaultPath        = "/usr/share/stigs/orchestration_overlay/conf/.creds.json.encrypted",
    [string]$ModulePath       = "/usr/share/stigs/orchestration_overlay/modules/CredentialManagement.psm1",
    [string]$SummaryOutputPath = "/usr/share/stigs/orchestration_overlay/reports/esxi_rotation_summary.json"
)

$ErrorActionPreference = "Continue"

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

# ---------------------------------------------------------
# 3. Target vCenter Inventory (From global_config.yml)
# ---------------------------------------------------------
if (-not (Test-Path $GlobalConfigPath)) {
    Write-Error "[FATAL] global_config.yml not found at: $GlobalConfigPath"
    [System.Environment]::Exit(1)
}

$VC_list = @()
if (Get-Module -ListAvailable -Name powershell-yaml) {
    Import-Module powershell-yaml -ErrorAction SilentlyContinue
    $globalConfig = Get-Content -Path $GlobalConfigPath -Raw | ConvertFrom-Yaml
    $VC_list = @($globalConfig.vcenter_targets | Where-Object { $_.enabled -eq $true -or $_.enabled -eq "true" } | ForEach-Object { $_.fqdn })
} else {
    # Zero-dependency regex parser fallback
    $rawYaml = Get-Content -Path $GlobalConfigPath -Raw
    $blocks = [regex]::Matches($rawYaml, '(?ms)-\s*fqdn:\s*"([^"]+)".*?enabled:\s*(true|false)')
    foreach ($b in $blocks) {
        if ($b.Groups[2].Value.Trim() -eq "true") {
            $VC_list += $b.Groups[1].Value.Trim()
        }
    }
}

# Optional Target Filtering: Filter by exact FQDN or short hostname
if (-not [string]::IsNullOrWhiteSpace($TargetVC)) {
    $matchedVC = $VC_list | Where-Object { $_ -eq $TargetVC -or ($_ -split '\.')[0] -eq ($TargetVC -split '\.')[0] }
    if (-not $matchedVC) {
        Write-Error "[FATAL] Specified target vCenter '$TargetVC' is not active or not found in $GlobalConfigPath"
        [System.Environment]::Exit(1)
    }
    $VC_list = @($matchedVC)
    Write-Host "[INFO] Filtered scope: Single target vCenter [$($VC_list[0])]" -ForegroundColor Yellow
}

if ($VC_list.Count -eq 0) {
    Write-Error "[FATAL] No active/enabled vCenter targets found."
    [System.Environment]::Exit(1)
}

Write-Host "[INFO] Loaded $($VC_list.Count) target vCenter(s) to process." -ForegroundColor Cyan

# Metric accumulators
$overallSuccess      = $true
$vCenterReportList   = @()
$totalTargetsScanned = 0
$totalPassedHosts    = 0
$totalFailedHosts    = 0

foreach ($VC in $VC_list) {
    Write-Host "`n========================================================"
    Write-Host "[INFO] Processing vCenter: ${VC}"
    Write-Host "========================================================"

    $vcPassedHosts = 0
    $vcFailedHosts = 0
    $targetsScanned = 0

    $vcEntry = Get-vCenterCredential -FQDN $VC -FilePath $VaultPath
    if (-not $vcEntry -or -not $vcEntry.AdminCred -or -not $vcEntry.EsxiCred) {
        Write-Warning "Skipping ${VC} - Missing AdminCred or EsxiCred in vault ($VaultPath)."
        $overallSuccess = $false
        $vCenterReportList += [PSCustomObject]@{
            Name           = $VC
            Scope          = "ESXi Root Password Rotation"
            Status         = "FAILED"
            TargetsScanned = 0
            Passed         = 0
            Failed         = 0
        }
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
            Passed         = 0
            Failed         = 0
        }
        continue
    }

    $vmhosts = Get-VMHost | Sort-Object Name
    $targetsScanned = if ($vmhosts) { $vmhosts.Count } else { 0 }
    $totalTargetsScanned += $targetsScanned
    Write-Host "[INFO] Found $targetsScanned ESXi host(s) managed by ${VC}"

    foreach ($vmhost in $vmhosts) {
        Write-Host "`n---> Rotating root password on ESXi Host: $($vmhost.Name)"

        if ($vmhost.ConnectionState -ne "Connected") {
            Write-Warning "[WARN] Host $($vmhost.Name) is in state '$($vmhost.ConnectionState)'. Marking as FAILED."
            $overallSuccess = $false
            $vcFailedHosts++
            continue
        }

        try {
            # 1. Temporarily clear history & aging constraints
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
            $vcPassedHosts++
        } catch {
            Write-Error "[ERROR] Failed password rotation on $($vmhost.Name): $($_.Exception.Message)"
            $overallSuccess = $false
            $vcFailedHosts++

            try {
                $vmhost | Get-AdvancedSetting -Name "Security.PasswordHistory" | Set-AdvancedSetting -Value "5" -Confirm:$false | Out-Null
                $vmhost | Get-AdvancedSetting -Name "Security.PasswordMaxDays" | Set-AdvancedSetting -Value "90" -Confirm:$false | Out-Null
            } catch { }
        }
    }

    $totalPassedHosts += $vcPassedHosts
    $totalFailedHosts += $vcFailedHosts

    $vcStatus = if ($vcFailedHosts -eq 0 -and $targetsScanned -gt 0) { "SUCCESS" } else { "FAILED" }

    $vCenterReportList += [PSCustomObject]@{
        Name           = $VC
        Scope          = "ESXi Root Password Rotation"
        Status         = $vcStatus
        TargetsScanned = $targetsScanned
        Passed         = $vcPassedHosts
        Failed         = $vcFailedHosts
    }

    Disconnect-VIServer $connection -Confirm:$false | Out-Null
}

# --- Generate JSON Summary for send_operational_alert.ps1 ---
$summaryObj = [PSCustomObject]@{
    TotalTargetsScanned = $totalTargetsScanned
    TotalPassedHosts    = $totalPassedHosts
    TotalFailedHosts    = $totalFailedHosts
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