#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Comprehensive VMware (vCenter & ESXi) Certificate Monitor & Auditor.
.DESCRIPTION
    Interrogates vCenter Machine SSL (direct TLS socket), vSphere REST certificate
    endpoints (Machine TLS and Trusted Root Chains), and all managed ESXi hosts via PowerCLI.
    Maintains a persistent rolling CSV inventory and outputs an alphabetized, grouped HTML dashboard.
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory=$true)][string]$OutputHtmlPath,
    [Parameter(Mandatory=$true)][string]$OutputJsonPath,
    [string]$RollingCsvPath = "/usr/share/stigs/orchestration_overlay/cert_tracker/reports/vmware_cert_inventory_rolling.csv",
    [string]$ConfigPath     = "/usr/share/stigs/orchestration_overlay/cert_tracker/conf/vmware_cert_config.json",
    [string]$VaultPath      = "/usr/share/stigs/orchestration_overlay/conf/.creds.json.encrypted",
    [string]$ModulePath     = "/usr/share/stigs/orchestration_overlay/modules/CredentialManagement.psm1"
)

$ErrorActionPreference = "Continue"

# ---------------------------------------------------------
# 1. Environment & Module Initialization
# ---------------------------------------------------------
if (Get-Module -ListAvailable -Name VMware.PowerCLI) {
    Set-PowerCLIConfiguration -InvalidCertificateAction Ignore -Confirm:$false | Out-Null
}

if (-not (Test-Path $ModulePath)) { throw "CredentialManagement module not found at: $ModulePath" }
Import-Module $ModulePath -Force

if (-not (Test-Path $ConfigPath)) { throw "Configuration file not found at: $ConfigPath" }
$config = Get-Content -Path $ConfigPath -Raw | ConvertFrom-Json

$disabledList = if ($config.DisabledvCenters) { @($config.DisabledvCenters) } else { @() }
$critDays     = if ($config.Thresholds.CriticalDays) { [int]$config.Thresholds.CriticalDays } else { 30 }
$warnDays     = if ($config.Thresholds.WarningDays)  { [int]$config.Thresholds.WarningDays }  else { 60 }
$noticeDays   = if ($config.Thresholds.NoticeDays)   { [int]$config.Thresholds.NoticeDays }   else { 90 }

# Ensure parent output folders exist
$reportDir = Split-Path -Path $OutputHtmlPath -Parent
if (-not (Test-Path $reportDir)) { New-Item -ItemType Directory -Path $reportDir -Force | Out-Null }
$csvDir = Split-Path -Path $RollingCsvPath -Parent
if (-not (Test-Path $csvDir)) { New-Item -ItemType Directory -Path $csvDir -Force | Out-Null }

$vaultStore = Get-vCenterCredentialStore -FilePath $VaultPath
if (-not $vaultStore.vCenters -or $vaultStore.vCenters.Count -eq 0) {
    throw "No vCenter targets discovered in vault: $VaultPath"
}

# Alphabetize target vCenters
$sortedVCenters = $vaultStore.vCenters | Sort-Object FQDN
$currentScanResults = [System.Collections.Generic.List[PSCustomObject]]::new()
$hasSuccess = $false

# ---------------------------------------------------------
# 2. Helper Functions
# ---------------------------------------------------------
function Evaluate-CertHealth {
    param([DateTime]$NotAfter, [int]$CritThreshold, [int]$WarnThreshold, [int]$NoticeThreshold)
    $daysLeft = [math]::Floor(($NotAfter - (Get-Date)).TotalDays)

    if ($daysLeft -le 0) {
        $status = "EXPIRED"; $statusClass = "critical"; $tier = "Critical (<= $CritThreshold d)"
    } elseif ($daysLeft -le $CritThreshold) {
        $status = "CRITICAL"; $statusClass = "critical"; $tier = "Critical (<= $CritThreshold d)"
    } elseif ($daysLeft -le $WarnThreshold) {
        $status = "WARNING"; $statusClass = "warning"; $tier = "Warning (31-$WarnThreshold d)"
    } elseif ($daysLeft -le $NoticeThreshold) {
        $status = "NOTICE"; $statusClass = "notice"; $tier = "Notice (61-$NoticeThreshold d)"
    } else {
        $status = "HEALTHY"; $statusClass = "healthy"; $tier = "Healthy (> $NoticeThreshold d)"
    }

    return @{
        Status      = $status
        StatusClass = $statusClass
        Tier        = $tier
        DaysLeft    = $daysLeft
    }
}

function Get-vCenterMachineSslDirect {
    param([string]$FQDN)
    try {
        $tcpClient = [System.Net.Sockets.TcpClient]::new($FQDN, 443)
        $sslStream = [System.Net.Security.SslStream]::new(
            $tcpClient.GetStream(),
            $false,
            { param($sender, $certificate, $chain, $sslPolicyErrors) return $true }
        )
        $sslStream.AuthenticateAsClient($FQDN)
        $remoteCert = $sslStream.RemoteCertificate
        $x509 = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($remoteCert)
        $sslStream.Dispose()
        $tcpClient.Dispose()
        return $x509
    } catch {
        Write-Warning "[WARN] Direct SSL handshake failed on port 443 for $FQDN : $($_.Exception.Message)"
        return $null
    }
}

function Get-vCenterRestCertificates {
    param([string]$FQDN, [PSCredential]$Credential)
    $results = @()
    $baseUri = "https://$FQDN/api"
    $plainPass = $Credential.GetNetworkCredential().Password
    $authHeader = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($Credential.UserName):$plainPass"))

    try {
        $sessionToken = Invoke-RestMethod -Uri "$baseUri/session" -Method Post -Headers @{ Authorization = "Basic $authHeader" } -SkipCertificateCheck -ErrorAction Stop
        $sessionHeader = @{ "vmware-api-session-id" = $sessionToken }

        # Query Active Machine TLS Certificate via REST
        try {
            $tlsCert = Invoke-RestMethod -Uri "$baseUri/vcenter/certificate-management/vcenter/tls" -Method Get -Headers $sessionHeader -SkipCertificateCheck -ErrorAction Stop
            if ($tlsCert.cert) {
                $certBytes = [System.Text.Encoding]::UTF8.GetBytes($tlsCert.cert)
                $results += [PSCustomObject]@{
                    CertType   = "Machine SSL (REST)"
                    CertObject = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($certBytes)
                }
            }
        } catch {
            Write-Warning "[WARN] Could not retrieve Machine TLS cert via REST from $FQDN : $($_.Exception.Message)"
        }

        # Query Trusted Root Chains (VMCA / External Roots)
        try {
            $rootChains = Invoke-RestMethod -Uri "$baseUri/vcenter/certificate-management/vcenter/trusted-root-chains" -Method Get -Headers $sessionHeader -SkipCertificateCheck -ErrorAction Stop
            foreach ($chain in $rootChains) {
                $chainDetails = Invoke-RestMethod -Uri "$baseUri/vcenter/certificate-management/vcenter/trusted-root-chains/$($chain.chain)" -Method Get -Headers $sessionHeader -SkipCertificateCheck
                foreach ($certStr in $chainDetails.cert_chain.certificates) {
                    $cBytes = [System.Text.Encoding]::UTF8.GetBytes($certStr)
                    $results += [PSCustomObject]@{
                        CertType   = "Trusted Root / VMCA"
                        CertObject = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($cBytes)
                    }
                }
            }
        } catch {
            Write-Warning "[WARN] Could not query root chains via REST from $FQDN : $($_.Exception.Message)"
        }

        # Terminate REST Session
        Invoke-RestMethod -Uri "$baseUri/session" -Method Delete -Headers $sessionHeader -SkipCertificateCheck -ErrorAction SilentlyContinue | Out-Null
    } catch {
        Write-Warning "[WARN] REST API session creation failed on $FQDN : $($_.Exception.Message)"
    }
    return $results
}

# ---------------------------------------------------------
# 3. Target Processing & Interrogation Loop
# ---------------------------------------------------------
foreach ($vcEntry in $sortedVCenters) {
    $fqdn = $vcEntry.FQDN

    if ($disabledList -contains $fqdn) {
        Write-Host "[INFO] Skipping disabled vCenter target: $fqdn"
        continue
    }

    $credObj = Get-vCenterCredential -FQDN $fqdn -FilePath $VaultPath
    if (-not $credObj -or -not $credObj.AdminCred) {
        Write-Warning "[WARN] Skipping $fqdn - Incomplete credentials in vault."
        continue
    }

    Write-Host "[INFO] >>> Processing vCenter: $fqdn <<<" -ForegroundColor Cyan

    # --- Phase A: Interrogate Direct Port 443 Machine SSL Certificate ---
    $machineCert = Get-vCenterMachineSslDirect -FQDN $fqdn
    if ($machineCert) {
        $health = Evaluate-CertHealth -NotAfter $machineCert.NotAfter -CritThreshold $critDays -WarnThreshold $warnDays -NoticeThreshold $noticeDays
        $currentScanResults.Add([PSCustomObject]@{
            UID            = "$($fqdn)_VCENTER_MACHINESSL"
            vCenter        = $fqdn
            CategoryOrder  = 1
            EndpointType   = "vCenter Machine SSL"
            EndpointName   = "$fqdn"
            Status         = $health.Status
            StatusClass    = $health.StatusClass
            Tier           = $health.Tier
            DaysRemaining  = $health.DaysLeft
            ExpirationDate = $machineCert.NotAfter.ToString("yyyy-MM-dd HH:mm:ss")
            Subject        = $machineCert.Subject
            Issuer         = $machineCert.Issuer
            Thumbprint     = $machineCert.Thumbprint
            LastScanned    = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
        })
        $hasSuccess = $true
    }

    # --- Phase C: Connect via PowerCLI & Interrogate Managed ESXi Hosts ---
    Write-Host "[INFO] Connecting PowerCLI session to $fqdn..."
    try {
        $viConnection = Connect-VIServer $fqdn -Credential $credObj.AdminCred -ErrorAction Stop
    } catch {
        Write-Warning "[WARN] Failed PowerCLI connection to $fqdn : $($_.Exception.Message)"
        continue
    }

    try {
        $vmHosts = Get-VMHost | Sort-Object Name
        Write-Host "[INFO] Auditing $($vmHosts.Count) ESXi host(s) managed by $fqdn..."

        foreach ($esx in $vmHosts) {
            try {
                $hostView = $esx | Get-View -Property Config.Certificate
                $rawCert  = $hostView.Config.Certificate
                $certObj  = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($rawCert)
                $notAfter = $certObj.NotAfter
                $health   = Evaluate-CertHealth -NotAfter $notAfter -CritThreshold $critDays -WarnThreshold $warnDays -NoticeThreshold $noticeDays

                $currentScanResults.Add([PSCustomObject]@{
                    UID            = "$($fqdn)_ESXI_$($esx.Name)"
                    vCenter        = $fqdn
                    CategoryOrder  = 3
                    EndpointType   = "ESXi Host"
                    EndpointName   = $esx.Name
                    Status         = $health.Status
                    StatusClass    = $health.StatusClass
                    Tier           = $health.Tier
                    DaysRemaining  = $health.DaysLeft
                    ExpirationDate = $notAfter.ToString("yyyy-MM-dd HH:mm:ss")
                    Subject        = $certObj.Subject
                    Issuer         = $certObj.Issuer
                    Thumbprint     = $certObj.Thumbprint
                    LastScanned    = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
                })
                $hasSuccess = $true
            } catch {
                Write-Warning "[WARN] Error interrogating ESXi host $($esx.Name): $($_.Exception.Message)"
            }
        }
    } finally {
        Disconnect-VIServer $viConnection -Confirm:$false
    }
}

if (-not $hasSuccess -and $currentScanResults.Count -eq 0) {
    throw "No certificate data could be collected from any configured vCenter target."
}

# ---------------------------------------------------------
# 4. Update Stateful Rolling CSV Database
# ---------------------------------------------------------
$rollingTable = @{}
if (Test-Path $RollingCsvPath) {
    try {
        $existingRecords = Import-Csv -Path $RollingCsvPath
        foreach ($rec in $existingRecords) {
            if ($rec.UID) { $rollingTable[$rec.UID] = $rec }
        }
    } catch {
        Write-Warning "[WARN] Could not parse existing rolling CSV. Initializing new database."
    }
}

foreach ($item in $currentScanResults) {
    $rollingTable[$item.UID] = [PSCustomObject]@{
        UID            = $item.UID
        vCenter        = $item.vCenter
        EndpointType   = $item.EndpointType
        EndpointName   = $item.EndpointName
        Status         = $item.Status
        DaysRemaining  = $item.DaysRemaining
        ExpirationDate = $item.ExpirationDate
        Subject        = $item.Subject
        Issuer         = $item.Issuer
        Thumbprint     = $item.Thumbprint
        LastScanned    = $item.LastScanned
    }
}

$rollingList = $rollingTable.Values | Sort-Object vCenter, EndpointType, EndpointName
$rollingList | Export-Csv -Path $RollingCsvPath -NoTypeInformation -Encoding utf8
Write-Host "[SUCCESS] Rolling CSV database updated: $RollingCsvPath"

# ---------------------------------------------------------
# 5. Build Summary JSON for Email Dispatcher
# ---------------------------------------------------------
$expiringList = $currentScanResults | Where-Object { $_.DaysRemaining -le $noticeDays } | Sort-Object vCenter, DaysRemaining
$summaryData = [PSCustomObject]@{
    ExecutionTime   = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
    TotalMonitored  = $currentScanResults.Count
    CriticalCount   = ($currentScanResults | Where-Object { $_.DaysRemaining -le $critDays }).Count
    WarningCount    = ($currentScanResults | Where-Object { $_.DaysRemaining -gt $critDays -and $_.DaysRemaining -le $warnDays }).Count
    NoticeCount     = ($currentScanResults | Where-Object { $_.DaysRemaining -gt $warnDays -and $_.DaysRemaining -le $noticeDays }).Count
    HealthyCount    = ($currentScanResults | Where-Object { $_.DaysRemaining -gt $noticeDays }).Count
    ExpiringRecords = @($expiringList)
}
$summaryData | ConvertTo-Json -Depth 6 | Out-File -FilePath $OutputJsonPath -Encoding utf8

# ---------------------------------------------------------
# 6. Generate Alphabetized & Grouped HTML Dashboard
# ---------------------------------------------------------
$groupedVCenters = $currentScanResults | Group-Object vCenter | Sort-Object Name
$htmlGroups = ""

foreach ($group in $groupedVCenters) {
    $vcName = $group.Name
    # Sort order: vCenter Appliance certs first, then alphabetized ESXi hosts
    $sortedGroupItems = $group.Group | Sort-Object CategoryOrder, EndpointName

    $tableRows = ""
    foreach ($row in $sortedGroupItems) {
        $tableRows += @"
        <tr class="$($row.StatusClass)">
            <td><span class="type-pill">$($row.EndpointType)</span></td>
            <td><strong>$($row.EndpointName)</strong></td>
            <td><span class="badge $($row.StatusClass)">$($row.Status)</span></td>
            <td><strong>$($row.DaysRemaining) days</strong></td>
            <td>$($row.ExpirationDate)</td>
            <td class="wrap">$($row.Subject)</td>
            <td class="wrap">$($row.Issuer)</td>
            <td><code>$($row.Thumbprint)</code></td>
        </tr>
"@
    }

    $htmlGroups += @"
    <div class="vc-group">
        <div class="vc-header">
            <h2>vCenter: $vcName</h2>
            <span class="vc-count">Monitored Items: $($sortedGroupItems.Count)</span>
        </div>
        <table>
            <thead>
                <tr>
                    <th style="width: 160px;">Certificate Type</th>
                    <th style="width: 240px;">Endpoint / Resource</th>
                    <th style="width: 100px;">Status</th>
                    <th style="width: 110px;">Remaining</th>
                    <th style="width: 160px;">Valid Until</th>
                    <th>Subject</th>
                    <th>Issuer</th>
                    <th style="width: 150px;">Thumbprint</th>
                </tr>
            </thead>
            <tbody>
                $tableRows
            </tbody>
        </table>
    </div>
"@
}

$htmlTemplate = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>VMware Infrastructure Certificate Health Dashboard</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background-color: #0b0f19; color: #e2e8f0; margin: 0; padding: 25px; }
        .container { max-width: 1500px; margin: auto; }
        .main-header { background: #1e293b; padding: 25px; border-radius: 10px; border: 1px solid #334155; margin-bottom: 25px; }
        h1 { margin: 0 0 10px 0; color: #38bdf8; font-size: 24px; }
        .meta-bar { display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; margin-top: 20px; }
        .card { padding: 15px; border-radius: 8px; text-align: center; background: #0f172a; border: 1px solid #334155; }
        .card h2 { margin: 5px 0 0 0; font-size: 26px; color: #fff; }
        .card.crit { border-top: 4px solid #ef4444; }
        .card.warn { border-top: 4px solid #f59e0b; }
        .card.note { border-top: 4px solid #38bdf8; }
        .card.good { border-top: 4px solid #10b981; }
        .vc-group { background: #1e293b; border-radius: 10px; border: 1px solid #334155; margin-bottom: 25px; overflow: hidden; }
        .vc-header { background: #111827; padding: 12px 20px; display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #334155; }
        .vc-header h2 { margin: 0; font-size: 17px; color: #93c5fd; }
        .vc-count { font-size: 12px; background: #374151; padding: 3px 8px; border-radius: 4px; color: #cbd5e1; }
        table { width: 100%; border-collapse: collapse; font-size: 13px; }
        th { background-color: #0f172a; color: #94a3b8; text-align: left; padding: 12px 10px; font-size: 11px; text-transform: uppercase; letter-spacing: 0.5px; }
        td { padding: 10px; border-bottom: 1px solid #2d3748; }
        tr:hover { background-color: #283548; }
        .badge { display: inline-block; padding: 3px 8px; border-radius: 12px; font-size: 11px; font-weight: bold; text-transform: uppercase; }
        .badge.healthy { background-color: rgba(16, 185, 129, 0.2); color: #34d399; border: 1px solid #059669; }
        .badge.notice { background-color: rgba(56, 189, 248, 0.2); color: #38bdf8; border: 1px solid #0284c7; }
        .badge.warning { background-color: rgba(245, 158, 11, 0.2); color: #fbbf24; border: 1px solid #d97706; }
        .badge.critical { background-color: rgba(239, 68, 68, 0.2); color: #f87171; border: 1px solid #dc2626; }
        .type-pill { background: #334155; padding: 2px 7px; border-radius: 4px; font-size: 11px; color: #e2e8f0; }
        .wrap { max-width: 250px; word-break: break-all; }
        code { font-family: monospace; font-size: 11px; background: #0f172a; padding: 2px 5px; border-radius: 4px; color: #cbd5e1; }
    </style>
</head>
<body>
    <div class="container">
        <div class="main-header">
            <h1>VMware Infrastructure Certificate Health Report</h1>
            <p style="color: #94a3b8; margin: 0;"><strong>Execution Timestamp:</strong> $($summaryData.ExecutionTime)</p>
            <div class="meta-bar">
                <div class="card crit">Critical (&le; $critDays d)<h2>$($summaryData.CriticalCount)</h2></div>
                <div class="card warn">Warning (31-$warnDays d)<h2>$($summaryData.WarningCount)</h2></div>
                <div class="card note">Notice (61-$noticeDays d)<h2>$($summaryData.NoticeCount)</h2></div>
                <div class="card good">Healthy (> $noticeDays d)<h2>$($summaryData.HealthyCount)</h2></div>
            </div>
        </div>
        $htmlGroups
    </div>
</body>
</html>
"@

$htmlTemplate | Out-File -FilePath $OutputHtmlPath -Encoding utf8
Write-Host "[SUCCESS] Grouped HTML dashboard written to $OutputHtmlPath"