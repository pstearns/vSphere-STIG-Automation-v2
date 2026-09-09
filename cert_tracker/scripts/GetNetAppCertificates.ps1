#!/usr/bin/env pwsh
<#
.SYNOPSIS
    NetApp ONTAP Cluster and SVM Certificate Monitor for STIG Automation Overlay.
.DESCRIPTION
    Retrieves AES-256 encrypted credentials from CredentialManagement.psm1,
    queries the ONTAP REST API (/api/security/certificates) for all server, client,
    and CA certificates, updates a persistent rolling CSV, and generates an alphabetized,
    grouped Cyberpunk HTML dashboard.
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory=$true)][string]$OutputHtmlPath,
    [Parameter(Mandatory=$true)][string]$OutputJsonPath,
    [string]$RollingCsvPath = "/usr/share/stigs/orchestration_overlay/cert_tracker/reports/netapp_cert_inventory_rolling.csv",
    [string]$ConfigPath     = "/usr/share/stigs/orchestration_overlay/cert_tracker/conf/netapp_cert_config.json",
    [string]$VaultPath      = "/usr/share/stigs/orchestration_overlay/conf/.creds.json.encrypted",
    [string]$ModulePath     = "/usr/share/stigs/orchestration_overlay/modules/CredentialManagement.psm1"
)

$ErrorActionPreference = "Stop"

# ---------------------------------------------------------
# 1. Environment & Module Initialization
# ---------------------------------------------------------
if (-not (Test-Path $ModulePath)) {
    throw "CredentialManagement module not found at: $ModulePath"
}
Import-Module $ModulePath -Force

if (-not (Test-Path $ConfigPath)) {
    throw "Configuration file not found at: $ConfigPath"
}
$config = Get-Content -Path $ConfigPath -Raw | ConvertFrom-Json

$disabledList = if ($config.DisabledClusters) { @($config.DisabledClusters) } else { @() }
$critDays     = if ($config.Thresholds.CriticalDays) { [int]$config.Thresholds.CriticalDays } else { 30 }
$warnDays     = if ($config.Thresholds.WarningDays)  { [int]$config.Thresholds.WarningDays }  else { 60 }
$noticeDays   = if ($config.Thresholds.NoticeDays)   { [int]$config.Thresholds.NoticeDays }   else { 90 }

# Ensure destination folders exist
$reportDir = Split-Path -Path $OutputHtmlPath -Parent
if (-not (Test-Path $reportDir)) { New-Item -ItemType Directory -Path $reportDir -Force | Out-Null }
$csvDir = Split-Path -Path $RollingCsvPath -Parent
if (-not (Test-Path $csvDir)) { New-Item -ItemType Directory -Path $csvDir -Force | Out-Null }

$vaultStore = Get-NetAppCredentialStore -FilePath $VaultPath
if (-not $vaultStore.netappClusters -or $vaultStore.netappClusters.Count -eq 0) {
    throw "No NetApp clusters found in vault: $VaultPath"
}

$sortedClusters = $vaultStore.netappClusters | Sort-Object FQDN
$currentScanResults = [System.Collections.Generic.List[PSCustomObject]]::new()
$hasSuccess = $false

# ---------------------------------------------------------
# 2. Health Evaluation Function
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

# ---------------------------------------------------------
# 3. Interrogate NetApp Clusters via ONTAP REST API
# ---------------------------------------------------------
foreach ($clusterEntry in $sortedClusters) {
    $fqdn = $clusterEntry.FQDN

    if ($disabledList -contains $fqdn) {
        Write-Host "[INFO] Skipping disabled NetApp cluster target: $fqdn"
        continue
    }

    $credObj = Get-NetAppCredential -FQDN $fqdn -FilePath $VaultPath
    if (-not $credObj -or -not $credObj.AdminCred) {
        Write-Warning "[WARN] Skipping $fqdn - Incomplete credentials in vault."
        continue
    }

    Write-Host "[INFO] >>> Interrogating NetApp Cluster: $fqdn <<<" -ForegroundColor Cyan

    $plainPass = $credObj.AdminCred.GetNetworkCredential().Password
    $authHeader = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($credObj.AdminCred.UserName):$plainPass"))
    $headers = @{
        "Authorization" = "Basic $authHeader"
        "Accept"        = "application/json"
    }

    $certApiUrl = "https://$fqdn/api/security/certificates?fields=name,svm.name,type,scope,expiry_time,common_name,serial_number,public_certificate"

    try {
        $response = Invoke-RestMethod -Uri $certApiUrl -Headers $headers -Method Get -SkipCertificateCheck -ErrorAction Stop
        $records = $response.records

        if (-not $records -or $records.Count -eq 0) {
            Write-Warning "[WARN] No certificate records returned by cluster $fqdn."
            continue
        }

        Write-Host "[INFO] Discovered $($records.Count) certificate(s) on $fqdn."

        foreach ($cert in $records) {
            try {
                $certName = if ($cert.name) { $cert.name } else { $cert.common_name }
                $svmName  = if ($cert.svm -and $cert.svm.name) { $cert.svm.name } else { "Cluster-Scoped" }
                $certType = if ($cert.type) { $cert.type.ToUpper() } else { "SERVER" }
                $scope    = if ($cert.scope) { $cert.scope } else { "cluster" }

                $notAfter = [DateTime]::Parse($cert.expiry_time)
                $health   = Evaluate-CertHealth -NotAfter $notAfter -CritThreshold $critDays -WarnThreshold $warnDays -NoticeThreshold $noticeDays

                $thumbprint = "N/A"
                $issuer     = "ONTAP Internal / Self-Signed"
                $subject    = if ($cert.common_name) { "CN=$($cert.common_name)" } else { $certName }

                if ($cert.public_certificate) {
                    try {
                        $rawBytes = [System.Text.Encoding]::UTF8.GetBytes($cert.public_certificate)
                        $x509 = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($rawBytes)
                        $thumbprint = $x509.Thumbprint
                        if ($x509.Issuer)  { $issuer  = $x509.Issuer }
                        if ($x509.Subject) { $subject = $x509.Subject }
                    } catch {
                        $thumbprint = if ($cert.serial_number) { "SN: $($cert.serial_number)" } else { "N/A" }
                    }
                }

                $uid = "$($fqdn)_$($svmName)_$($certName)"

                $currentScanResults.Add([PSCustomObject]@{
                    UID            = $uid
                    Cluster        = $fqdn
                    SVM            = $svmName
                    CertName       = $certName
                    CertType       = "ONTAP $certType"
                    Scope          = $scope
                    Status         = $health.Status
                    StatusClass    = $health.StatusClass
                    Tier           = $health.Tier
                    DaysRemaining  = $health.DaysLeft
                    ExpirationDate = $notAfter.ToString("yyyy-MM-dd HH:mm:ss")
                    Subject        = $subject
                    Issuer         = $issuer
                    Thumbprint     = $thumbprint
                    LastScanned    = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
                })
                $hasSuccess = $true
            } catch {
                Write-Warning "[WARN] Error processing certificate entry on $fqdn : $($_.Exception.Message)"
            }
        }
    } catch {
        Write-Warning "[WARN] REST API call failed against NetApp cluster $fqdn : $($_.Exception.Message)"
        continue
    }
}

if (-not $hasSuccess -and $currentScanResults.Count -eq 0) {
    throw "No certificate data could be collected from configured NetApp targets."
}

# ---------------------------------------------------------
# 4. Stateful Rolling CSV Database Update
# ---------------------------------------------------------
$rollingTable = @{}
if (Test-Path $RollingCsvPath) {
    try {
        $existingRecords = Import-Csv -Path $RollingCsvPath
        foreach ($rec in $existingRecords) {
            if ($rec.UID) { $rollingTable[$rec.UID] = $rec }
        }
    } catch {
        Write-Warning "[WARN] Could not parse existing rolling CSV. Rebuilding fresh database."
    }
}

foreach ($item in $currentScanResults) {
    $rollingTable[$item.UID] = [PSCustomObject]@{
        UID            = $item.UID
        Cluster        = $item.Cluster
        SVM            = $item.SVM
        CertName       = $item.CertName
        CertType       = $item.CertType
        Scope          = $item.Scope
        Status         = $item.Status
        DaysRemaining  = $item.DaysRemaining
        ExpirationDate = $item.ExpirationDate
        Subject        = $item.Subject
        Issuer         = $item.Issuer
        Thumbprint     = $item.Thumbprint
        LastScanned    = $item.LastScanned
    }
}

$rollingList = $rollingTable.Values | Sort-Object Cluster, SVM, CertName
$rollingList | Export-Csv -Path $RollingCsvPath -NoTypeInformation -Encoding utf8
Write-Host "[SUCCESS] NetApp Rolling CSV database updated: $RollingCsvPath" -ForegroundColor Green

# ---------------------------------------------------------
# 5. Build Summary JSON Metadata
# ---------------------------------------------------------
$expiringList = $currentScanResults | Where-Object { $_.DaysRemaining -le $noticeDays } | Sort-Object Cluster, DaysRemaining
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
# 6. Generate UNIFIED DARK THEME HTML Dashboard
# ---------------------------------------------------------
$platformTitle = "NetApp ONTAP Certificate Health Report" # Set title for this report
$groupedClusters = $currentScanResults | Group-Object Cluster | Sort-Object Name
$htmlGroups = ""

foreach ($group in $groupedClusters) {
    $clusterName = $group.Name
    $sortedItems = $group.Group | Sort-Object SVM, CertName
    $tableRows = ""

    foreach ($row in $sortedItems) {
        $tableRows += @"
        <tr class="$($row.StatusClass)">
            <td><span class="type-pill">$($row.SVM)</span></td>
            <td><strong>$($row.CertName)</strong></td>
            <td><code>$($row.CertType)</code></td>
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
            <h2>NetApp Cluster: $clusterName</h2>
            <span class="vc-count">Monitored Certs: $($sortedItems.Count)</span>
        </div>
        <table>
            <thead>
                <tr>
                    <th style="width: 140px;">SVM / Scope</th>
                    <th style="width: 220px;">Certificate Name</th>
                    <th style="width: 110px;">Type</th>
                    <th style="width: 100px;">Status</th>
                    <th style="width: 110px;">Remaining</th>
                    <th style="width: 160px;">Valid Until</th>
                    <th>Subject / Common Name</th>
                    <th>Issuer</th>
                    <th style="width: 150px;">Thumbprint / SN</th>
                </tr>
            </thead>
            <tbody>
                $tableRows
            </tbody>
        </table>
    </div>
"@
}

# THIS IS THE UPDATED TEMPLATE TO MATCH THE VMWARE DARK THEME
$htmlTemplate = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>$platformTitle Dashboard</title>
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
        th { background-color: #0f172a; color: #94a3b8; text-align: left; padding: 12px 10px; font-size: 11px; text-transform: uppercase; cursor: pointer; user-select: none; }
        th:hover { background-color: #1e293b; }
        th::after { content: " ⇅"; font-size: 10px; opacity: 0.6; }
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
            <h1>$platformTitle</h1>
            <p style="color: #94a3b8; margin: 0; font-size: 13px;"><strong>Generated:</strong> $($summaryData.ExecutionTime) | <em>Tip: Click any table header column to sort.</em></p>
            <div class="meta-bar">
                <div class="card crit">Critical (&le; $critDays d)<h2>$($summaryData.CriticalCount)</h2></div>
                <div class="card warn">Warning (31-$warnDays d)<h2>$($summaryData.WarningCount)</h2></div>
                <div class="card note">Notice (61-$noticeDays d)<h2>$($summaryData.NoticeCount)</h2></div>
                <div class="card good">Healthy (> $noticeDays d)<h2>$($summaryData.HealthyCount)</h2></div>
            </div>
        </div>
        $htmlGroups
    </div>
    <script>
        document.querySelectorAll("th").forEach((th) => {
            th.addEventListener("click", function() {
                const table = this.closest("table");
                const tbody = table.querySelector("tbody");
                const rows = Array.from(tbody.querySelectorAll("tr"));
                const colIndex = Array.from(this.parentNode.children).indexOf(this);
                const isAscending = this.dataset.asc === "true";
                rows.sort((rowA, rowB) => {
                    const valA = rowA.children[colIndex].innerText.trim();
                    const valB = rowB.children[colIndex].innerText.trim();
                    const numA = parseFloat(valA.replace(/[^\d.-]/g, ''));
                    const numB = parseFloat(valB.replace(/[^\d.-]/g, ''));
                    if (!isNaN(numA) && !isNaN(numB) && valA.includes("days")) {
                        return isAscending ? numA - numB : numB - numA;
                    }
                    return isAscending ? valA.localeCompare(valB) : valB.localeCompare(valA);
                });
                this.dataset.asc = !isAscending;
                tbody.innerHTML = "";
                rows.forEach(row => tbody.appendChild(row));
            });
        });
    </script>
</body>
</html>
"@

$htmlTemplate | Out-File -FilePath $OutputHtmlPath -Encoding utf8
Write-Host "[SUCCESS] NetApp HTML dashboard written to $OutputHtmlPath"