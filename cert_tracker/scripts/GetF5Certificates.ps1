#!/usr/bin/env pwsh
<#
.SYNOPSIS
    F5 BIG-IP Certificate Monitor for STIG Automation Overlay.
.DESCRIPTION
    Queries the F5 iControl REST API (/mgmt/tm/sys/file/ssl-cert), directly mapping
    native Subject, Issuer, Fingerprint, and Expiration properties.
    Maintains a persistent rolling CSV and outputs an alphabetized, grouped HTML dashboard.
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory=$true)][string]$OutputHtmlPath,
    [Parameter(Mandatory=$true)][string]$OutputJsonPath,
    [string]$RollingCsvPath = "/usr/share/stigs/orchestration_overlay/cert_tracker/reports/f5_cert_inventory_rolling.csv",
    [string]$ConfigPath     = "/usr/share/stigs/orchestration_overlay/cert_tracker/conf/f5_cert_config.json",
    [string]$VaultPath      = "/usr/share/stigs/orchestration_overlay/conf/.creds.json.encrypted",
    [string]$ModulePath     = "/usr/share/stigs/orchestration_overlay/modules/CredentialManagement.psm1"
)

$ErrorActionPreference = "Stop"

# ---------------------------------------------------------
# 1. Environment & Module Initialization
# ---------------------------------------------------------
if (-not (Test-Path $ModulePath)) { throw "CredentialManagement module not found at: $ModulePath" }
Import-Module $ModulePath -Force

if (-not (Test-Path $ConfigPath)) { throw "Configuration file not found at: $ConfigPath" }
$config = Get-Content -Path $ConfigPath -Raw | ConvertFrom-Json

$disabledList = if ($config.DisabledDevices) { @($config.DisabledDevices) } else { @() }
$critDays     = if ($config.Thresholds.CriticalDays) { [int]$config.Thresholds.CriticalDays } else { 30 }
$warnDays     = if ($config.Thresholds.WarningDays)  { [int]$config.Thresholds.WarningDays }  else { 60 }
$noticeDays   = if ($config.Thresholds.NoticeDays)   { [int]$config.Thresholds.NoticeDays }   else { 90 }

# Ensure destination folders exist
$reportDir = Split-Path -Path $OutputHtmlPath -Parent
if (-not (Test-Path $reportDir)) { New-Item -ItemType Directory -Path $reportDir -Force | Out-Null }
$csvDir = Split-Path -Path $RollingCsvPath -Parent
if (-not (Test-Path $csvDir)) { New-Item -ItemType Directory -Path $csvDir -Force | Out-Null }

$currentScanResults = [System.Collections.Generic.List[PSCustomObject]]::new()
$hasSuccess = $false

# ---------------------------------------------------------
# 2. Health Evaluation Helper
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
# 3. Interrogate F5 Devices via iControl REST API
# ---------------------------------------------------------
foreach ($f5Device in ($config.F5Devices | Sort-Object fqdn)) {
    $fqdn = $f5Device.fqdn

    if ($disabledList -contains $fqdn) {
        Write-Host "[INFO] Skipping disabled F5 device: ${fqdn}"
        continue
    }

    $credObj = Get-F5Credential -FQDN $fqdn -FilePath $VaultPath
    if (-not $credObj -or -not $credObj.AdminCred) {
        Write-Warning "[WARN] Skipping ${fqdn}: No F5 credentials found in vault."
        continue
    }

    Write-Host "[INFO] >>> Interrogating F5 BIG-IP: ${fqdn} <<<" -ForegroundColor Cyan

    $plainPass = $credObj.AdminCred.GetNetworkCredential().Password
    $authHeader = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($credObj.AdminCred.UserName):$plainPass"))
    $headers = @{
        "Authorization" = "Basic $authHeader"
        "Accept"        = "application/json"
    }

    $f5FileApiUrl = "https://${fqdn}/mgmt/tm/sys/file/ssl-cert"

    try {
        $response = Invoke-RestMethod -Uri $f5FileApiUrl -Headers $headers -Method Get -SkipCertificateCheck -ErrorAction Stop
        $records = $response.items

        if (-not $records -or $records.Count -eq 0) {
            Write-Warning "[WARN] No certificate files found on F5 ${fqdn}."
            continue
        }

        Write-Host "[INFO] Discovered $($records.Count) certificate(s) on ${fqdn}."

        foreach ($cert in $records) {
            try {
                $certName  = $cert.name
                $partition = if ($cert.partition) { $cert.partition } else { "Common" }
                $issuer    = if ($cert.issuer) { $cert.issuer } else { "Unknown Issuer" }
                $subject   = if ($cert.subject) { $cert.subject } else { $cert.name }
                $fingerprint = if ($cert.fingerprint) { $cert.fingerprint } else { "N/A" }

                # Parse Expiration Date from Unix epoch or string
                $notAfter = [DateTime]::MinValue
                if ($cert.expirationDate -and [long]$cert.expirationDate -gt 0) {
                    $notAfter = [DateTimeOffset]::FromUnixTimeSeconds([long]$cert.expirationDate).LocalDateTime
                } elseif ($cert.expirationString) {
                    [DateTime]::TryParse($cert.expirationString, [ref]$notAfter) | Out-Null
                }

                if ($notAfter -eq [DateTime]::MinValue) {
                    $notAfter = (Get-Date).AddYears(1)
                }

                $health = Evaluate-CertHealth -NotAfter $notAfter -CritThreshold $critDays -WarnThreshold $warnDays -NoticeThreshold $noticeDays
                $uid = "${fqdn}_${partition}_${certName}"

                $currentScanResults.Add([PSCustomObject]@{
                    UID            = $uid
                    Device         = $fqdn
                    Partition      = $partition
                    CertName       = $certName
                    CertType       = "F5 SSL Cert"
                    Status         = $health.Status
                    StatusClass    = $health.StatusClass
                    Tier           = $health.Tier
                    DaysRemaining  = $health.DaysLeft
                    ExpirationDate = $notAfter.ToString("yyyy-MM-dd HH:mm:ss")
                    Subject        = $subject
                    Issuer         = $issuer
                    Thumbprint     = $fingerprint
                    LastScanned    = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
                })
                $hasSuccess = $true
            } catch {
                Write-Warning "[WARN] Error processing certificate ${certName} on ${fqdn}: $($_.Exception.Message)"
            }
        }
    } catch {
        Write-Warning "[WARN] REST API call failed against F5 device ${fqdn}: $($_.Exception.Message)"
        continue
    }
}

if (-not $hasSuccess -and $currentScanResults.Count -eq 0) {
    throw "No certificate data could be collected from configured F5 targets."
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
        Write-Warning "[WARN] Could not parse existing rolling CSV. Rebuilding."
    }
}

foreach ($item in $currentScanResults) {
    $rollingTable[$item.UID] = [PSCustomObject]@{
        UID            = $item.UID
        Device         = $item.Device
        Partition      = $item.Partition
        CertName       = $item.CertName
        CertType       = $item.CertType
        Status         = $item.Status
        DaysRemaining  = $item.DaysRemaining
        ExpirationDate = $item.ExpirationDate
        Subject        = $item.Subject
        Issuer         = $item.Issuer
        Thumbprint     = $item.Thumbprint
        LastScanned    = $item.LastScanned
    }
}

$rollingList = $rollingTable.Values | Sort-Object Device, Partition, CertName
$rollingList | Export-Csv -Path $RollingCsvPath -NoTypeInformation -Encoding utf8
Write-Host "[SUCCESS] F5 Rolling CSV database updated: $RollingCsvPath" -ForegroundColor Green

# ---------------------------------------------------------
# 5. Build Summary JSON Metadata
# ---------------------------------------------------------
$expiringList = $currentScanResults | Where-Object { $_.DaysRemaining -le $noticeDays } | Sort-Object Device, DaysRemaining
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
$platformTitle = "F5 BIG-IP Certificate Health Report"
$groupedDevices = $currentScanResults | Group-Object Device | Sort-Object Name
$htmlGroups = ""

foreach ($group in $groupedDevices) {
    $deviceName = $group.Name
    $sortedItems = $group.Group | Sort-Object Partition, CertName

    $tableRows = ""
    foreach ($row in $sortedItems) {
        $tableRows += @"
        <tr class="$($row.StatusClass)">
            <td><span class="type-pill">$($row.Partition)</span></td>
            <td><strong>$($row.CertName)</strong></td>
            <td><code>$($row.CertType)</code></td>
            <td><span class="badge $($row.StatusClass)">$($row.Status)</span></td>
            <td><strong>$($row.DaysRemaining) days</strong></td>
            <td>$($row.ExpirationDate)</td>
            <td class="wrap">$($row.Subject)</td>
            <td class="wrap">$($row.Issuer)</td>
            <td class="wrap"><code>$($row.Thumbprint)</code></td>
        </tr>
"@
    }

    $htmlGroups += @"
    <div class="vc-group">
        <div class="vc-header">
            <h2>F5 Device: $deviceName</h2>
            <span class="vc-count">Monitored Certs: $($sortedItems.Count)</span>
        </div>
        <table>
            <thead>
                <tr>
                    <th style="width: 140px;">Partition</th>
                    <th style="width: 220px;">Certificate Name</th>
                    <th style="width: 110px;">Type</th>
                    <th style="width: 100px;">Status</th>
                    <th style="width: 110px;">Remaining</th>
                    <th style="width: 160px;">Valid Until</th>
                    <th>Subject</th>
                    <th>Issuer</th>
                    <th style="width: 180px;">Fingerprint</th>
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
    <title>$platformTitle Dashboard</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background-color: #f8fafc; color: #1e293b; margin: 0; padding: 25px; }
        .container { max-width: 1500px; margin: auto; }
        .main-header { background: #ffffff; padding: 25px; border-radius: 8px; border: 1px solid #e2e8f0; box-shadow: 0 2px 8px rgba(0,0,0,0.05); margin-bottom: 25px; }
        h1 { margin: 0 0 6px 0; color: #0f172a; font-size: 22px; }
        .meta-bar { display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; margin-top: 20px; }
        .card { padding: 15px; border-radius: 6px; text-align: center; background: #f8fafc; border: 1px solid #e2e8f0; }
        .card h2 { margin: 4px 0 0 0; font-size: 24px; }
        .card.crit { border-top: 4px solid #ef4444; color: #991b1b; }
        .card.warn { border-top: 4px solid #f59e0b; color: #92400e; }
        .card.note { border-top: 4px solid #0284c7; color: #075985; }
        .card.good { border-top: 4px solid #10b981; color: #166534; }
        .vc-group { background: #ffffff; border-radius: 8px; border: 1px solid #e2e8f0; box-shadow: 0 1px 3px rgba(0,0,0,0.05); margin-bottom: 20px; overflow: hidden; }
        .vc-header { background: #f8fafc; padding: 12px 20px; display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #e2e8f0; }
        .vc-header h2 { margin: 0; font-size: 15px; color: #0f172a; }
        .vc-count { font-size: 11px; background: #e2e8f0; padding: 3px 8px; border-radius: 4px; color: #475569; font-weight: bold; }
        table { width: 100%; border-collapse: collapse; font-size: 12px; }
        th { background-color: #0f172a; color: #ffffff; text-align: left; padding: 10px; font-size: 11px; text-transform: uppercase; cursor: pointer; user-select: none; }
        th:hover { background-color: #1e293b; }
        th::after { content: " ⇅"; font-size: 10px; opacity: 0.6; }
        td { padding: 9px 10px; border-bottom: 1px solid #f1f5f9; }
        tr:hover { background-color: #f8fafc; }
        .badge { display: inline-block; padding: 2px 8px; border-radius: 12px; font-size: 10px; font-weight: bold; text-transform: uppercase; }
        .badge.healthy { background-color: #ecfdf5; color: #047857; border: 1px solid #10b981; }
        .badge.notice { background-color: #f0f9ff; color: #0369a1; border: 1px solid #0284c7; }
        .badge.warning { background-color: #fffbeb; color: #b45309; border: 1px solid #f59e0b; }
        .badge.critical { background-color: #fef2f2; color: #b91c1c; border: 1px solid #ef4444; }
        .type-pill { background: #f1f5f9; padding: 2px 7px; border-radius: 4px; font-size: 11px; color: #475569; border: 1px solid #e2e8f0; }
        .wrap { max-width: 250px; word-break: break-all; }
        code { font-family: monospace; font-size: 11px; background: #f1f5f9; padding: 2px 5px; border-radius: 4px; color: #334155; border: 1px solid #e2e8f0; }
    </style>
</head>
<body>
    <div class="container">
        <div class="main-header">
            <h1>$platformTitle</h1>
            <p style="color: #64748b; margin: 0; font-size: 13px;"><strong>Generated:</strong> $($summaryData.ExecutionTime) | <em>Tip: Click any table header column to sort.</em></p>
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
Write-Host "[SUCCESS] F5 HTML dashboard written to $OutputHtmlPath" -ForegroundColor Green