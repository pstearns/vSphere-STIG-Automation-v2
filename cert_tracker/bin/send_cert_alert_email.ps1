#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Universal Enterprise-Themed Certificate Alert Email Dispatcher (VMware, NetApp & F5 Compatible).
.DESCRIPTION
    Dynamically renders title banners, platform scope, and grouped 30/60/90-day alert tables
    based on the executing JobName and the properties of the incoming summary data.
#>

param (
    [Parameter(Mandatory=$true)][string]$JobName,
    [Parameter(Mandatory=$true)][string]$LogPath,
    [Parameter(Mandatory=$true)][int]$ExitCode,
    [ValidateSet("SUCCESS", "FAILED")][string]$Status = "SUCCESS",
    [string]$AttachmentPath,
    [string]$SummaryJsonPath,
    [string]$ConfigPath = "/usr/share/stigs/orchestration_overlay/cert_tracker/conf/vmware_cert_config.json"
)

# 1. Load Mail Configuration
if (-not (Test-Path $ConfigPath)) { throw "Configuration file not found at: $ConfigPath" }
$config = Get-Content -Path $ConfigPath -Raw | ConvertFrom-Json
$mailConfig = $config.MailConfig

$smtpServer = $mailConfig.SmtpServer
$port       = if ($mailConfig.Port) { [int]$mailConfig.Port } else { 25 }
$from       = $mailConfig.From
$recipients = @($mailConfig.To)

$hostname   = [System.Net.Dns]::GetHostName()
$timestamp  = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

# Determine Display Branding dynamically from JobName
if ($JobName -match "F5") {
    $platformTitle = "F5 BIG-IP Certificate Health Report"
    $targetLabel   = "F5 Device"
    $rollingDbFile = "f5_cert_inventory_rolling.csv"
} elseif ($JobName -match "NetApp") {
    $platformTitle = "NetApp ONTAP Certificate Health Report"
    $targetLabel   = "NetApp Cluster"
    $rollingDbFile = "netapp_cert_inventory_rolling.csv"
} else {
    $platformTitle = "VMware Infrastructure Certificate Health Report"
    $targetLabel   = "vCenter"
    $rollingDbFile = "vmware_cert_inventory_rolling.csv"
}

# 2. Build HTML Body
if ($Status -eq "FAILED" -or $ExitCode -ne 0) {
    $subject  = "[ALERT - FAILED] Certificate Monitor: $JobName"
    $priority = [System.Net.Mail.MailPriority]::High

    $logTail = ""
    if (Test-Path $LogPath) {
        $logTail = [System.Web.HttpUtility]::HtmlEncode(((Get-Content -Path $LogPath -Tail 50) -join "`n"))
    }

    $htmlBody = @"
<!DOCTYPE html>
<html>
<body style="background-color: #f1f5f9; color: #1e293b; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; margin: 0; padding: 20px;">
    <div style="max-width: 900px; margin: auto; background-color: #ffffff; border: 1px solid #ef4444; border-top: 5px solid #ef4444; box-shadow: 0 4px 6px rgba(0,0,0,0.05); border-radius: 8px; padding: 25px;">
        <h1 style="color: #991b1b; margin-top: 0; font-size: 20px; border-bottom: 1px solid #e2e8f0; padding-bottom: 10px;">
            AUTOMATION JOB FAILURE: $JobName
        </h1>
        <table style="width: 100%; font-size: 13px; color: #475569; margin-bottom: 15px;">
            <tr><td><strong>Host:</strong> $hostname</td><td><strong>Timestamp:</strong> $timestamp</td></tr>
            <tr><td><strong>Status:</strong> <span style="color: #ef4444; font-weight: bold;">FAILED (Exit Code: $ExitCode)</span></td><td><strong>Log Path:</strong> $LogPath</td></tr>
        </table>
        <h3 style="color: #0f172a; margin-bottom: 5px; font-size: 14px;">Last 50 Log Lines:</h3>
        <pre style="background-color: #0f172a; color: #f8fafc; padding: 15px; border-radius: 6px; font-size: 11px; overflow-x: auto; white-space: pre-wrap;">$logTail</pre>
    </div>
</body>
</html>
"@
} else {
    $summary = $null
    if (-not [string]::IsNullOrEmpty($SummaryJsonPath) -and (Test-Path $SummaryJsonPath)) {
        $summary = Get-Content -Path $SummaryJsonPath -Raw | ConvertFrom-Json
    }

    $critCount = if ($summary) { $summary.CriticalCount } else { 0 }
    $warnCount = if ($summary) { $summary.WarningCount } else { 0 }
    $noteCount = if ($summary) { $summary.NoticeCount } else { 0 }
    $goodCount = if ($summary) { $summary.HealthyCount } else { 0 }
    $totCount  = if ($summary) { $summary.TotalMonitored } else { 0 }

    if ($critCount -gt 0) {
        $subject  = "[CRITICAL ALERT] Certificate Expirations Detected ($JobName)"
        $priority = [System.Net.Mail.MailPriority]::High
    } elseif ($warnCount -gt 0) {
        $subject  = "[WARNING] Upcoming Certificate Expirations ($JobName)"
        $priority = [System.Net.Mail.MailPriority]::High
    } else {
        $subject  = "[REPORT] Certificate Status: $JobName"
        $priority = [System.Net.Mail.MailPriority]::Normal
    }

    # Build Grouped Expiration Tables
    $imminentTables = ""
    if ($summary -and $summary.ExpiringRecords -and $summary.ExpiringRecords.Count -gt 0) {
        
        # Dynamic grouping property detection
        $firstRecProps = $summary.ExpiringRecords[0].PSObject.Properties.Name
        $groupingProperty = if ($firstRecProps -contains 'Device') { 
            'Device' 
        } elseif ($firstRecProps -contains 'Cluster') { 
            'Cluster' 
        } else { 
            'vCenter' 
        }

        $groupedExpiring = $summary.ExpiringRecords | Group-Object $groupingProperty | Sort-Object Name

        foreach ($grp in $groupedExpiring) {
            $rows = ""
            foreach ($cert in ($grp.Group | Sort-Object DaysRemaining)) {
                $badgeStyle = "background-color: #ecfdf5; color: #047857; border: 1px solid #10b981;"
                if ($cert.DaysRemaining -le 30) {
                    $badgeStyle = "background-color: #fef2f2; color: #b91c1c; border: 1px solid #ef4444; font-weight: bold;"
                } elseif ($cert.DaysRemaining -le 60) {
                    $badgeStyle = "background-color: #fffbeb; color: #b45309; border: 1px solid #f59e0b; font-weight: bold;"
                } elseif ($cert.DaysRemaining -le 90) {
                    $badgeStyle = "background-color: #f0f9ff; color: #0369a1; border: 1px solid #0284c7;"
                }

                $endpointDisplay = if ($cert.EndpointName) { $cert.EndpointName } else { $cert.CertName }
                $typeDisplay     = if ($cert.EndpointType) { $cert.EndpointType } else { $cert.CertType }
                $scopeDisplay    = if ($cert.Partition) { 
                    "<span style='color:#64748b; font-size:11px;'>($($cert.Partition))</span>" 
                } elseif ($cert.SVM) { 
                    "<span style='color:#64748b; font-size:11px;'>($($cert.SVM))</span>" 
                } else { 
                    "" 
                }

                $rows += @"
                <tr style="border-bottom: 1px solid #e2e8f0;">
                    <td style="padding: 10px; color: #334155;">$typeDisplay $scopeDisplay</td>
                    <td style="padding: 10px; color: #0f172a; font-weight: bold;">$endpointDisplay</td>
                    <td style="padding: 10px;"><span style="display: inline-block; padding: 3px 8px; border-radius: 12px; font-size: 11px; text-transform: uppercase; $badgeStyle">$($cert.Status)</span></td>
                    <td style="padding: 10px; color: #0f172a; font-weight: bold;">$($cert.DaysRemaining) days</td>
                    <td style="padding: 10px; color: #475569;">$($cert.ExpirationDate)</td>
                </tr>
"@
            }

            $imminentTables += @"
            <div style="margin-top: 20px; border: 1px solid #cbd5e1; border-radius: 6px; overflow: hidden; background-color: #ffffff;">
                <div style="background-color: #f8fafc; padding: 10px 15px; border-bottom: 1px solid #cbd5e1; color: #0f172a; font-weight: bold; font-size: 13px;">
                    [ ${targetLabel}: $($grp.Name) ]
                </div>
                <table style="width: 100%; border-collapse: collapse; font-size: 12px; text-align: left;">
                    <thead>
                        <tr style="background-color: #0f172a; color: #ffffff; font-size: 11px; text-transform: uppercase;">
                            <th style="padding: 10px;">Type / Scope</th>
                            <th style="padding: 10px;">Resource / Cert Name</th>
                            <th style="padding: 10px;">Status</th>
                            <th style="padding: 10px;">Remaining</th>
                            <th style="padding: 10px;">Expiration Date</th>
                        </tr>
                    </thead>
                    <tbody>
                        $rows
                    </tbody>
                </table>
            </div>
"@
        }
    } else {
        $imminentTables = @"
        <div style="padding: 15px; background: #ecfdf5; border: 1px solid #10b981; border-radius: 6px; color: #047857; margin-top: 15px; text-align: center; font-weight: bold; font-size: 13px;">
            [OK] All monitored certificates have greater than 90 days remaining validity.
        </div>
"@
    }

    $htmlBody = @"
<!DOCTYPE html>
<html>
<body style="background-color: #f1f5f9; color: #334155; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; margin: 0; padding: 25px;">
    <div style="max-width: 1000px; margin: auto; background-color: #ffffff; border: 1px solid #e2e8f0; border-radius: 8px; box-shadow: 0 4px 12px rgba(0,0,0,0.05); padding: 30px;">
        
        <!-- Header -->
        <div style="border-bottom: 2px solid #0f172a; padding-bottom: 15px; margin-bottom: 25px;">
            <h1 style="color: #0f172a; margin: 0 0 6px 0; font-size: 22px;">
                $platformTitle
            </h1>
            <div style="color: #64748b; font-size: 12px;">
                <strong>Host:</strong> $hostname &nbsp;|&nbsp; 
                <strong>Job:</strong> $JobName &nbsp;|&nbsp; 
                <strong>Execution Time:</strong> $timestamp
            </div>
        </div>

        <!-- Metric Cards -->
        <table style="width: 100%; border-collapse: separate; border-spacing: 12px; margin-bottom: 20px;">
            <tr>
                <td style="width: 25%; background-color: #f8fafc; border: 1px solid #e2e8f0; border-top: 4px solid #ef4444; border-radius: 6px; padding: 15px; text-align: center;">
                    <div style="color: #64748b; font-size: 11px; text-transform: uppercase; font-weight: bold;">Critical (&le; 30d)</div>
                    <div style="color: #991b1b; font-size: 26px; font-weight: bold; margin-top: 4px;">$critCount</div>
                </td>
                <td style="width: 25%; background-color: #f8fafc; border: 1px solid #e2e8f0; border-top: 4px solid #f59e0b; border-radius: 6px; padding: 15px; text-align: center;">
                    <div style="color: #64748b; font-size: 11px; text-transform: uppercase; font-weight: bold;">Warning (31-60d)</div>
                    <div style="color: #92400e; font-size: 26px; font-weight: bold; margin-top: 4px;">$warnCount</div>
                </td>
                <td style="width: 25%; background-color: #f8fafc; border: 1px solid #e2e8f0; border-top: 4px solid #0284c7; border-radius: 6px; padding: 15px; text-align: center;">
                    <div style="color: #64748b; font-size: 11px; text-transform: uppercase; font-weight: bold;">Notice (61-90d)</div>
                    <div style="color: #075985; font-size: 26px; font-weight: bold; margin-top: 4px;">$noteCount</div>
                </td>
                <td style="width: 25%; background-color: #f8fafc; border: 1px solid #e2e8f0; border-top: 4px solid #10b981; border-radius: 6px; padding: 15px; text-align: center;">
                    <div style="color: #64748b; font-size: 11px; text-transform: uppercase; font-weight: bold;">Healthy (> 90d)</div>
                    <div style="color: #166534; font-size: 26px; font-weight: bold; margin-top: 4px;">$goodCount</div>
                </td>
            </tr>
        </table>

        <!-- Imminent Expiration Section -->
        <h2 style="color: #0f172a; font-size: 15px; margin: 25px 0 10px 0; text-transform: uppercase; letter-spacing: 0.5px;">
            Imminent Expirations (&le; 90 Days)
        </h2>
        $imminentTables

        <!-- Footer -->
        <div style="margin-top: 30px; padding-top: 15px; border-top: 1px solid #e2e8f0; color: #64748b; font-size: 12px; text-align: center;">
            <p style="margin: 0 0 4px 0;"><strong>Total Monitored Scope:</strong> $totCount certificates</p>
            <p style="margin: 0; color: #94a3b8;">Detailed dashboard attached. Rolling database updated at <code>/usr/share/stigs/orchestration_overlay/cert_tracker/reports/$rollingDbFile</code></p>
        </div>

    </div>
</body>
</html>
"@
}

# 3. Dispatch Email via SmtpClient
try {
    $mailMsg = [System.Net.Mail.MailMessage]::new()
    $mailMsg.From = [System.Net.Mail.MailAddress]::new($from)
    $mailMsg.Subject = $subject
    $mailMsg.Body = $htmlBody
    $mailMsg.IsBodyHtml = $true
    $mailMsg.Priority = $priority

    $mailMsg.Headers.Add("Content-Language", "en-US")
    $mailMsg.Headers.Add("Accept-Language", "en-US, en")

    foreach ($recipient in $recipients) {
        if (-not [string]::IsNullOrWhiteSpace($recipient)) {
            $mailMsg.To.Add($recipient.Trim())
        }
    }

    if ($Status -eq "SUCCESS" -and -not [string]::IsNullOrEmpty($AttachmentPath) -and (Test-Path $AttachmentPath)) {
        $attachment = [System.Net.Mail.Attachment]::new($AttachmentPath)
        $mailMsg.Attachments.Add($attachment)
    }

    $smtpClient = [System.Net.Mail.SmtpClient]::new($smtpServer, $port)
    $smtpClient.EnableSsl = if ($mailConfig.EnableSsl -eq $true) { $true } else { $false }
    $smtpClient.Send($mailMsg)

    $smtpClient.Dispose()
    $mailMsg.Dispose()

    $recipientList = ($recipients -join ", ")
    Write-Host "[INFO] Enterprise certificate email ($Status) dispatched to: $recipientList" -ForegroundColor Green
} catch {
    Write-Error "[ERROR] Failed to dispatch email: $($_.Exception.Message)"
    exit 1
}