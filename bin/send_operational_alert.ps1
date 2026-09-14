#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Operational Maintenance & Task Dispatcher (Non-Audit Jobs).
    Path: /usr/share/stigs/orchestration_overlay/bin/send_operational_alert.ps1
#>
param (
    [Parameter(Mandatory=$true)][string]$JobName,
    [Parameter(Mandatory=$true)][string]$LogPath,
    [Parameter(Mandatory=$true)][int]$ExitCode,
    [ValidateSet("SUCCESS", "FAILED")][string]$Status = "SUCCESS",
    [string]$SummaryJsonPath,
    [string]$ConfigPath = "/usr/share/stigs/orchestration_overlay/conf/mail_config.json"
)

# 1. Load Mail Configuration
if (-not (Test-Path $ConfigPath)) { throw "Mail configuration not found at: $ConfigPath" }
$mailConfig = Get-Content -Path $ConfigPath -Raw | ConvertFrom-Json
$smtpServer = $mailConfig.SmtpServer
$port       = if ($mailConfig.Port) { [int]$mailConfig.Port } else { 25 }
$from       = $mailConfig.From
$recipients = @($mailConfig.To)

$hostname  = [System.Net.Dns]::GetHostName()
$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

# 2. Parse Summary JSON
$summary = $null
if (-not [string]::IsNullOrEmpty($SummaryJsonPath) -and (Test-Path $SummaryJsonPath)) {
    try { $summary = Get-Content -Path $SummaryJsonPath -Raw | ConvertFrom-Json } catch { }
}

$totalSystems = if ($summary.vCenters) { $summary.vCenters.Count } else { 0 }
$totalTargets = if ($summary.TotalTargetsScanned) { $summary.TotalTargetsScanned } else { 0 }

# 3. Construct Subject & Clean HTML Body
$subject = if ($Status -eq "SUCCESS") { "[SUCCESS] Maintenance Completed: $JobName" } else { "[ALERT - FAILED] Maintenance Failure: $JobName" }
$priority = if ($Status -eq "SUCCESS") { [System.Net.Mail.MailPriority]::Normal } else { [System.Net.Mail.MailPriority]::High }

$systemRows = ""
if ($summary.vCenters.Count -gt 0) {
    foreach ($sys in $summary.vCenters) {
        $badge = if ($sys.Status -eq "SUCCESS") {
            "<span style='background-color: #ecfdf5; color: #047857; border: 1px solid #10b981; padding: 2px 8px; border-radius: 10px; font-size: 11px; font-weight: bold;'>SUCCESS</span>"
        } else {
            "<span style='background-color: #fef2f2; color: #b91c1c; border: 1px solid #ef4444; padding: 2px 8px; border-radius: 10px; font-size: 11px; font-weight: bold;'>FAILED</span>"
        }

        $systemRows += @"
        <tr style="border-bottom: 1px solid #e2e8f0;">
            <td style="padding: 10px; font-weight: bold; color: #0f172a;">$($sys.Name)</td>
            <td style="padding: 10px; color: #475569;">$($sys.Scope)</td>
            <td style="padding: 10px; text-align: center;">$badge</td>
            <td style="padding: 10px; text-align: center; font-weight: bold;">$($sys.TargetsScanned)</td>
        </tr>
"@
    }
}

$htmlBody = @"
<!DOCTYPE html>
<html>
<body style="background-color: #f1f5f9; color: #334155; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 25px;">
    <div style="max-width: 850px; margin: auto; background-color: #ffffff; border: 1px solid #e2e8f0; border-top: 5px solid #0284c7; border-radius: 8px; padding: 30px;">
        <div style="border-bottom: 2px solid #0f172a; padding-bottom: 15px; margin-bottom: 20px;">
            <h1 style="color: #0f172a; margin: 0 0 6px 0; font-size: 20px;">Task Execution Summary: $JobName</h1>
            <div style="color: #64748b; font-size: 12px;"><strong>Host:</strong> $hostname &nbsp;|&nbsp; <strong>Executed:</strong> $timestamp</div>
        </div>

        <table style="width: 100%; border-collapse: separate; border-spacing: 12px; margin-bottom: 20px;">
            <tr>
                <td style="width: 50%; background-color: #f8fafc; border: 1px solid #e2e8f0; border-top: 4px solid #10b981; border-radius: 6px; padding: 15px; text-align: center;">
                    <div style="color: #64748b; font-size: 11px; text-transform: uppercase; font-weight: bold;">ESXi Hosts Rotated</div>
                    <div style="color: #166534; font-size: 28px; font-weight: bold; margin-top: 4px;">$totalTargets</div>
                </td>
                <td style="width: 50%; background-color: #f8fafc; border: 1px solid #e2e8f0; border-top: 4px solid #0284c7; border-radius: 6px; padding: 15px; text-align: center;">
                    <div style="color: #64748b; font-size: 11px; text-transform: uppercase; font-weight: bold;">vCenters Updated</div>
                    <div style="color: #075985; font-size: 28px; font-weight: bold; margin-top: 4px;">$totalSystems</div>
                </td>
            </tr>
        </table>

        <div style="border: 1px solid #cbd5e1; border-radius: 6px; overflow: hidden;">
            <table style="width: 100%; border-collapse: collapse; font-size: 12px; text-align: left;">
                <thead>
                    <tr style="background-color: #0f172a; color: #ffffff; font-size: 11px; text-transform: uppercase;">
                        <th style="padding: 10px;">vCenter Server</th>
                        <th style="padding: 10px;">Scope</th>
                        <th style="padding: 10px; text-align: center;">Status</th>
                        <th style="padding: 10px; text-align: center;">Hosts Rotated</th>
                    </tr>
                </thead>
                <tbody>$systemRows</tbody>
            </table>
        </div>
    </div>
</body>
</html>
"@

# 4. Dispatch
$mailMsg = [System.Net.Mail.MailMessage]::new()
$mailMsg.From = [System.Net.Mail.MailAddress]::new($from)
$mailMsg.Subject = $subject
$mailMsg.Body = $htmlBody
$mailMsg.IsBodyHtml = $true
$mailMsg.Priority = $priority
foreach ($r in $recipients) { if (-not [string]::IsNullOrWhiteSpace($r)) { $mailMsg.To.Add($r.Trim()) } }
$smtp = [System.Net.Mail.SmtpClient]::new($smtpServer, $port)
$smtp.EnableSsl = if ($mailConfig.EnableSsl -eq $true) { $true } else { $false }
$smtp.Send($mailMsg)
$smtp.Dispose()
$mailMsg.Dispose()