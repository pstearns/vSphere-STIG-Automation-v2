#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Universal Enterprise STIG Report & Alert Dispatcher.
.DESCRIPTION
    Dispatches styled HTML emails for STIG automation jobs across multiple technologies 
    (VMware vCenter, ESXi, NetApp ONTAP, etc.). Generates generic system metrics,
    open finding metrics (CAT I/II/III), and execution metadata.
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
if (-not (Test-Path $ConfigPath)) {
    throw "Mail configuration file not found at: $ConfigPath"
}

$mailConfig = Get-Content -Path $ConfigPath -Raw | ConvertFrom-Json
$smtpServer = $mailConfig.SmtpServer
$port       = if ($mailConfig.Port) { [int]$mailConfig.Port } else { 25 }
$from       = $mailConfig.From
$recipients = @($mailConfig.To)

$hostname  = [System.Net.Dns]::GetHostName()
$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

# 2. Parse Summary JSON if available
$summary = $null
if (-not [string]::IsNullOrEmpty($SummaryJsonPath) -and (Test-Path $SummaryJsonPath)) {
    try {
        $summary = Get-Content -Path $SummaryJsonPath -Raw | ConvertFrom-Json
    } catch {
        Write-Warning "Could not parse summary JSON at '$SummaryJsonPath': $($_.Exception.Message)"
    }
}

# 3. Construct Subject Line & HTML Body
$htmlBody = ""

# --- FAILURE or NO SUMMARY ---
if ($Status -eq "FAILED" -or $ExitCode -ne 0 -or $null -eq $summary) {
    $subject  = "[ALERT - FAILED] STIG Automation: $JobName"
    $priority = [System.Net.Mail.MailPriority]::High

    $logTail = ""
    if (Test-Path $LogPath) {
        $rawLog = (Get-Content -Path $LogPath -Tail 50) -join "`n"
        $logTail = [System.Web.HttpUtility]::HtmlEncode($rawLog)
    }

    $htmlBody = @"
<!DOCTYPE html>
<html>
<body style="background-color: #f1f5f9; color: #1e293b; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; margin: 0; padding: 20px;">
    <div style="max-width: 950px; margin: auto; background-color: #ffffff; border: 1px solid #ef4444; border-top: 5px solid #ef4444; border-radius: 8px; padding: 25px;">
        <h1 style="color: #991b1b; margin-top: 0; font-size: 20px; border-bottom: 1px solid #e2e8f0; padding-bottom: 10px;">
            STIG AUTOMATION EXECUTION FAILURE: $JobName
        </h1>
        <table style="width: 100%; font-size: 13px; color: #475569; margin-bottom: 15px;">
            <tr><td style="padding: 4px 0;"><strong>Host:</strong> $hostname</td><td style="padding: 4px 0;"><strong>Timestamp:</strong> $timestamp</td></tr>
            <tr><td style="padding: 4px 0;"><strong>Status:</strong> <span style="color: #ef4444; font-weight: bold;">FAILED (Exit Code: $ExitCode)</span></td><td style="padding: 4px 0;"><strong>Log File:</strong> <code>$LogPath</code></td></tr>
        </table>
        <h3 style="color: #0f172a; margin-bottom: 5px; font-size: 14px;">Last 50 Execution Log Lines:</h3>
        <pre style="background-color: #0f172a; color: #f8fafc; padding: 15px; border-radius: 6px; font-size: 11px; overflow-x: auto; white-space: pre-wrap; font-family: 'Consolas', 'Courier New', monospace;">$logTail</pre>
    </div>
</body>
</html>
"@
# --- SUCCESS WITH SUMMARY ---
} else {
    # Backward compatible with both 'vCenters' or 'Systems' tags
    $totalSystems   = if ($summary.vCenters) { $summary.vCenters.Count } else { 0 }
    $totalTargets   = if ($summary.TotalTargetsScanned) { $summary.TotalTargetsScanned } else { 0 }
    $cat1Open       = if ($summary.Cat1Open) { $summary.Cat1Open } else { 0 }
    $cat2Open       = if ($summary.Cat2Open) { $summary.Cat2Open } else { 0 }
    $cat3Open       = if ($summary.Cat3Open) { $summary.Cat3Open } else { 0 }
    $totalOpen      = $cat1Open + $cat2Open + $cat3Open

    if ($cat1Open -gt 0) {
        $subject  = "[STIG ALERT - CAT I DETECTED] $JobName ($cat1Open Open CAT I)"
        $priority = [System.Net.Mail.MailPriority]::High
    } elseif ($totalOpen -gt 0) {
        $subject  = "[STIG REPORT] $JobName - $totalOpen Open Findings"
        $priority = [System.Net.Mail.MailPriority]::Normal
    } else {
        $subject  = "[SUCCESS] STIG Compliance Report: $JobName"
        $priority = [System.Net.Mail.MailPriority]::Normal
    }

    # Generate Technology-Agnostic Breakdown Table Rows
    $systemRows = ""
    if ($summary.vCenters.Count -gt 0) {
        foreach ($sys in $summary.vCenters) {
            $statusBadge = if ($sys.Status -eq "SUCCESS") {
                "<span style='background-color: #ecfdf5; color: #047857; border: 1px solid #10b981; padding: 2px 8px; border-radius: 10px; font-size: 11px; font-weight: bold;'>SUCCESS</span>"
            } else {
                "<span style='background-color: #fef2f2; color: #b91c1c; border: 1px solid #ef4444; padding: 2px 8px; border-radius: 10px; font-size: 11px; font-weight: bold;'>FAILED</span>"
            }
            $cat1Cell = if ($sys.Cat1Open -gt 0) { "<strong style='color: #b91c1c;'>$($sys.Cat1Open)</strong>" } else { "0" }
            $cat2Cell = if ($sys.Cat2Open -gt 0) { "<span style='color: #b45309;'>$($sys.Cat2Open)</span>" } else { "0" }
            
            $systemRows += @"
            <tr style="border-bottom: 1px solid #e2e8f0;">
                <td style="padding: 10px; font-weight: bold; color: #0f172a;">$($sys.Name)</td>
                <td style="padding: 10px; color: #475569;">$($sys.Scope)</td>
                <td style="padding: 10px; text-align: center;">$statusBadge</td>
                <td style="padding: 10px; text-align: center;">$($sys.TargetsScanned)</td>
                <td style="padding: 10px; text-align: center;">$cat1Cell</td>
                <td style="padding: 10px; text-align: center;">$cat2Cell</td>
                <td style="padding: 10px; text-align: center;">$($sys.Cat3Open)</td>
                <td style="padding: 10px; text-align: center; font-weight: bold; color: #0f172a;">$($sys.TotalOpen)</td>
            </tr>
"@
        }
    } else {
        $systemRows = "<tr><td colspan='8' style='padding: 15px; text-align: center; color: #64748b;'>No detailed system metric data available.</td></tr>"
    }

    $htmlBody = @"
<!DOCTYPE html>
<html>
<body style="background-color: #f1f5f9; color: #334155; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; margin: 0; padding: 25px;">
    <div style="max-width: 1000px; margin: auto; background-color: #ffffff; border: 1px solid #e2e8f0; border-top: 5px solid #0284c7; border-radius: 8px; box-shadow: 0 4px 12px rgba(0,0,0,0.05); padding: 30px;">
        
        <!-- Header -->
        <div style="border-bottom: 2px solid #0f172a; padding-bottom: 15px; margin-bottom: 25px;">
            <h1 style="color: #0f172a; margin: 0 0 6px 0; font-size: 22px;">STIG Compliance & Execution Summary</h1>
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
                    <div style="color: #64748b; font-size: 11px; text-transform: uppercase; font-weight: bold;">CAT I Open</div>
                    <div style="color: #991b1b; font-size: 26px; font-weight: bold; margin-top: 4px;">$cat1Open</div>
                </td>
                <td style="width: 25%; background-color: #f8fafc; border: 1px solid #e2e8f0; border-top: 4px solid #f59e0b; border-radius: 6px; padding: 15px; text-align: center;">
                    <div style="color: #64748b; font-size: 11px; text-transform: uppercase; font-weight: bold;">CAT II Open</div>
                    <div style="color: #92400e; font-size: 26px; font-weight: bold; margin-top: 4px;">$cat2Open</div>
                </td>
                <td style="width: 25%; background-color: #f8fafc; border: 1px solid #e2e8f0; border-top: 4px solid #0284c7; border-radius: 6px; padding: 15px; text-align: center;">
                    <div style="color: #64748b; font-size: 11px; text-transform: uppercase; font-weight: bold;">CAT III Open</div>
                    <div style="color: #075985; font-size: 26px; font-weight: bold; margin-top: 4px;">$cat3Open</div>
                </td>
                <td style="width: 25%; background-color: #f8fafc; border: 1px solid #e2e8f0; border-top: 4px solid #10b981; border-radius: 6px; padding: 15px; text-align: center;">
                    <div style="color: #64748b; font-size: 11px; text-transform: uppercase; font-weight: bold;">Systems Scanned</div>
                    <div style="color: #166534; font-size: 26px; font-weight: bold; margin-top: 4px;">$totalSystems</div>
                </td>
            </tr>
        </table>

        <!-- Target Scope & Findings Table -->
        <h2 style="color: #0f172a; font-size: 15px; margin: 25px 0 10px 0; text-transform: uppercase; letter-spacing: 0.5px;">
            Target System Breakdown
        </h2>
        <div style="border: 1px solid #cbd5e1; border-radius: 6px; overflow: hidden;">
            <table style="width: 100%; border-collapse: collapse; font-size: 12px; text-align: left;">
                <thead>
                    <tr style="background-color: #0f172a; color: #ffffff; font-size: 11px; text-transform: uppercase;">
                        <th style="padding: 10px;">System / Group</th>
                        <th style="padding: 10px;">Scope</th>
                        <th style="padding: 10px; text-align: center;">Status</th>
                        <th style="padding: 10px; text-align: center;">Assets</th>
                        <th style="padding: 10px; text-align: center;">CAT I</th>
                        <th style="padding: 10px; text-align: center;">CAT II</th>
                        <th style="padding: 10px; text-align: center;">CAT III</th>
                        <th style="padding: 10px; text-align: center;">Total Open</th>
                    </tr>
                </thead>
                <tbody>
                    $systemRows
                </tbody>
            </table>
        </div>
        
        <!-- Footer -->
        <div style="margin-top: 30px; padding-top: 15px; border-top: 1px solid #e2e8f0; color: #64748b; font-size: 12px; text-align: center;">
            <p style="margin: 0 0 4px 0;"><strong>Total Audited Assets:</strong> $totalTargets targets across $totalSystems systems</p>
            <p style="margin: 0; color: #94a3b8;">Full checklists archived under <code>/usr/share/stigs/orchestration_overlay/reports/</code> and synced to STIG Manager.</p>
        </div>
    </div>
</body>
</html>
"@
}

# 4. Dispatch Email
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

    $smtpClient = [System.Net.Mail.SmtpClient]::new($smtpServer, $port)
    $smtpClient.EnableSsl = if ($mailConfig.EnableSsl -eq $true) { $true } else { $false }
    $smtpClient.Send($mailMsg)

    $smtpClient.Dispose()
    $mailMsg.Dispose()

    $recipientList = ($recipients -join ", ")
    Write-Host "[INFO] STIG execution report ($Status) dispatched to: $recipientList" -ForegroundColor Green
} catch {
    Write-Error "[ERROR] Failed to dispatch email: $($_.Exception.Message)"
    exit 1
}