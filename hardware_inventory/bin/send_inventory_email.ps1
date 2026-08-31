param (
    [Parameter(Mandatory=$true)][string]$JobName,
    [Parameter(Mandatory=$true)][string]$LogPath,
    [Parameter(Mandatory=$true)][int]$ExitCode,
    [ValidateSet("SUCCESS", "FAILED")][string]$Status = "SUCCESS",
    [string]$AttachmentPath,
    [string]$ConfigPath = "/usr/share/stigs/orchestration_overlay/hardware_inventory/conf/mail_config.json"
)

# 1. Load configuration from conf file
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

# 2. Build email headers and body
if ($Status -eq "FAILED" -or $ExitCode -ne 0) {
    $subject  = "[ALERT - FAILED] Hardware Inventory: $JobName"
    $priority = [System.Net.Mail.MailPriority]::High

    $logTail = ""
    if (Test-Path $LogPath) {
        $logTail = (Get-Content -Path $LogPath -Tail 50) -join "`n"
    }

    $body = @"
Hardware Inventory Automation Failure
=====================================
Host:        $hostname
Job:         $JobName
Timestamp:   $timestamp
Status:      FAILED (Exit Code: $ExitCode)
Log File:    $LogPath

--- Last 50 Log Lines ---
$logTail
"@
} else {
    $subject  = "[REPORT] Hardware Inventory: $JobName"
    $priority = [System.Net.Mail.MailPriority]::Normal

    $body = @"
Hardware Inventory Automation Report
====================================
Host:        $hostname
Job:         $JobName
Timestamp:   $timestamp
Status:      SUCCESSFUL (Exit Code: 0)
Attachment:  $AttachmentPath

The scheduled hardware inventory data collection completed successfully.
The generated CSV report is attached to this email.
"@
}

# 3. Construct and dispatch mail via .NET SmtpClient
try {
    $mailMsg = [System.Net.Mail.MailMessage]::new()
    $mailMsg.From = [System.Net.Mail.MailAddress]::new($from)
    $mailMsg.Subject = $subject
    $mailMsg.Body = $body
    $mailMsg.Priority = $priority

    # Add all configured recipients
    foreach ($recipient in $recipients) {
        if (-not [string]::IsNullOrWhiteSpace($recipient)) {
            $mailMsg.To.Add($recipient.Trim())
        }
    }

    # Attach CSV report on success if file exists
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
    Write-Host "[INFO] Inventory email ($Status) successfully dispatched to: $recipientList"
} catch {
    Write-Error "[ERROR] Failed to dispatch email: $($_.Exception.Message)"
    e

xit 1
}