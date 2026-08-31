param (
    [Parameter(Mandatory=$true)][string]$JobName,
    [Parameter(Mandatory=$true)][string]$LogPath,
    [Parameter(Mandatory=$true)][int]$ExitCode,
    [ValidateSet("SUCCESS", "FAILED")][string]$Status = "SUCCESS",
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

# 2. Construct Subject Line & Body
if ($Status -eq "FAILED" -or $ExitCode -ne 0) {
    $subject  = "[ALERT - FAILED] STIG Automation: $JobName"
    $priority = [System.Net.Mail.MailPriority]::High

    $logTail = ""
    if (Test-Path $LogPath) {
        $logTail = (Get-Content -Path $LogPath -Tail 50) -join "`n"
    }

    $body = @"
STIG Audit Job Failure Notification
==================================
Host:        $hostname
Job:         $JobName
Timestamp:   $timestamp
Status:      FAILED (Exit Code: $ExitCode)
Log File:    $LogPath

--- Last 50 Log Lines ---
$logTail
"@
} else {
    $subject  = "[SUCCESS] STIG Automation: $JobName"
    $priority = [System.Net.Mail.MailPriority]::Normal

    $body = @"
STIG Audit Job Notification
==================================
Host:        $hostname
Job:         $JobName
Timestamp:   $timestamp
Status:      SUCCESSFUL (Exit Code: 0)
Log File:    $LogPath

The scheduled STIG automation task completed successfully.
"@
}

# 3. Dispatch Email via .NET SmtpClient
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

    $smtpClient = [System.Net.Mail.SmtpClient]::new($smtpServer, $port)
    $smtpClient.EnableSsl = if ($mailConfig.EnableSsl -eq $true) { $true } else { $false }
    $smtpClient.Send($mailMsg)

    $smtpClient.Dispose()
    $mailMsg.Dispose()

    $recipientList = ($recipients -join ", ")
    Write-Host "[INFO] Notification email ($Status) successfully dispatched to: $recipientList"
} catch {
    Write-Error "[ERROR] Failed to dispatch email: $($_.Exception.Message)"
    exit 1
}