param (
    [Parameter(Mandatory=$true)][string]$JobName,
    [Parameter(Mandatory=$true)][string]$LogPath,
    [Parameter(Mandatory=$true)][int]$ExitCode,
    [ValidateSet("SUCCESS", "FAILED")][string]$Status = "SUCCESS",
    [string]$SmtpServer = "139.231.126.109",
    [int]$Port = 25,
    [string]$From = "stig-alerts@niprpnp.army.mil",
    [string]$To = "peter.j.stearns.ctr@army.mil"
)

$hostname = [System.Net.Dns]::GetHostName()
$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

if ($Status -eq "FAILED" -or $ExitCode -ne 0) {
    $subject = "[ALERT - FAILED] STIG Automation: $JobName on $hostname"
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
    $subject = "[SUCCESS] STIG Automation: $JobName on $hostname"
    $priority = [System.Net.Mail.MailPriority]::Normal

    $body = @"
STIG Audit Job Notification
==================================
Host:        $hostname
Job:         $JobName
Timestamp:   $timestamp
Status:      SUCCESSFUL (Exit Code: 0)
Log File:    $LogPath

The scheduled STIG audit completed successfully.
"@
}

try {
    $mailMsg = [System.Net.Mail.MailMessage]::new($From, $To, $subject, $body)
    $mailMsg.Priority = $priority

    $smtpClient = [System.Net.Mail.SmtpClient]::new($SmtpServer, $Port)
    $smtpClient.EnableSsl = $false
    $smtpClient.Send($mailMsg)
    $smtpClient.Dispose()
    $mailMsg.Dispose()

    Write-Host "[INFO] Notification email ($Status) successfully dispatched to $To"
} catch {
    Write-Error "[ERROR] Failed to dispatch email: $($_.Exception.Message)"
    exit 1
}