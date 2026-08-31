#!/bin/bash
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
export HOME="/root"

JOB_NAME="NetApp_STIG_Audit"
OVERLAY_ROOT="/usr/share/stigs/orchestration_overlay"
NETAPP_ROOT="${OVERLAY_ROOT}/netapp"
CRON_LOG="${OVERLAY_ROOT}/logs/netapp_execution_trace.log"
ALERT_SCRIPT="${OVERLAY_ROOT}/bin/send_alert.ps1"

mkdir -p "$(dirname "$CRON_LOG")"

echo "[$(date '+%Y-%m-%d %H:%M:%S')] --- Initiating Scheduled ${JOB_NAME} ---" >> "$CRON_LOG"

# Change directory to NETAPP_ROOT to support any relative file dependencies
cd "$NETAPP_ROOT" || exit 1

/usr/bin/pwsh -NonInteractive -NoProfile -Command '
    $ErrorActionPreference = "Stop"
    Import-Module "/usr/share/stigs/orchestration_overlay/netapp/modules/Invoke-NetAppAudit.psm1" -Force
    $finalResults = Invoke-NetAppAudit
' >> "$CRON_LOG" 2>&1

EXIT_CODE=$?

if [ $EXIT_CODE -ne 0 ]; then
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [ERROR] ${JOB_NAME} failed with exit code ${EXIT_CODE}" >> "$CRON_LOG"
    logger -p local0.err -t "STIG-AUTOMATION" "[FAILURE] ${JOB_NAME} failed with exit code ${EXIT_CODE}"
    /usr/bin/pwsh -NonInteractive -NoProfile -File "$ALERT_SCRIPT" -JobName "$JOB_NAME" -LogPath "$CRON_LOG" -ExitCode "$EXIT_CODE" -Status "FAILED"
    exit $EXIT_CODE
else
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [SUCCESS] ${JOB_NAME} completed successfully." >> "$CRON_LOG"
    logger -p local0.info -t "STIG-AUTOMATION" "[SUCCESS] ${JOB_NAME} completed successfully."
    /usr/bin/pwsh -NonInteractive -NoProfile -File "$ALERT_SCRIPT" -JobName "$JOB_NAME" -LogPath "$CRON_LOG" -ExitCode 0 -Status "SUCCESS"
fi