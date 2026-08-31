#!/bin/bash
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
export HOME="/root"

JOB_NAME="ESXi_Root_Password_Rotation"
OVERLAY_ROOT="/usr/share/stigs/orchestration_overlay"
CRON_LOG="${OVERLAY_ROOT}/logs/esxi_password_reset.log"
ALERT_SCRIPT="${OVERLAY_ROOT}/bin/send_alert.ps1"
SCRIPT_PATH="${OVERLAY_ROOT}/scripts/Reset-EsxiRootPasswords.ps1"

mkdir -p "${OVERLAY_ROOT}/logs"

echo "[$(date '+%Y-%m-%d %H:%M:%S')] --- Initiating Scheduled ${JOB_NAME} ---" >> "$CRON_LOG"

/usr/bin/pwsh -NonInteractive -NoProfile -File "$SCRIPT_PATH" >> "$CRON_LOG" 2>&1
EXIT_CODE=$?

if [ $EXIT_CODE -ne 0 ]; then
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [ERROR] ${JOB_NAME} failed with exit code ${EXIT_CODE}" >> "$CRON_LOG"
    logger -p local0.err -t "ESXI-SECURITY" "[FAILURE] ${JOB_NAME} failed with exit code ${EXIT_CODE}"
    /usr/bin/pwsh -NonInteractive -NoProfile -File "$ALERT_SCRIPT" -JobName "$JOB_NAME" -LogPath "$CRON_LOG" -ExitCode "$EXIT_CODE" -Status "FAILED"
    exit $EXIT_CODE
else
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [SUCCESS] ${JOB_NAME} completed successfully." >> "$CRON_LOG"
    logger -p local0.info -t "ESXI-SECURITY" "[SUCCESS] ${JOB_NAME} completed successfully."
    /usr/bin/pwsh -NonInteractive -NoProfile -File "$ALERT_SCRIPT" -JobName "$JOB_NAME" -LogPath "$CRON_LOG" -ExitCode 0 -Status "SUCCESS"
fi