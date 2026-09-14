#!/bin/bash

set -o pipefail

export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
export HOME="/root"

JOB_NAME="ESXi_Root_Password_Rotation"
OVERLAY_ROOT="/usr/share/stigs/orchestration_overlay"
CRON_LOG="${OVERLAY_ROOT}/logs/esxi_password_reset.log"
ALERT_SCRIPT="${OVERLAY_ROOT}/bin/send_operational_alert.ps1"
SCRIPT_PATH="${OVERLAY_ROOT}/scripts/Reset-EsxiRootPasswords.ps1"
SUMMARY_JSON="${OVERLAY_ROOT}/reports/esxi_rotation_summary.json"

mkdir -p "${OVERLAY_ROOT}/logs"
mkdir -p "${OVERLAY_ROOT}/reports"

echo "[$(date '+%Y-%m-%d %H:%M:%S')] --- Initiating Scheduled ${JOB_NAME} ---" >> "$CRON_LOG"

# Execute PowerCLI rotation script
/usr/bin/pwsh -NonInteractive -NoProfile -File "$SCRIPT_PATH" -SummaryOutputPath "$SUMMARY_JSON" >> "$CRON_LOG" 2>&1
EXIT_CODE=$?

# Force file system buffer flush to prevent read sync lag
sync

# Evaluate status and call the unmodified send_alert.ps1
if [ $EXIT_CODE -ne 0 ]; then
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [ERROR] ${JOB_NAME} failed with exit code ${EXIT_CODE}" >> "$CRON_LOG"
    logger -p local0.err -t "ESXI-SECURITY" "[FAILURE] ${JOB_NAME} failed with exit code ${EXIT_CODE}"
    
    /usr/bin/pwsh -NonInteractive -NoProfile -File "$ALERT_SCRIPT" \
        -JobName "$JOB_NAME" \
        -LogPath "$CRON_LOG" \
        -ExitCode "$EXIT_CODE" \
        -Status "FAILED"
    
    exit $EXIT_CODE
else
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [SUCCESS] ${JOB_NAME} completed successfully." >> "$CRON_LOG"
    logger -p local0.info -t "ESXI-SECURITY" "[SUCCESS] ${JOB_NAME} completed successfully."
    
    # Pass the generated JSON Summary so send_alert.ps1 processes the SUCCESS state correctly
    /usr/bin/pwsh -NonInteractive -NoProfile -File "$ALERT_SCRIPT" \
        -JobName "$JOB_NAME" \
        -LogPath "$CRON_LOG" \
        -ExitCode 0 \
        -Status "SUCCESS" \
        -SummaryJsonPath "$SUMMARY_JSON"
    
    exit 0
fi