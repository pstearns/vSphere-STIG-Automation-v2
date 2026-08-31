#!/bin/bash
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
export HOME="/root"

PKG_ROOT="/usr/share/stigs/orchestration_overlay/hardware_inventory"
JOB_NAME="VM_Inventory"
DATE_STAMP=$(date +%m%d%Y)
CSV_PATH="${PKG_ROOT}/reports/VMSerialNumbers_${DATE_STAMP}.csv"
CRON_LOG="${PKG_ROOT}/logs/vm_inventory_trace.log"
ALERT_SCRIPT="${PKG_ROOT}/bin/send_inventory_email.ps1"
SCRIPT_PATH="${PKG_ROOT}/scripts/GetVMSerialNumbersandIP.ps1"

mkdir -p "${PKG_ROOT}/logs" "${PKG_ROOT}/reports"

echo "[$(date '+%Y-%m-%d %H:%M:%S')] --- Initiating Scheduled ${JOB_NAME} ---" >> "$CRON_LOG"

/usr/bin/pwsh -NonInteractive -NoProfile -File "$SCRIPT_PATH" -OutputPath "$CSV_PATH" >> "$CRON_LOG" 2>&1
EXIT_CODE=$?

if [ $EXIT_CODE -ne 0 ]; then
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [ERROR] ${JOB_NAME} failed with exit code ${EXIT_CODE}" >> "$CRON_LOG"
    logger -p local0.err -t "HARDWARE-INVENTORY" "[FAILURE] ${JOB_NAME} failed with exit code ${EXIT_CODE}"
    /usr/bin/pwsh -NonInteractive -NoProfile -File "$ALERT_SCRIPT" -JobName "$JOB_NAME" -LogPath "$CRON_LOG" -ExitCode "$EXIT_CODE" -Status "FAILED"
    exit $EXIT_CODE
else
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [SUCCESS] ${JOB_NAME} completed successfully. Report: ${CSV_PATH}" >> "$CRON_LOG"
    logger -p local0.info -t "HARDWARE-INVENTORY" "[SUCCESS] ${JOB_NAME} completed successfully."
    /usr/bin/pwsh -NonInteractive -NoProfile -File "$ALERT_SCRIPT" -JobName "$JOB_NAME" -LogPath "$CRON_LOG" -ExitCode 0 -Status "SUCCESS" -AttachmentPath "$CSV_PATH"
fi
