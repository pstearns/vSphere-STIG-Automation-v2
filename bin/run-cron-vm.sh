#!/bin/bash

export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
export HOME="/root"

JOB_NAME="VM_STIG_Audit"
PWSH_COMMAND="Invoke-MultiVmOrchestration"

OVERLAY_ROOT="/usr/share/stigs/orchestration_overlay"
CRON_LOG="${OVERLAY_ROOT}/logs/vm_execution_trace.log"
ALERT_SCRIPT="${OVERLAY_ROOT}/bin/send_alert.ps1"

mkdir -p "$(dirname "$CRON_LOG")"

echo "[$(date '+%Y-%m-%d %H:%M:%S')] --- Initiating Scheduled ${JOB_NAME} ---" >> "$CRON_LOG"

# Execute PowerShell Orchestration
/usr/bin/pwsh -NonInteractive -NoProfile -Command "
    \$ErrorActionPreference = 'Stop'
    Import-Module ${OVERLAY_ROOT}/modules/StigOrchestration.psm1
    ${PWSH_COMMAND} -OverlayRoot '${OVERLAY_ROOT}' -Silent
" >> "$CRON_LOG" 2>&1

EXIT_CODE=$?

# Success email is dispatched internally by PowerShell with full CKL metrics.
# This wrapper handles logging and catastrophic/syntax failure alerts.
if [ $EXIT_CODE -ne 0 ]; then
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [ERROR] ${JOB_NAME} failed with exit code ${EXIT_CODE}" >> "$CRON_LOG"
    logger -p local0.err -t "STIG-AUTOMATION" "[FAILURE] ${JOB_NAME} failed with exit code ${EXIT_CODE}"
    /usr/bin/pwsh -NonInteractive -NoProfile -File "$ALERT_SCRIPT" -JobName "$JOB_NAME" -LogPath "$CRON_LOG" -ExitCode "$EXIT_CODE" -Status "FAILED"
    exit $EXIT_CODE
else
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [SUCCESS] ${JOB_NAME} completed successfully." >> "$CRON_LOG"
    logger -p local0.info -t "STIG-AUTOMATION" "[SUCCESS] ${JOB_NAME} completed successfully."
fi