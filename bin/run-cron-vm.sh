#!/bin/bash

export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
export HOME="/root"

JOB_NAME="VM_STIG_Orchestration_Pipeline"
OVERLAY_ROOT="/usr/share/stigs/orchestration_overlay"
CRON_LOG="${OVERLAY_ROOT}/logs/vm_execution_trace.log"
ALERT_SCRIPT="${OVERLAY_ROOT}/bin/send_alert.ps1"
REMEDIATE_SCRIPT="${OVERLAY_ROOT}/bin/run-remediation-vm.sh"

mkdir -p "$(dirname "$CRON_LOG")"

echo "[$(date '+%Y-%m-%d %H:%M:%S')] --- Initiating Scheduled STIG Pipeline ---" >> "$CRON_LOG"

# -------------------------------------------------------------------------
# PHASE 1: EXECUTE BASELINE AUDIT
# -------------------------------------------------------------------------
echo "[$(date '+%Y-%m-%d %H:%M:%S')] [INFO] Launching Baseline Audit..." >> "$CRON_LOG"

/usr/bin/pwsh -NonInteractive -NoProfile -Command "
    \$ErrorActionPreference = 'Stop'
    Import-Module ${OVERLAY_ROOT}/modules/StigOrchestration.psm1
    Invoke-MultiVmOrchestration -OverlayRoot '${OVERLAY_ROOT}' -Silent
" >> "$CRON_LOG" 2>&1

EXIT_CODE=$?

# Validate Audit Success before proceeding
if [ $EXIT_CODE -ne 0 ]; then
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [ERROR] Baseline Audit failed with exit code ${EXIT_CODE}. Remediation aborted." >> "$CRON_LOG"
    logger -p local0.err -t "STIG-AUTOMATION" "[FAILURE] Baseline Audit failed with exit code ${EXIT_CODE}. Remediation aborted."
    /usr/bin/pwsh -NonInteractive -NoProfile -File "$ALERT_SCRIPT" -JobName "${JOB_NAME}_Audit_Phase" -LogPath "$CRON_LOG" -ExitCode "$EXIT_CODE" -Status "FAILED"
    exit $EXIT_CODE
else
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [SUCCESS] Baseline Audit completed successfully." >> "$CRON_LOG"
    logger -p local0.info -t "STIG-AUTOMATION" "[SUCCESS] Baseline Audit completed successfully."
fi

# -------------------------------------------------------------------------
# PHASE 2 & 3: TRIGGER REMEDIATION & DELTA VERIFICATION
# -------------------------------------------------------------------------
echo "[$(date '+%Y-%m-%d %H:%M:%S')] [INFO] Launching Remediation & Delta Verification..." >> "$CRON_LOG"

if [ -f "$REMEDIATE_SCRIPT" ]; then
    bash "$REMEDIATE_SCRIPT" >> "$CRON_LOG" 2>&1
    REMEDIATE_EXIT_CODE=$?
else
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [ERROR] Remediation wrapper script not found at ${REMEDIATE_SCRIPT}" >> "$CRON_LOG"
    REMEDIATE_EXIT_CODE=127
fi

if [ $REMEDIATE_EXIT_CODE -ne 0 ]; then
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [ERROR] Remediation/Verification Engine failed with exit code ${REMEDIATE_EXIT_CODE}" >> "$CRON_LOG"
    logger -p local0.err -t "STIG-AUTOMATION" "[FAILURE] Remediation/Verification Engine failed with exit code ${REMEDIATE_EXIT_CODE}"
    /usr/bin/pwsh -NonInteractive -NoProfile -File "$ALERT_SCRIPT" -JobName "${JOB_NAME}_Remediation_Phase" -LogPath "$CRON_LOG" -ExitCode "$REMEDIATE_EXIT_CODE" -Status "FAILED"
    exit $REMEDIATE_EXIT_CODE
else
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [SUCCESS] Remediation & Delta Verification completed successfully." >> "$CRON_LOG"
    logger -p local0.info -t "STIG-AUTOMATION" "[SUCCESS] Remediation & Delta Verification completed successfully."
fi

echo "[$(date '+%Y-%m-%d %H:%M:%S')] --- Pipeline Run Complete ---" >> "$CRON_LOG"
exit 0