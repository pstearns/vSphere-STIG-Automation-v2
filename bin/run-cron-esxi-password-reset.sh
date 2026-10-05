#!/bin/bash

set -o pipefail

export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
export HOME="/root"

TARGET_VC="$1" # Optional: e.g. ./rotate_passwords.sh huarinfvc.niprpnp.army.mil

JOB_NAME="ESXi_Root_Password_Rotation"
if [ -n "$TARGET_VC" ]; then
    JOB_NAME="ESXi_Root_Password_Rotation_${TARGET_VC%%.*}"
fi

OVERLAY_ROOT="/usr/share/stigs/orchestration_overlay"
CRON_LOG="${OVERLAY_ROOT}/logs/esxi_password_reset.log"
ALERT_SCRIPT="${OVERLAY_ROOT}/bin/send_operational_alert.ps1"
SCRIPT_PATH="${OVERLAY_ROOT}/scripts/Reset-EsxiRootPasswords.ps1"
SUMMARY_JSON="${OVERLAY_ROOT}/reports/esxi_rotation_summary.json"

mkdir -p "${OVERLAY_ROOT}/logs"
mkdir -p "${OVERLAY_ROOT}/reports"

echo "[$(date '+%Y-%m-%d %H:%M:%S')] --- Initiating Scheduled ${JOB_NAME} ---" >> "$CRON_LOG"

# Build optional PWSH argument array
PWSH_ARGS=(-NonInteractive -NoProfile -File "$SCRIPT_PATH" -SummaryOutputPath "$SUMMARY_JSON")
if [ -n "$TARGET_VC" ]; then
    PWSH_ARGS+=(-TargetVC "$TARGET_VC")
fi

# Execute PowerCLI rotation script
/usr/bin/pwsh "${PWSH_ARGS[@]}" >> "$CRON_LOG" 2>&1
EXIT_CODE=$?

# Force file system buffer flush
sync

# Evaluate status and dispatch operational alert
if [ $EXIT_CODE -ne 0 ]; then
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [ERROR] ${JOB_NAME} failed with exit code ${EXIT_CODE}" >> "$CRON_LOG"
    logger -p local0.err -t "ESXI-SECURITY" "[FAILURE] ${JOB_NAME} failed with exit code ${EXIT_CODE}"

    /usr/bin/pwsh -NonInteractive -NoProfile -File "$ALERT_SCRIPT" \
        -JobName "$JOB_NAME" \
        -LogPath "$CRON_LOG" \
        -ExitCode "$EXIT_CODE" \
        -Status "FAILED" \
        -SummaryJsonPath "$SUMMARY_JSON"

    exit $EXIT_CODE
else
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [SUCCESS] ${JOB_NAME} completed successfully." >> "$CRON_LOG"
    logger -p local0.info -t "ESXI-SECURITY" "[SUCCESS] ${JOB_NAME} completed successfully."

    /usr/bin/pwsh -NonInteractive -NoProfile -File "$ALERT_SCRIPT" \
        -JobName "$JOB_NAME" \
        -LogPath "$CRON_LOG" \
        -ExitCode 0 \
        -Status "SUCCESS" \
        -SummaryJsonPath "$SUMMARY_JSON"

    exit 0
fi