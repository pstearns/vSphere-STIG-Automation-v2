#!/bin/bash
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
export HOME="/root"

PKG_ROOT="/usr/share/stigs/orchestration_overlay/cert_tracker"
JOB_NAME="F5_Certificate_Tracker"
DATE_STAMP=$(date +%m%d%Y)
HTML_PATH="${PKG_ROOT}/reports/F5_Certs_${DATE_STAMP}.html"
JSON_PATH="${PKG_ROOT}/reports/F5_Certs_${DATE_STAMP}.json"
ROLLING_CSV="${PKG_ROOT}/reports/f5_cert_inventory_rolling.csv"
CRON_LOG="${PKG_ROOT}/logs/f5_cert_tracker.log"
ALERT_SCRIPT="${PKG_ROOT}/bin/send_cert_alert_email.ps1"
SCRIPT_PATH="${PKG_ROOT}/scripts/GetF5Certificates.ps1"
CONF_PATH="${PKG_ROOT}/conf/f5_cert_config.json"

mkdir -p "${PKG_ROOT}/logs" "${PKG_ROOT}/reports"

echo "[$(date '+%Y-%m-%d %H:%M:%S')] --- Initiating Scheduled ${JOB_NAME} ---" >> "$CRON_LOG"

/usr/bin/pwsh -NonInteractive -NoProfile -File "$SCRIPT_PATH" \
    -OutputHtmlPath "$HTML_PATH" \
    -OutputJsonPath "$JSON_PATH" \
    -RollingCsvPath "$ROLLING_CSV" \
    -ConfigPath "$CONF_PATH" >> "$CRON_LOG" 2>&1
EXIT_CODE=$?

if [ $EXIT_CODE -ne 0 ]; then
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [ERROR] ${JOB_NAME} failed with exit code ${EXIT_CODE}" >> "$CRON_LOG"
    logger -p local0.err -t "F5-CERT-TRACKER" "[FAILURE] ${JOB_NAME} failed with exit code ${EXIT_CODE}"
    /usr/bin/pwsh -NonInteractive -NoProfile -File "$ALERT_SCRIPT" \
        -JobName "$JOB_NAME" \
        -LogPath "$CRON_LOG" \
        -ExitCode "$EXIT_CODE" \
        -Status "FAILED" \
        -ConfigPath "$CONF_PATH"
    exit $EXIT_CODE
else
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [SUCCESS] ${JOB_NAME} completed successfully. Report: ${HTML_PATH}" >> "$CRON_LOG"
    logger -p local0.info -t "F5-CERT-TRACKER" "[SUCCESS] ${JOB_NAME} completed successfully."
    /usr/bin/pwsh -NonInteractive -NoProfile -File "$ALERT_SCRIPT" \
        -JobName "$JOB_NAME" \
        -LogPath "$CRON_LOG" \
        -ExitCode 0 \
        -Status "SUCCESS" \
        -AttachmentPath "$HTML_PATH" \
        -SummaryJsonPath "$JSON_PATH" \
        -ConfigPath "$CONF_PATH"
fi