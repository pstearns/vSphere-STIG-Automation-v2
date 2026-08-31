#!/bin/bash
JOB_NAME="$1"
LOG_FILE="$2"
EXIT_CODE="$3"

# 1. Always record failure to systemd-journald / syslog
logger -p local0.err -t "STIG-AUTOMATION" "[FAILURE] Job: ${JOB_NAME} | Exit Code: ${EXIT_CODE} | Log: ${LOG_FILE}"

# 2. Dispatch email via pwsh helper
/usr/bin/pwsh -NonInteractive -NoProfile -File "/usr/share/stigs/orchestration_overlay/bin/send_alert.ps1" \
    -JobName "$JOB_NAME" \
    -LogPath "$LOG_FILE" \
    -ExitCode "$EXIT_CODE"