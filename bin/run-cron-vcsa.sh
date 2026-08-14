#!/bin/bash
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
export HOME="/root"

CRON_LOG="/usr/share/stigs/orchestration_overlay/logs/vcsa_execution_trace.log"
mkdir -p "$(dirname "$CRON_LOG")"

echo "[$(date '+%Y-%m-%d %H:%M:%S')] --- Initiating Scheduled VCSA STIG Audit ---" >> "$CRON_LOG"

/usr/bin/pwsh -NonInteractive -NoProfile -Command "
    \$ErrorActionPreference = 'Stop'
    Import-Module /usr/share/stigs/orchestration_overlay/modules/StigOrchestration.psm1;
    Invoke-MultiVcsaOrchestration -OverlayRoot '/usr/share/stigs/orchestration_overlay' -Silent
" >> "$CRON_LOG" 2>&1