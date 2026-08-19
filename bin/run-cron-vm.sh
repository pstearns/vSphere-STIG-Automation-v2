#!/bin/bash
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
export HOME="/root"

CRON_LOG="/usr/share/stigs/orchestration_overlay/logs/vm_execution_trace.log"
mkdir -p "$(dirname "$CRON_LOG")"

echo "[$(date '+%Y-%m-%d %H:%M:%S')] --- Initiating Scheduled VM STIG Audit ---" >> "$CRON_LOG"

/usr/bin/pwsh -NonInteractive -NoProfile -Command "
    \$ErrorActionPreference = 'Stop'
    Import-Module /usr/share/stigs/orchestration_overlay/modules/StigOrchestration.psm1;
    Invoke-MultiVMOrchestration -OverlayRoot '/usr/share/stigs/orchestration_overlay' -Silent
" >> "$CRON_LOG" 2>&1