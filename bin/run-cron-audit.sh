#!/bin/bash
# Direct cron execution wrapper with secure env load
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

# Call PowerShell silently to feed log files without terminal interference
pwsh -NonInteractive -NoProfile -Command "
    Import-Module /usr/share/stigs/orchestration_overlay/modules/StigOrchestration.psm1;
    Invoke-MultiVCenterOrchestration -OverlayRoot '/usr/share/stigs/orchestration_overlay' -Silent
" > /dev/null 2>&1