#!/bin/bash
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
export HOME="/root"

CRON_LOG="/usr/share/stigs/orchestration_overlay/logs/vm_remediation_trace.log"
mkdir -p "$(dirname "$CRON_LOG")"

echo "[$(date '+%Y-%m-%d %H:%M:%S')] --- Initiating Scheduled VM STIG Remediation ---" >> "$CRON_LOG"

# Using single quotes preserve literal PowerShell variables and functions
/usr/bin/pwsh -NonInteractive -NoProfile -Command '
    $ErrorActionPreference = "Stop"
    Import-Module /usr/share/stigs/orchestration_overlay/modules/RemediationOrchestration.psm1;
    Invoke-StigRemediation -AssetType VM -Silent
' >> "$CRON_LOG" 2>&1