#!/bin/bash
# =========================================================================
# NAME: run-vcsa-remediation.sh
# DESCRIPTION: Cron-safe automated wrapper for multi-VCSA STIG remediation.
#              Employs lock protection to prevent concurrent execution collisons.
# =========================================================================

export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
export HOME="/root"

CRON_LOG="/usr/share/stigs/orchestration_overlay/logs/vcsa_remediation_trace.log"
LOCK_FILE="/var/run/vcsa_remediation.lock"

# Ensure log directory exists
mkdir -p "$(dirname "$CRON_LOG")"

# Redirect all stdout and stderr to the log file for the locked block
exec >> "$CRON_LOG" 2>&1

# Use flock to natively prevent duplicate concurrent runs
(
    if ! flock -n 9; then
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] [WARN] Another instance of VCSA STIG Remediation is actively running. Exiting."
        exit 1
    fi

    START_TIME=$(date +%s)
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [INFO] --- Initiating Scheduled VCSA STIG Remediation ---"

    # Verify PowerShell is installed on path
    if ! command -v pwsh &> /dev/null; then
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] [ERROR] PowerShell (pwsh) is not installed or not in PATH."
        exit 1
    fi

    # Invoke the unified orchestration engine with VCSA targets in Silent Mode
    pwsh -NonInteractive -NoProfile -Command "
        \$ErrorActionPreference = 'Stop'
        try {
            Import-Module /usr/share/stigs/orchestration_overlay/modules/RemediationOrchestration.psm1 -Force
            Invoke-StigRemediation -AssetType VCSA -Silent
            exit 0
        }
        catch {
            Write-Error \$_
            exit 1
        }
    "
    PWSH_EXIT=$?

    END_TIME=$(date +%s)
    DURATION=$((END_TIME - START_TIME))
    MIN=$((DURATION / 60))
    SEC=$((DURATION % 60))

    if [ $PWSH_EXIT -eq 0 ]; then
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] [SUCCESS] Scheduled VCSA STIG Remediation finalized successfully. (Duration: ${MIN}m ${SEC}s)"
    else
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] [ERROR] Scheduled VCSA STIG Remediation encountered errors (Exit Code: $PWSH_EXIT). (Duration: ${MIN}m ${SEC}s)"
        exit $PWSH_EXIT
    fi

) 9>"$LOCK_FILE"